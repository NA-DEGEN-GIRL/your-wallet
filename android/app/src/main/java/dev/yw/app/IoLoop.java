package dev.yw.app;

import android.content.Context;
import java.util.Arrays;

/**
 * The I/O thread (spec/15 §3.2, §18 42 N9; 2026-11-25 A2-4b): it waits on {@link Native#next} for a platform I/O
 * request, serves it ({@link DeviceKeys}) and answers with {@link Native#ioComplete}. Rust never calls Java: a
 * Rust thread that needs the Keystore or the memory facts queues a request and blocks until this thread answers or
 * its deadline passes (then the request fails closed and a late answer is dropped by Rust).
 *
 * <p>The request frame is zeroed right after it was served (the wrap request carries the plain file key), and so
 * is the answer body after ioComplete returns (the unwrap answer is the plain file key). A frame this build cannot
 * read gets no answer here unless it has an id (BAD_REQUEST); Rust's deadline ends it either way.
 *
 * <p>2026-11-25 A2-6: {@code next} also hands out the UI frames of the screen (UiWire); this thread passes each to the
 * main thread ({@link Screen#post}). They carry no secret.
 */
final class IoLoop implements Runnable {
    /** How long one next call waits. */
    private static final long WAIT_MS = 2_000;

    private final Context context;

    private IoLoop(Context context) {
        this.context = context;
    }

    /** Starts the I/O thread once for this process. */
    static void start(Context context) {
        Thread thread = new Thread(new IoLoop(context.getApplicationContext()), "io");
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void run() {
        while (true) {
            byte[] frame = Native.next(WAIT_MS);
            if (frame != null) {
                serve(frame);
            }
        }
    }

    private void serve(byte[] frame) {
        if (frame.length > 0 && (frame[0] & 0xff) == UiWire.FRAME_UI) {
            // 2026-11-25 A2-6: a UI frame goes to the main thread (Screen).
            Screen.post(frame);
            return;
        }
        if (frame.length < IoFrame.HEADER || (frame[0] & 0xff) != IoFrame.FRAME_IO) {
            Arrays.fill(frame, (byte) 0);
            return;
        }
        long id = IoFrame.id(frame);
        DeviceKeys.Answer answer;
        try {
            if (!IoFrame.valid(frame)) {
                answer = DeviceKeys.Answer.of(IoFrame.BAD_REQUEST);
            } else if (IoFrame.op(frame) == IoFrame.OP_WRAP) {
                answer = DeviceKeys.wrap(context, frame);
            } else if (IoFrame.op(frame) == IoFrame.OP_UNWRAP) {
                answer = DeviceKeys.unwrap(context, frame);
            } else if (IoFrame.makesKey(frame)) {
                answer = DeviceKeys.make(frame);
            } else {
                answer = DeviceKeys.memory(context);
            }
        } catch (Throwable error) {
            answer = DeviceKeys.Answer.of(IoFrame.OTHER);
        } finally {
            Arrays.fill(frame, (byte) 0);
        }
        try {
            Native.ioComplete(id, answer.status, answer.body);
        } finally {
            if (answer.body != null) {
                Arrays.fill(answer.body, (byte) 0);
            }
        }
    }
}
