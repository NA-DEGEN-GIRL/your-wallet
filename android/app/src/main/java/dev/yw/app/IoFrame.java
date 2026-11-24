package dev.yw.app;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * The platform I/O request frames that {@link Native#next} hands out and the answers {@link Native#ioComplete}
 * takes (spec/15 §3.2, §18 42 N9; 2026-11-25 A2-4b). The same layout as yw-android io_request (its Rust tests pin
 * the same bytes): 0x01 (an I/O request) ‖ op ‖ kind ‖ id (8, little-endian) ‖ body.
 *
 * <p>The wrap request's body is the plain 32-byte file key (the one exception to "no secret in next", §3.2): the
 * reader never copies it out of the frame, and the I/O thread fills the frame with zeros right after use.
 *
 * <p>Platform-neutral: tested by the JVM runner (§18 42 N15).
 */
final class IoFrame {
    /** The first byte of an I/O request frame. */
    static final int FRAME_IO = 0x01;
    /** Frame kind, op, kind, id. */
    static final int HEADER = 11;

    static final int OP_WRAP = 1;
    static final int OP_UNWRAP = 2;
    static final int OP_MEMORY = 3;
    /**
     * Make the device key when there is none (kind 0, no body): the only op that makes it; a wrap and an unwrap
     * never do (spec/15 §5.2; 2026-11-25 A2-4b review, before a wrap made a missing key).
     */
    static final int OP_CREATE = 4;

    /** A file key. */
    static final int KEY_LEN = 32;
    /** A wrapped file key: GCM iv (12) ‖ ct (32) ‖ tag (16). */
    static final int WRAPPED_LEN = 60;
    /** The GCM IV made by the Keystore. */
    static final int IV_LEN = 12;
    /** The memory facts answer. */
    static final int FACTS_LEN = 25;

    // Answer statuses: the same numbers as yw-android io_request::status.
    static final int OK = 0;
    static final int KEY_MISSING = 1;
    static final int KEY_FAILED = 2;
    static final int CRYPTO_FAILED = 3;
    static final int DEVICE_LOCKED = 4;
    static final int BAD_REQUEST = 5;
    static final int OTHER = 6;

    private IoFrame() {}

    /** Whether frame is an I/O request this build reads: the frame kind, a known op and that op's body length. */
    static boolean valid(byte[] frame) {
        if (frame == null || frame.length < HEADER || (frame[0] & 0xff) != FRAME_IO) {
            return false;
        }
        int body = frame.length - HEADER;
        switch (op(frame)) {
            case OP_WRAP:
                return body == KEY_LEN && aad(kind(frame)) != null;
            case OP_UNWRAP:
                return body == WRAPPED_LEN && aad(kind(frame)) != null;
            case OP_MEMORY:
                return body == 0;
            case OP_CREATE:
                return body == 0 && kind(frame) == 0;
            default:
                return false;
        }
    }

    /** Whether frame is the one request that may make the device key: a valid create frame. */
    static boolean makesKey(byte[] frame) {
        return valid(frame) && op(frame) == OP_CREATE;
    }

    static int op(byte[] frame) {
        return frame[1] & 0xff;
    }

    static int kind(byte[] frame) {
        return frame[2] & 0xff;
    }

    /** The request id; only for a frame of at least HEADER bytes. */
    static long id(byte[] frame) {
        return ByteBuffer.wrap(frame, 3, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    /**
     * The AAD of the device-key wrap for a kind number: the kind's string (yw-core vault::envelope::SealKind), a fresh
     * array; null for an unknown kind.
     */
    static byte[] aad(int kind) {
        switch (kind) {
            case 1:
                return ascii("vault");
            case 2:
                return ascii("meta");
            case 3:
                return ascii("journal");
            case 4:
                return ascii("apikeys");
            default:
                return null;
        }
    }

    /** The memory facts answer (yw-android kdf_gate::parse): totalMem ‖ availMem ‖ threshold ‖ flags. */
    static byte[] memoryFacts(long total, long avail, long threshold, boolean lowMemory, boolean lowRamDevice) {
        int flags = (lowMemory ? 1 : 0) | (lowRamDevice ? 2 : 0);
        return ByteBuffer.allocate(FACTS_LEN)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong(total)
                .putLong(avail)
                .putLong(threshold)
                .put((byte) flags)
                .array();
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }
}
