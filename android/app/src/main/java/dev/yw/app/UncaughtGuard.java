package dev.yw.app;

import android.os.Process;

/**
 * The default uncaught-exception handler (spec/15 §3.3). The platform's default handler writes the stack and the
 * exception message to logcat; this one writes nothing: it sends the fixed java_uncaught event to Rust, which wipes
 * every slot and ends the process with _exit (§5.3). If the library is not loaded (or the call returns), the process
 * ends here. The exception's class, message and stack are never read.
 */
final class UncaughtGuard implements Thread.UncaughtExceptionHandler {
    @Override
    public void uncaughtException(Thread thread, Throwable error) {
        try {
            if (App.loaded()) {
                Native.call(Wire.javaUncaught());
            }
        } catch (Throwable ignored) {
            // Nothing: no text of any throwable goes anywhere.
        } finally {
            Process.killProcess(Process.myPid());
            System.exit(10);
        }
    }
}
