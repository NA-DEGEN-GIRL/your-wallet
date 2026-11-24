package dev.yw.app;

/**
 * Which process loads libyw.so (spec/15 §3.2, §7.4; §18 1): only the app's main process, whose name is exactly the
 * package name. The in-app browser runs in ":browser" (A4) and never loads the wallet library, so the DEK never lives
 * in the process that hosts WebView code. Platform-neutral: tested by the JVM runner (§18 42 N15).
 */
final class ProcessRule {
    private ProcessRule() {}

    static boolean isMainProcess(String processName, String packageName) {
        return processName != null
                && packageName != null
                && !packageName.isEmpty()
                && processName.equals(packageName);
    }
}
