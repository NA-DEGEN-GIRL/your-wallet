package dev.yw.app;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The JVM unit tests of the platform-neutral Java classes, with no test library (spec/15 §18 42 N15): the Gradle task
 * jvmTest runs this main, which exits non-zero when a test fails or none ran. Each test is one method listed in main.
 */
public final class JvmTests {
    private static int passed;
    private static int failed;

    private JvmTests() {}

    public static void main(String[] args) {
        run("main process is exactly the package name", JvmTests::mainProcess);
        run("interim inputs are the bytes Rust matches", JvmTests::interimInputs);
        run("interim inputs are fresh copies", JvmTests::freshCopies);
        run("status line accepts printable ASCII only", JvmTests::statusLine);
        System.out.println("jvmTest: " + passed + " passed, " + failed + " failed");
        if (failed != 0 || passed == 0) {
            System.exit(1);
        }
    }

    private interface Body {
        void run();
    }

    private static void run(String name, Body body) {
        try {
            body.run();
            passed++;
        } catch (AssertionError failure) {
            failed++;
            System.out.println("FAIL " + name + ": " + failure.getMessage());
        }
    }

    private static void check(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError(what);
        }
    }

    private static void mainProcess() {
        check(ProcessRule.isMainProcess("dev.yw.app", "dev.yw.app"), "main");
        check(!ProcessRule.isMainProcess("dev.yw.app:browser", "dev.yw.app"), ":browser");
        check(!ProcessRule.isMainProcess("dev.yw.ap", "dev.yw.app"), "prefix");
        check(!ProcessRule.isMainProcess(null, "dev.yw.app"), "no process name");
        check(!ProcessRule.isMainProcess("dev.yw.app", null), "no package name");
        check(!ProcessRule.isMainProcess("", ""), "empty");
    }

    private static void interimInputs() {
        // The same bytes as yw-android interim::STATUS and interim::JAVA_UNCAUGHT (their Rust tests pin them too).
        check(Arrays.equals(Wire.statusRequest(), ascii("{\"t\":\"status\"}")), "status");
        check(Arrays.equals(Wire.javaUncaught(), ascii("{\"t\":\"java_uncaught\"}")), "java_uncaught");
    }

    private static void freshCopies() {
        byte[] first = Wire.statusRequest();
        first[0] = 0;
        check(Wire.statusRequest()[0] == '{', "statusRequest is a fresh array");
        byte[] event = Wire.javaUncaught();
        event[0] = 0;
        check(Wire.javaUncaught()[0] == '{', "javaUncaught is a fresh array");
    }

    private static void statusLine() {
        check("yw 0.3.0 arm64-v8a".equals(Wire.statusLine(ascii("yw 0.3.0 arm64-v8a"))), "plain line");
        check(Wire.statusLine(null) == null, "null");
        check(Wire.statusLine(new byte[0]) == null, "empty");
        byte[] longest = new byte[Wire.STATUS_MAX];
        Arrays.fill(longest, (byte) 'a');
        check(Wire.statusLine(longest) != null, "STATUS_MAX bytes");
        check(Wire.statusLine(Arrays.copyOf(longest, Wire.STATUS_MAX + 1)) == null, "too long");
        check(Wire.statusLine(new byte[] {'a', 0x0a}) == null, "control byte");
        check(Wire.statusLine(new byte[] {'a', 0x7f}) == null, "DEL");
        check(Wire.statusLine(new byte[] {'a', (byte) 0xc3, (byte) 0xa9}) == null, "non-ASCII");
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }
}
