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
        run("start input is the bytes Rust parses", JvmTests::startInput);
        run("I/O frames are read as Rust writes them", JvmTests::ioFrames);
        run("I/O statuses and kind strings are Rust's", JvmTests::ioConstants);
        run("memory facts are the bytes Rust parses", JvmTests::memoryFacts);
        run("only the create request may make the device key", JvmTests::createFrame);
        run("facts input is the bytes Rust parses", JvmTests::factsInput);
        run("bands answer is strict UTF-8 lines", JvmTests::bandsAnswer);
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

    private static void startInput() {
        // yw-android interim::tests::the_start_input pins the same bytes.
        check(Arrays.equals(Wire.start("/data/user/0/dev.yw.app/no_backup"),
                ascii("{\"t\":\"start\",\"dir\":\"/data/user/0/dev.yw.app/no_backup\"}")), "device folder");
        String[] bad = {null, "", "relative/x", "/a/../b", "/a/./b", "/a b", "/a\\b", "/a\"b", "/é", "/a\u0000b"};
        for (String dir : bad) {
            check(Wire.start(dir) == null, "refused: " + (dir == null ? "null" : dir.length()));
        }
        StringBuilder longest = new StringBuilder("/");
        while (longest.length() < Wire.START_MAX) {
            longest.append('a');
        }
        check(Wire.start(longest.toString()) == null, "over START_MAX");
    }

    private static void ioFrames() {
        // yw-android io_request::tests::the_frame_layout: an unwrap request, id 1, kind 3.
        byte[] head = {0x01, 0x02, 0x03, 0x01, 0, 0, 0, 0, 0, 0, 0};
        check(IoFrame.op(head) == IoFrame.OP_UNWRAP, "op");
        check(IoFrame.kind(head) == 3, "kind");
        check(IoFrame.id(head) == 1L, "id");
        byte[] unwrap = Arrays.copyOf(head, IoFrame.HEADER + IoFrame.WRAPPED_LEN);
        check(IoFrame.valid(unwrap), "unwrap with 60 bytes");
        check(!IoFrame.valid(Arrays.copyOf(head, IoFrame.HEADER + IoFrame.KEY_LEN)), "unwrap with 32 bytes");
        byte[] wrap = Arrays.copyOf(head, IoFrame.HEADER + IoFrame.KEY_LEN);
        wrap[1] = IoFrame.OP_WRAP;
        check(IoFrame.valid(wrap), "wrap with 32 bytes");
        wrap[2] = 9;
        check(!IoFrame.valid(wrap), "unknown kind");
        byte[] memory = Arrays.copyOf(head, IoFrame.HEADER);
        memory[1] = IoFrame.OP_MEMORY;
        memory[2] = 0;
        check(IoFrame.valid(memory), "memory without body");
        memory[0] = 0x02;
        check(!IoFrame.valid(memory), "another frame kind");
        check(!IoFrame.valid(new byte[IoFrame.HEADER - 1]), "short");
        check(!IoFrame.valid(null), "null");
        byte[] big = {0x01, 0x03, 0, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, 0x7f};
        check(IoFrame.id(big) == Long.MAX_VALUE, "little-endian id");
    }

    private static void ioConstants() {
        // yw-android io_request::status and yw-core vault::envelope::SealKind.
        int[] statuses = {IoFrame.OK, IoFrame.KEY_MISSING, IoFrame.KEY_FAILED, IoFrame.CRYPTO_FAILED,
            IoFrame.DEVICE_LOCKED, IoFrame.BAD_REQUEST, IoFrame.OTHER};
        for (int at = 0; at < statuses.length; at++) {
            check(statuses[at] == at, "status " + at);
        }
        String[] kinds = {null, "vault", "meta", "journal", "apikeys", null};
        for (int kind = 0; kind < kinds.length; kind++) {
            byte[] aad = IoFrame.aad(kind);
            check(kinds[kind] == null ? aad == null : Arrays.equals(aad, ascii(kinds[kind])), "kind " + kind);
        }
        byte[] first = IoFrame.aad(1);
        first[0] = 0;
        check(IoFrame.aad(1)[0] == 'v', "aad is a fresh array");
        check(IoFrame.HEADER == 11 && IoFrame.WRAPPED_LEN == 60 && IoFrame.KEY_LEN == 32, "lengths");
    }

    private static void createFrame() {
        // yw-android device_key::tests::make_key_is_its_own_op: op 4, kind 0, no body (2026-11-25 A2-4b review).
        byte[] create = {0x01, 0x04, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0};
        check(IoFrame.OP_CREATE == 4, "op number");
        check(IoFrame.valid(create) && IoFrame.makesKey(create), "create request");
        byte[] withKind = create.clone();
        withKind[2] = 1;
        check(!IoFrame.valid(withKind) && !IoFrame.makesKey(withKind), "create with a kind");
        check(!IoFrame.makesKey(Arrays.copyOf(create, IoFrame.HEADER + 1)), "create with a body");
        byte[] wrap = Arrays.copyOf(create, IoFrame.HEADER + IoFrame.KEY_LEN);
        wrap[1] = IoFrame.OP_WRAP;
        wrap[2] = 1;
        check(IoFrame.valid(wrap) && !IoFrame.makesKey(wrap), "a wrap never makes the key");
        byte[] unwrap = Arrays.copyOf(create, IoFrame.HEADER + IoFrame.WRAPPED_LEN);
        unwrap[1] = IoFrame.OP_UNWRAP;
        unwrap[2] = 1;
        check(IoFrame.valid(unwrap) && !IoFrame.makesKey(unwrap), "an unwrap never makes the key");
        byte[] memory = Arrays.copyOf(create, IoFrame.HEADER);
        memory[1] = IoFrame.OP_MEMORY;
        check(IoFrame.valid(memory) && !IoFrame.makesKey(memory), "memory");
        create[0] = 0x02;
        check(!IoFrame.makesKey(create), "another frame kind");
        check(!IoFrame.makesKey(null), "null");
    }

    private static void memoryFacts() {
        // yw-android kdf_gate::tests::the_answer_bytes.
        long gib = 1L << 30;
        byte[] facts = IoFrame.memoryFacts(3 * gib, gib, 200L << 20, false, true);
        check(facts.length == IoFrame.FACTS_LEN, "length");
        check(facts[0] == 0 && facts[3] == (byte) 0xc0, "total little-endian");
        check(facts[24] == 2, "isLowRamDevice is bit 1");
        check(IoFrame.memoryFacts(0, 0, 0, true, false)[24] == 1, "lowMemory is bit 0");
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static void factsInput() {
        // The same bytes as yw-android interim's the_facts_input test.
        check(
                Arrays.equals(
                        Wire.facts(29, "2021-01-01", true, false),
                        ascii("{\"t\":\"facts\",\"sdk\":29,\"patch\":\"2021-01-01\",\"adb\":true,\"adbw\":false}")),
                "test device");
        check(
                Arrays.equals(
                        Wire.facts(36, "", false, true),
                        ascii("{\"t\":\"facts\",\"sdk\":36,\"patch\":\"\",\"adb\":false,\"adbw\":true}")),
                "no patch");
        for (String bad : new String[] {null, "", "2021-1-01", "2021/01/01", "2021-01-01 ", "x\"}", "2021-01-0a"}) {
            String sent = new String(Wire.facts(31, bad, false, false), StandardCharsets.US_ASCII);
            check(sent.contains("\"patch\":\"\""), "patch sent as empty: " + bad);
        }
        check(new String(Wire.facts(-1, "", false, false), StandardCharsets.US_ASCII).contains("\"sdk\":0,"), "negative");
        check(
                new String(Wire.facts(Wire.SDK_MAX + 1, "", false, false), StandardCharsets.US_ASCII)
                        .contains("\"sdk\":0,"),
                "too large");
        check(
                new String(Wire.facts(Wire.SDK_MAX, "", false, false), StandardCharsets.US_ASCII)
                        .contains("\"sdk\":" + Wire.SDK_MAX + ","),
                "largest");
    }

    private static void bandsAnswer() {
        String first = "\uC2DC\uD5D8\uC6A9 \uBE4C\uB4DC";
        String second = "This device's protection is weak (use it for testing only).";
        String[] two = Wire.bands((first + "\n" + second).getBytes(StandardCharsets.UTF_8));
        check(two != null && two.length == 2 && two[0].equals(first) && two[1].equals(second), "two lines");
        check(Wire.bands(new byte[0]).length == 0, "no band");
        check(Wire.bands(null) == null, "null");
        check(Wire.bands(new byte[] {(byte) 0xC3}) == null, "cut UTF-8");
        check(Wire.bands(new byte[] {(byte) 0xED, (byte) 0xA0, (byte) 0x80}) == null, "surrogate");
        check(Wire.bands(ascii("a\n")) == null, "empty last line");
        check(Wire.bands(ascii("a\n\nb")) == null, "empty line");
        check(Wire.bands(ascii("a\rb")) == null, "control");
        check(Wire.bands(ascii("a\tb")) == null, "tab");
        check(Wire.bands(new byte[] {'a', 0x7f}) == null, "delete");
        byte[] longest = new byte[Wire.BANDS_MAX];
        Arrays.fill(longest, (byte) 'a');
        check(Wire.bands(longest) != null, "longest");
        check(Wire.bands(Arrays.copyOf(longest, Wire.BANDS_MAX + 1)) == null, "too long");
    }
}
