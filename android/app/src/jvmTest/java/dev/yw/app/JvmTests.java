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
        run("an unreadable debugging setting reads as on", JvmTests::settingOn);
        run("JSON is read strictly", JvmTests::jsonStrict);
        run("the pinned model frame is read as Rust writes it", JvmTests::modelFrame);
        run("screen inputs are the bytes Rust decodes", JvmTests::screenInputs);
        run("a field frame applies only to the edits Rust has seen", JvmTests::fieldFrames);
        run("QR modules are read from their hex", JvmTests::qrModules);
        run("secret window inputs are the bytes Rust decodes", JvmTests::secretInputs);
        run("the app keyboard types every printable ASCII unit", JvmTests::keyLayout);
        run("secret windows close by session, by window and by resync", JvmTests::secretWindows);
        run("the app is in the background only with no Activity started", JvmTests::startedCount);
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

    /** 2026-11-25 A2-7: the same bytes as yw-android secret_wire's and secret_keys' tests. */
    private static void secretInputs() {
        check(SecretWire.field(1, 0) == 0x100, "field token");
        check(SecretWire.field(7, 2) == 0x702, "field token 2");
        check(SecretWire.field(5, SecretWire.TARGET_PICK) == 0x540, "pick token");
        check(SecretWire.field(0, 0) == -1 && SecretWire.field(SecretWire.WIN_MAX + 1, 0) == -1, "no window");
        check(SecretWire.field(1, 256) == -1 && SecretWire.field(1, -1) == -1, "no target");
        check(SecretWire.field(SecretWire.WIN_MAX, 0x3f) == 0x7fffff3f, "largest token");
        check(Arrays.equals(
                        SecretWire.ready(4, 2, true, Wire.factsMembers(29, "2021-01-01", true, false)),
                        utf8("{\"t\":\"s_ready\",\"serial\":4,\"win\":2,\"secure\":true,\"sdk\":29,\"patch\":\"2021-01-01\","
                                + "\"adb\":true,\"adbw\":false}")),
                "ready");
        check(Arrays.equals(
                        SecretWire.button(2, "reveal", 1, "down"),
                        utf8("{\"t\":\"s_btn\",\"win\":2,\"b\":\"reveal\",\"i\":1,\"e\":\"down\"}")),
                "button");
        check(Arrays.equals(SecretWire.focus(2, false), utf8("{\"t\":\"s_focus\",\"win\":2,\"on\":false}")), "focus");
        check(Arrays.equals(SecretWire.back(2), utf8("{\"t\":\"s_back\",\"win\":2}")), "back");
        check(Arrays.equals(SecretWire.gone(4, 2), utf8("{\"t\":\"s_gone\",\"serial\":4,\"win\":2}")), "gone");
        // The facts input still has its own bytes (Wire.facts over the same members).
        check(Arrays.equals(
                        Wire.facts(29, "2021-01-01", true, false),
                        ascii("{\"t\":\"facts\",\"sdk\":29,\"patch\":\"2021-01-01\",\"adb\":true,\"adbw\":false}")),
                "facts");
    }

    /** A secret window as the registry sees it (no Activity). */
    private static final class FakeWin implements SecretWindows.Win {
        final long serial;
        final int win;
        boolean closed;

        FakeWin(long serial, int win) {
            this.serial = serial;
            this.win = win;
        }

        @Override
        public long serial() {
            return serial;
        }

        @Override
        public int win() {
            return win;
        }

        @Override
        public void closeFromRust() {
            closed = true;
        }
    }

    /**
     * 2026-11-25 A2-7 review (spec/15 §9.1): every live window is kept; a session with a window live or starting is not
     * started again; s_close closes all of a session's windows, s_close_win one, s_keep every window it does not name,
     * and a model goes to the window it names.
     */
    private static void secretWindows() {
        SecretWindows<FakeWin> windows = new SecretWindows<>();
        // Asked with no started Activity: pending, started later once.
        check(!windows.launch(4, false) && windows.takePending() == 4 && windows.takePending() == -1, "pending");
        check(windows.launch(4, true), "first launch");
        check(!windows.launch(4, true), "starting: not again");
        FakeWin first = new FakeWin(4, 1);
        windows.created(first);
        check(!windows.launch(4, true), "live: not again");
        // A duplicate (made before this fix could stop it): s_close_win closes it alone; the first one keeps its models.
        FakeWin duplicate = new FakeWin(4, 2);
        windows.created(duplicate);
        windows.closeWin(4, 2);
        check(duplicate.closed && !first.closed, "close_win closes that window only");
        windows.destroyed(duplicate);
        check(windows.find(4, 1) == first && windows.find(4, 2) == null && windows.find(5, 1) == null, "find");
        // s_close: every window of the session; a window still starting for it closes itself.
        FakeWin other = new FakeWin(4, 3);
        windows.created(other);
        windows.close(4);
        check(first.closed && other.closed && windows.wasClosed(4), "close closes every window of the session");
        check(!windows.launch(4, true), "a closed session is not started");
        windows.destroyed(first);
        windows.destroyed(other);
        check(windows.liveCount() == 0, "none live");
        // s_keep (a resync after a lost s_close): every window not named closes; win 0 keeps a session's windows.
        FakeWin stale = new FakeWin(7, 4);
        FakeWin open = new FakeWin(8, 5);
        FakeWin twin = new FakeWin(8, 6);
        windows.created(stale);
        windows.created(open);
        windows.created(twin);
        check(windows.launch(9, true), "asked 9");
        windows.keep(java.util.List.of(new long[] {8, 5}));
        check(stale.closed && windows.wasClosed(7), "an unnamed session closes");
        check(!open.closed && twin.closed && !windows.wasClosed(8), "a duplicate of a named session closes alone");
        check(windows.wasClosed(9), "an unnamed starting session closes itself when made");
        FakeWin asked = new FakeWin(10, 7);
        windows.created(asked);
        windows.keep(java.util.List.of(new long[] {10, 0}));
        check(!asked.closed && open.closed, "win 0 keeps the asked session's windows");
        windows.keep(java.util.List.of());
        check(asked.closed, "an empty keep closes every window");
        // The frame Rust's secret_wire::keep_frame writes.
        Object frame = Json.parse(utf8("{\"t\":\"s_keep\",\"wins\":[{\"serial\":8,\"win\":5},{\"serial\":10,\"win\":0}]}"));
        java.util.List<long[]> kept = SecretWire.kept(frame);
        check(kept.size() == 2 && kept.get(0)[0] == 8 && kept.get(0)[1] == 5 && kept.get(1)[1] == 0, "kept");
        check(SecretWire.kept(Json.parse(utf8("{\"t\":\"s_keep\",\"wins\":[{\"serial\":-1,\"win\":0}]}"))).isEmpty(),
                "an unreadable entry keeps nothing");
    }

    /** 2026-11-25 A2-7 review (spec/15 §5.4): front on the first started Activity, back when none is started. */
    private static void startedCount() {
        SecretWindows<FakeWin> windows = new SecretWindows<>();
        check(windows.started(), "main starts: front");
        // A secret window covers the main one: its onStart comes before the main one's onStop.
        check(!windows.started(), "secret starts");
        check(!windows.stopped(), "main stops: not the background");
        // The secret window closes: main starts again, then the secret window stops.
        check(!windows.started() && !windows.stopped(), "back to main");
        check(windows.stopped(), "home: back");
        check(!windows.stopped(), "no count below zero");
        check(windows.started(), "front again");
    }

    /** 2026-11-25 A2-7 (spec/15 §9.2): the four text layers hold exactly printable ASCII; words and letters a-z. */
    private static void keyLayout() {
        java.util.Set<Integer> text = new java.util.TreeSet<>();
        for (int layer = KeyLayout.LOWER; layer <= KeyLayout.MORE; layer++) {
            for (int[] row : KeyLayout.rows("text", layer)) {
                for (int code : row) {
                    if (KeyLayout.sends(code)) {
                        text.add(code);
                    } else {
                        check(code == KeyLayout.SHIFT || code == KeyLayout.SYMBOLS || code == KeyLayout.LETTERS, "layer key");
                    }
                    check(!KeyLayout.label(code, layer).isEmpty(), "label");
                }
            }
        }
        java.util.Set<Integer> expected = new java.util.TreeSet<>();
        for (int unit = 0x20; unit <= 0x7e; unit++) {
            expected.add(unit);
        }
        expected.add(KeyLayout.BACKSPACE);
        expected.add(KeyLayout.ENTER);
        check(text.equals(expected), "text layers: " + text);
        java.util.Set<Integer> words = new java.util.TreeSet<>();
        for (int[] row : KeyLayout.rows("words", 0)) {
            for (int code : row) {
                words.add(code);
            }
        }
        java.util.Set<Integer> letters = new java.util.TreeSet<>();
        for (int[] row : KeyLayout.rows("letters", 0)) {
            for (int code : row) {
                letters.add(code);
            }
        }
        java.util.Set<Integer> az = new java.util.TreeSet<>();
        for (int unit = 'a'; unit <= 'z'; unit++) {
            az.add(unit);
        }
        az.add(KeyLayout.BACKSPACE);
        az.add(KeyLayout.ENTER);
        check(letters.equals(az), "letters: " + letters);
        az.add(KeyLayout.SPACE);
        check(words.equals(az), "words: " + words);
        check(KeyLayout.rows("none", 0).length == 0 && KeyLayout.rows(null, 0).length == 0, "none");
        check(KeyLayout.next(KeyLayout.LOWER, KeyLayout.SHIFT) == KeyLayout.UPPER, "shift");
        check(KeyLayout.next(KeyLayout.UPPER, KeyLayout.SHIFT) == KeyLayout.LOWER, "shift back");
        check(KeyLayout.next(KeyLayout.LOWER, KeyLayout.SYMBOLS) == KeyLayout.SYMBOL, "symbols");
        check(KeyLayout.next(KeyLayout.SYMBOL, KeyLayout.SHIFT) == KeyLayout.MORE, "more");
        check(KeyLayout.next(KeyLayout.MORE, KeyLayout.SHIFT) == KeyLayout.SYMBOL, "more back");
        check(KeyLayout.next(KeyLayout.MORE, KeyLayout.LETTERS) == KeyLayout.LOWER, "letters");
        check(KeyLayout.next(KeyLayout.UPPER, 'A') == KeyLayout.UPPER, "a key keeps the layer");
        // Labels are characters or symbols: no Hangul, no letters beyond the keyboard's own glyphs.
        for (int code = 0x20; code <= 0x7e; code++) {
            check(KeyLayout.label(code, 0).length() == 1, "label of " + code);
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

    private static void settingOn() {
        // 2026-11-25 A2-5 review: missing or malformed is on, except a missing adb_wifi_enabled before API 30.
        String[] raws = {null, "", "x", "0", "1", "2", "-1", " 1", "0x1", "99999999999"};
        boolean[] on = {true, true, true, false, true, true, true, true, true, true};
        boolean[] onWhenAbsentIsOff = {false, true, true, false, true, true, true, true, true, true};
        for (int at = 0; at < raws.length; at++) {
            String name = raws[at] == null ? "null" : "\"" + raws[at] + "\"";
            check(Wire.settingOn(raws[at], false) == on[at], "setting " + name);
            check(Wire.settingOn(raws[at], true) == onWhenAbsentIsOff[at], "setting before API 30 " + name);
        }
    }

    private static void jsonStrict() {
        // 2026-11-25 A2-6: the reader of the UI frames.
        Object value = Json.parse(utf8("{\"a\":[1,-2,true,false,null],\"b\":\"x\\u00e9\\n\\\"\"}"));
        check(Json.list(value, "a").size() == 5, "array");
        check(Long.valueOf(-2).equals(Json.list(value, "a").get(1)), "negative");
        check(Json.list(value, "a").get(4) == Json.NULL, "null");
        check("x\u00e9\n\"".equals(Json.string(value, "b")), "escapes");
        check(Json.parse(utf8("{\"a\":1,\"a\":2}")) == null, "duplicate key");
        check(Json.parse(utf8("1.5")) == null, "fraction");
        check(Json.parse(utf8("1e3")) == null, "exponent");
        check(Json.parse(utf8("01")) == null, "leading zero");
        check(Json.parse(utf8("{} x")) == null, "trailing");
        check(Json.parse(utf8("\"a\nb\"")) == null, "raw control");
        check(Json.parse(new byte[] {'"', (byte) 0xC3, '"'}) == null, "cut UTF-8");
        check(Json.parse(utf8("[".repeat(33) + "]".repeat(33))) == null, "too deep");
        check(Json.parse(utf8("[".repeat(32) + "]".repeat(32))) != null, "deep enough");
        check(Json.parse(utf8("99999999999999999999")) == null, "too large");
        check("\"a\\\"b\\\\c\\u0001\"".equals(Json.quote("a\"b\\c\u0001")), "quote");
    }

    /** The same string as yw-engine tests/wire.rs MODEL_FRAME (Rust pins its bytes, Java reads them). */
    private static final String MODEL_FRAME = "{\"t\":\"model\",\"rev\":7,\"items\":[{\"k\":\"title\",\"text\":\"Hi\"},"
            + "{\"k\":\"banner\",\"text\":\"état \\\"x\\\"\",\"tone\":\"warn\",\"tag\":\"Caution\"},"
            + "{\"k\":\"row\",\"ctls\":[{\"s\":0,\"c\":\"button\",\"style\":\"primary\",\"text\":\"Go\",\"on\":true,"
            + "\"checked\":null,\"first\":null,\"password\":null,\"readonly\":null,\"limit\":null,\"badge\":null,"
            + "\"compact\":false,\"face\":null,\"tip\":null},{\"s\":1,\"c\":\"check\",\"style\":null,\"text\":\"C\","
            + "\"on\":false,\"checked\":true,\"first\":null,\"password\":null,\"readonly\":null,\"limit\":null,"
            + "\"badge\":null,\"compact\":false,\"face\":null,\"tip\":null}]},{\"k\":\"lrow\",\"label\":\"N\","
            + "\"ctls\":[{\"s\":2,\"c\":\"edit\",\"style\":null,\"text\":\"a\",\"on\":true,\"checked\":null,"
            + "\"first\":null,\"password\":false,\"readonly\":false,\"limit\":32,\"badge\":null,"
            + "\"compact\":false,\"face\":null,\"tip\":null}]}]}";

    private static void modelFrame() {
        byte[] json = utf8(MODEL_FRAME);
        byte[] framed = new byte[json.length + 1];
        framed[0] = (byte) UiWire.FRAME_UI;
        System.arraycopy(json, 0, framed, 1, json.length);
        Object frame = UiWire.frame(framed);
        check("model".equals(Json.string(frame, "t")), "kind");
        check(Json.number(frame, "rev", -1) == 7, "rev");
        java.util.List<?> items = Json.list(frame, "items");
        check(items.size() == 4, "items");
        check("état \"x\"".equals(Json.string(items.get(1), "text")), "banner text");
        check("Caution".equals(Json.string(items.get(1), "tag")), "banner tag");
        Object box = Json.list(items.get(2), "ctls").get(1);
        check(Json.number(box, "s", -1) == 1, "slot 1");
        check(Boolean.FALSE.equals(Json.bool(box, "on")) && Boolean.TRUE.equals(Json.bool(box, "checked")), "check");
        Object edit = Json.list(items.get(3), "ctls").get(0);
        check(Json.number(edit, "s", -1) == 2 && Json.number(edit, "limit", -1) == 32, "edit");
        check(UiWire.frame(json) == null, "untagged");
        check(UiWire.frame(new byte[] {(byte) UiWire.FRAME_UI, '{'}) == null, "cut");
    }

    private static void fieldFrames() {
        // 2026-11-25 A2-6 review: the shape yw-android ui_host writes (its test a_render_answer_hands_back_the_edit_texts).
        byte[] json = utf8("{\"t\":\"field\",\"rev\":2,\"slot\":3,\"text\":\"written\",\"seen\":1}");
        byte[] framed = new byte[json.length + 1];
        framed[0] = (byte) UiWire.FRAME_UI;
        System.arraycopy(json, 0, framed, 1, json.length);
        Object frame = UiWire.frame(framed);
        check("written".equals(Json.string(frame, "text")), "text");
        check(UiWire.fieldApplies(frame, 2, 1), "applies");
        check(!UiWire.fieldApplies(frame, 2, 2), "an edit sent since");
        check(!UiWire.fieldApplies(frame, 2, 0), "seen more than sent");
        check(!UiWire.fieldApplies(frame, 3, 1), "another model");
        Object unseen = Json.parse(utf8("{\"t\":\"field\",\"rev\":2,\"slot\":3,\"text\":\"x\"}"));
        check(!UiWire.fieldApplies(unseen, 2, 0), "no seen member");
    }

    private static void screenInputs() {
        // The same strings the Rust tests decode (yw-engine wire::tests, tests/fuzz_lite_android_input.rs seeds).
        check(Arrays.equals(UiWire.press(3, 7), utf8("{\"t\":\"press\",\"rev\":3,\"slot\":7}")), "press");
        check(Arrays.equals(UiWire.edit(2, 1, "a\"b"), utf8("{\"t\":\"edit\",\"rev\":2,\"slot\":1,\"text\":\"a\\\"b\"}")), "edit");
        check(UiWire.edit(1, 1, "a".repeat(UiWire.INPUT_MAX)) == null, "edit too long");
        check(Arrays.equals(UiWire.rendered(9, -1, 8), utf8("{\"t\":\"rendered\",\"rev\":9,\"focus\":null,\"of\":null}")),
                "rendered none");
        check(Arrays.equals(UiWire.rendered(9, 4, 8), utf8("{\"t\":\"rendered\",\"rev\":9,\"focus\":4,\"of\":8}")), "rendered");
        check(Arrays.equals(UiWire.life("back"), utf8("{\"t\":\"life\",\"e\":\"back\"}")), "life");
        check(Arrays.equals(UiWire.tick(), utf8("{\"t\":\"tick\"}")), "tick");
        check(Arrays.equals(UiWire.timer("send_check"), utf8("{\"t\":\"timer\",\"id\":\"send_check\"}")), "timer");
        check(Arrays.equals(UiWire.copied(5, true), utf8("{\"t\":\"copied\",\"id\":5,\"ok\":true}")), "copied");
        check(UiWire.TICK_MS == 250, "tick period");
    }

    private static void qrModules() {
        // 3 x 3 modules: 101 010 101 -> 1010 1010 1(000 0000) -> "aa80".
        boolean[] dark = UiWire.qrModules(3, "aa80");
        check(dark != null && dark.length == 9, "size");
        boolean[] want = {true, false, true, false, true, false, true, false, true};
        check(Arrays.equals(dark, want), "modules");
        check(UiWire.qrModules(3, "aa8") == null, "short");
        check(UiWire.qrModules(3, "aa8z") == null, "not hex");
        check(UiWire.qrModules(0, "") == null, "empty");
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
