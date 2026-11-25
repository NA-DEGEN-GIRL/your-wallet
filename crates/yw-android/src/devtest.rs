//! The `-DeviceTest` debug build's test points (spec/09 §2.6): compiled only into a debug APK built
//! with `scripts/build-android.ps1 -Variant debug -DeviceTest` (`--cfg yw_device_test`; never by
//! the gate, never into a release APK).
//!
//! 2026-11-25 A2-5: the panic test's fault points ([`fault_points`], read by the status call).
//!
//! 2026-11-25 A2-8: the A2-4b device round trip is gone. It made (or unlocked) a vault from the
//! public test vector under a fixed synthetic password on its own thread at every start, on the
//! same data folder the key worker now opens; the real flows (W01 → W08 → W10, W05, W02) and a
//! process kill between them are the device-key round trip now (spec/09 §2.6, A2 device run).
//! Before, that thread logged `devtest.done step=<created|reopened> …`.

use yw_engine::logging::{self, Field};

/// The fault file of [`fault_points`]: `<data folder>/devtest.fault`, written by hand with
/// `run-as` on the debuggable `-DeviceTest` APK (spec/09 §2.6). Read at most this many bytes.
const FAULT_FILE: &str = "devtest.fault";
const FAULT_MAX: u64 = 16;

/// The panic test of A2-5 (2026-11-25; spec/15 §5.3, spec/09 §2.1 fault injection, the
/// Android form of `YW_FAULT_POINT`): when the fault file holds exactly `call` (optionally with
/// one line end), the status call panics on its own (Java's) thread; `thread`, a new Rust thread
/// panics while the status call waits. Either way the panic hook must wipe the slots, write the
/// one `app.panic` line and `_exit(70)` (no tombstone, no crash record). Anything else, or no
/// file, does nothing. Compiled only with `--cfg yw_device_test` (never the gate's or a release
/// build); the status call is its only caller.
pub(crate) fn fault_points() {
    let Some(data) = crate::shell::data() else {
        return;
    };
    let Ok(file) = std::fs::File::open(data.join(FAULT_FILE)) else {
        return;
    };
    let mut named = Vec::new();
    if std::io::Read::read_to_end(&mut std::io::Read::take(file, FAULT_MAX), &mut named).is_err() {
        return;
    }
    let point = named.strip_suffix(b"\n").unwrap_or(&named);
    match point {
        b"call" => {
            logging::warn(
                "devtest",
                "devtest.fault",
                &[("point", Field::Word("call"))],
            );
            panic_now();
        }
        b"thread" => {
            logging::warn(
                "devtest",
                "devtest.fault",
                &[("point", Field::Word("thread"))],
            );
            if std::thread::Builder::new()
                .name("devtest-fault".into())
                .spawn(panic_now)
                .is_ok()
            {
                // The hook ends the process from the other thread.
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        }
        _ => {}
    }
}

#[expect(
    clippy::panic,
    reason = "the A2-5 fault point panics on purpose (-DeviceTest builds only)"
)]
fn panic_now() {
    panic!("devtest fault point");
}
