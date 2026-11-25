#![allow(unsafe_code)]
//! The JNI boundary (spec/15 §3.2): `JNI_OnLoad`, the only entry Java reaches by symbol, and the five
//! methods it registers with `RegisterNatives` on [`NATIVE_CLASS`] (no `Java_*` exports).
//!
//! `JNI_OnLoad` first calls `prctl(PR_SET_DUMPABLE, 0)` and checks it took (spec/15 §5.3: before
//! `:browser` or any Activity exists, so no other process of the same UID can read this one's memory
//! through `/proc/<pid>/mem` or ptrace), then installs the panic hook, then registers the methods.
//! Any failure returns `JNI_ERR`: the Java `System.loadLibrary` throws and the app cannot reach the
//! wallet (fail closed). Rust never calls into Java afterwards: no `AttachCurrentThread`, no global
//! reference, no cached `jclass` (spec/15 §3.2); the table is used only inside a call Java made.
//!
//! 2026-11-24 A2-1: the five methods are stubs that read nothing and answer "nothing": `call` and
//! `next` return null, `ioComplete` and `secretKey` do nothing, `secretFill` returns 0 and writes
//! nothing (an unknown handle, spec/15 §3.2). A2-6 and A2-7 give them their bodies. (2026-11-24
//! A2-3: `call` knows the two interim inputs of [`crate::interim`] — the status request, answered
//! with the status line through `NewByteArray`/`SetByteArrayRegion`, and Java's uncaught-exception
//! event, which ends the process like a panic; the other four are still stubs.) (2026-11-25
//! A2-4b: `call` also takes the start input; `next` hands out the platform I/O requests of
//! [`crate::io_request`] and `ioComplete` answers them — the same table entries, no new index;
//! `secretKey` and `secretFill` are still stubs.) (2026-11-25 A2-7: `secretKey` feeds the open
//! secret window (`crate::shell::secret_key`) and `secretFill` writes a handle's units into Java's
//! `char[]` with `GetArrayLength` and `SetCharArrayRegion` — the indices P0-1 checked under
//! `CheckJNI`, no new one — and returns how many it wrote; the Rust copy is wiped when dropped.)
//!
//! 2026-11-24 A2-1 review: ART's `RegisterNatives` binds the methods in order and stops at the first
//! it cannot find, leaving the earlier ones bound. So every method body runs only through
//! [`when_loaded`], which answers "nothing" until `JNI_OnLoad` has registered all five and set
//! [`LOADED`]: a Java caller that caught the `UnsatisfiedLinkError` of a failed load (or a second
//! class loader) reaches no wallet code through a half-registered surface. Java treats a failed
//! `System.loadLibrary` as fatal and never catches it (spec/15 §3.2); this flag does not rely on that.
//! (Before, the stubs had no such check; `UnregisterNatives` on failure was not taken because its
//! table index is not yet checked under `CheckJNI`.)

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicBool, Ordering};

use yw_core::secret::Zeroizing;
use yw_engine::protection::Surface;

use crate::interim::{self, Interim};
use crate::io_request;
use crate::jni_table::{JNI_ERR, JNI_OK, JNI_VERSION_1_6, METHODS, NATIVE_CLASS, env, vm};

/// Set (`Release`) only after `RegisterNatives` returned `JNI_OK` for all five methods; never cleared.
static LOADED: AtomicBool = AtomicBool::new(false);

/// Runs `body` only when `JNI_OnLoad` succeeded (`LOADED`, `Acquire`); else answers `nothing`, the
/// method's "no answer" (null, 0 or nothing done).
fn when_loaded<T>(nothing: T, body: impl FnOnce() -> T) -> T {
    if LOADED.load(Ordering::Acquire) {
        body()
    } else {
        nothing
    }
}

/// A function table: an array of C function pointers.
type FnTable = *const *const c_void;
/// `JNIEnv*`: a pointer to the table pointer.
type JniEnv = *const FnTable;
/// `JavaVM*`: a pointer to the table pointer.
type JavaVm = *const FnTable;
/// `jobject` and its kinds (`jclass`, `jbyteArray`, `jcharArray`).
type JObject = *mut c_void;

/// `JNINativeMethod`.
#[repr(C)]
struct NativeMethod {
    name: *const c_char,
    signature: *const c_char,
    fn_ptr: *mut c_void,
}

/// Reads entry `$index` of the function table that `$holder` (a `JNIEnv*` or `JavaVM*` ART passed
/// to the current call) points to, as `Option<$ty>` (`None` for a null entry).
macro_rules! table_fn {
    ($holder:expr, $index:expr, $ty:ty) => {{
        let holder: *const FnTable = $holder;
        // SAFETY: `holder` is the live `JNIEnv*`/`JavaVM*` of the current call on this thread; it
        // points to the table pointer.
        let table = unsafe { *holder };
        // SAFETY: `$index` is below the table's length (`jni_table`, unit-tested), so the entry is
        // inside the table.
        let entry = unsafe { table.add($index) };
        // SAFETY: Entry `$index` holds a function of exactly the C type `$ty` (NDK r30 `jni.h`,
        // checked under CheckJNI in P0-1) or null; `Option` of a function pointer has the null niche.
        unsafe { entry.cast::<Option<$ty>>().read() }
    }};
}

type GetEnvFn = unsafe extern "C" fn(JavaVm, *mut *mut c_void, i32) -> i32;
type FindClassFn = unsafe extern "C" fn(JniEnv, *const c_char) -> JObject;
type ExceptionCheckFn = unsafe extern "C" fn(JniEnv) -> u8;
type ExceptionClearFn = unsafe extern "C" fn(JniEnv);
type DeleteLocalRefFn = unsafe extern "C" fn(JniEnv, JObject);
type RegisterNativesFn = unsafe extern "C" fn(JniEnv, JObject, *const NativeMethod, i32) -> i32;
type GetArrayLengthFn = unsafe extern "C" fn(JniEnv, JObject) -> i32;
type NewByteArrayFn = unsafe extern "C" fn(JniEnv, i32) -> JObject;
type GetByteArrayRegionFn = unsafe extern "C" fn(JniEnv, JObject, i32, i32, *mut i8);
type SetByteArrayRegionFn = unsafe extern "C" fn(JniEnv, JObject, i32, i32, *const i8);
type SetCharArrayRegionFn = unsafe extern "C" fn(JniEnv, JObject, i32, i32, *const u16);

/// Clears a pending Java exception (one `FindClass` or `RegisterNatives` threw), so the loader's own
/// error is what Java sees.
fn clear_exception(jni: JniEnv) {
    let Some(check) = table_fn!(jni, env::EXCEPTION_CHECK, ExceptionCheckFn) else {
        return;
    };
    // SAFETY: `jni` is the current thread's `JNIEnv*`; `ExceptionCheck` may be called with an
    // exception pending.
    let pending = unsafe { check(jni) } != 0;
    if pending && let Some(clear) = table_fn!(jni, env::EXCEPTION_CLEAR, ExceptionClearFn) {
        // SAFETY: As above; `ExceptionClear` is allowed with an exception pending.
        unsafe { clear(jni) };
    }
}

/// The longest input `call` reads: a screen input (yw-engine `wire::INPUT_MAX`), longer than the
/// interim ones (2026-11-25 A2-6; before, [`interim::START_MAX`]).
const INPUT_READ_MAX: usize = if yw_engine::wire::INPUT_MAX > interim::START_MAX {
    yw_engine::wire::INPUT_MAX
} else {
    interim::START_MAX
};

/// `byte[] call(byte[] cmd)`: the engine's input (spec/15 §3.2). 2026-11-24 A2-3: only the two
/// interim inputs ([`interim`]): the status request is answered with the status line, the
/// uncaught-exception event ends the process like a panic; anything else (or more than
/// [`interim::MAX_INPUT`] bytes, which are not read) is answered with null. The engine joins in A2-6.
/// 2026-11-25 A2-4b: also the start input ([`interim::start_dir`], at most
/// [`interim::START_MAX`] bytes read): the shell starts on that folder ([`crate::shell::start`])
/// and answers the status line, or null when it could not. 2026-11-25 A2-5: the uncaught-exception
/// event writes its line (`panic_hook::java_uncaught`); the facts input ([`interim::facts`]) is
/// kept and answered with the main screen's bands from those facts
/// ([`crate::device::bands_with`]) in the default language (Korean until the settings are read,
/// A2-8; 2026-11-25 A2-8: the app language, `crate::shell::language`); a `-DeviceTest` build checks its fault points on the status request
/// (`crate::devtest::fault_points`; 2026-11-25 A2 device run: also right after the start input
/// started the shell, since Java no longer sends the status request). (2026-11-25 A2-5 review: an input that begins like a facts
/// input ([`interim::is_facts`]) but is refused is answered with the worst case's bands, never
/// null, so the test-build band cannot go missing.) 2026-11-25 A2-6: every other input (up to
/// [`INPUT_READ_MAX`] bytes) is a screen input of the wire format (yw-engine `wire`, spec/15 §18 8):
/// the screen host takes it (`crate::shell::ui_input`) and `call` answers null; the
/// frames it makes go out through `next`.
extern "C" fn call(jni: JniEnv, _class: JObject, input: JObject) -> JObject {
    when_loaded(core::ptr::null_mut(), || {
        let Some(bytes) = read_bytes(jni, input, INPUT_READ_MAX) else {
            return core::ptr::null_mut();
        };
        match interim::classify(&bytes) {
            Interim::Status => {
                #[cfg(yw_device_test)]
                crate::devtest::fault_points();
                new_byte_array(jni, interim::STATUS_LINE.as_bytes())
            }
            Interim::JavaUncaught => crate::panic_hook::java_uncaught(),
            Interim::Unknown => {
                if let Some(dir) = interim::start_dir(&bytes) {
                    if crate::shell::start(&dir) {
                        // 2026-11-25 A2 device run: Java has not sent the status request since
                        // A2-6, so the fault points are read once the start input made the data
                        // folder (before, only on the status request: unreachable on the device).
                        #[cfg(yw_device_test)]
                        crate::devtest::fault_points();
                        new_byte_array(jni, interim::STATUS_LINE.as_bytes())
                    } else {
                        core::ptr::null_mut()
                    }
                } else if interim::is_facts(&bytes) {
                    let now = crate::shell::now_unix_ms();
                    let fresh = interim::facts(&bytes);
                    let bands = crate::device::bands_with(fresh, Surface::Main, now);
                    // 2026-11-25 A2-8: in the app language (before, always the default).
                    new_byte_array(
                        jni,
                        &interim::bands_answer(&bands, crate::shell::language()),
                    )
                } else {
                    // 2026-11-25 A2-6: a screen input; its frames go out through `next`.
                    crate::shell::ui_input(&bytes);
                    core::ptr::null_mut()
                }
            }
        }
    })
}

/// Copies a Java `byte[]` of at most `max` bytes into a buffer wiped on drop; `None` for null, a
/// longer array (not read) or a failed copy.
fn read_bytes(jni: JniEnv, array: JObject, max: usize) -> Option<Zeroizing<Vec<u8>>> {
    if array.is_null() {
        return None;
    }
    let length_of = table_fn!(jni, env::GET_ARRAY_LENGTH, GetArrayLengthFn)?;
    // SAFETY: `jni` is the current thread's `JNIEnv*` inside a native call; `array` is the non-null
    // local reference of the `byte[]` parameter Java passed.
    let length = unsafe { length_of(jni, array) };
    let len = usize::try_from(length).ok()?;
    if len > max {
        return None;
    }
    let mut bytes = Zeroizing::new(vec![0_u8; len]);
    if len == 0 {
        return Some(bytes);
    }
    let region = table_fn!(jni, env::GET_BYTE_ARRAY_REGION, GetByteArrayRegionFn)?;
    // SAFETY: As above; `0..length` is inside the array (its length was just read) and `bytes` has
    // exactly `length` bytes of room.
    unsafe { region(jni, array, 0, length, bytes.as_mut_ptr().cast()) };
    if exception_pending(jni) {
        return None;
    }
    Some(bytes)
}

/// A new Java `byte[]` holding `bytes`, or null (an exception it caused is cleared).
fn new_byte_array(jni: JniEnv, bytes: &[u8]) -> JObject {
    let Ok(length) = i32::try_from(bytes.len()) else {
        return core::ptr::null_mut();
    };
    let Some(new_array) = table_fn!(jni, env::NEW_BYTE_ARRAY, NewByteArrayFn) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `jni` is the current thread's `JNIEnv*` inside a native call; `length` ≥ 0.
    let array = unsafe { new_array(jni, length) };
    if array.is_null() {
        clear_exception(jni);
        return core::ptr::null_mut();
    }
    let Some(set_region) = table_fn!(jni, env::SET_BYTE_ARRAY_REGION, SetByteArrayRegionFn) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `array` is the new `byte[]` of exactly `length` elements; `bytes` holds `length` bytes.
    unsafe { set_region(jni, array, 0, length, bytes.as_ptr().cast()) };
    if exception_pending(jni) {
        return core::ptr::null_mut();
    }
    array
}

/// Whether a Java exception is pending; if so it is cleared (the caller answers "nothing").
fn exception_pending(jni: JniEnv) -> bool {
    let Some(check) = table_fn!(jni, env::EXCEPTION_CHECK, ExceptionCheckFn) else {
        return true;
    };
    // SAFETY: `jni` is the current thread's `JNIEnv*`; `ExceptionCheck` may be called any time.
    let pending = unsafe { check(jni) } != 0;
    if pending {
        clear_exception(jni);
    }
    pending
}

/// The longest wait of one `next` call (Java's I/O thread calls it in a loop).
const NEXT_WAIT_MAX_MS: u64 = 10_000;

/// `byte[] next(long timeoutMs)`: effects, the screen model and platform I/O requests. 2026-11-25
/// A2-4b: the platform I/O requests of [`crate::io_request`] (the Keystore device key, the memory
/// facts), waiting up to `timeoutMs` (at most [`NEXT_WAIT_MAX_MS`]); null when none came. The
/// Rust copy of the frame is wiped once the Java array holds it (the wrap request carries the
/// plain file key, spec/15 §3.2). 2026-11-25 A2-6: and the UI frames of the screen host
/// ([`io_request::FRAME_UI`]: the screen model and the effects Java applies, `crate::ui_host`),
/// after any waiting I/O request.
extern "C" fn next(jni: JniEnv, _class: JObject, timeout_ms: i64) -> JObject {
    when_loaded(core::ptr::null_mut(), || {
        let wait = u64::try_from(timeout_ms).map_or(0, |ms| ms.min(NEXT_WAIT_MAX_MS));
        match crate::shell::BROKER.take(core::time::Duration::from_millis(wait)) {
            Some(frame) => new_byte_array(jni, &frame),
            None => core::ptr::null_mut(),
        }
    })
}

/// `void ioComplete(long id, int status, byte[] body)`: a platform I/O result (2026-11-25 A2-4b).
/// The body (at most [`io_request::ANSWER_MAX`] bytes; a longer one is not read and the request
/// fails with `BAD_REQUEST`) goes to the waiting request; an id that is not waiting (late, unknown,
/// negative, answered twice) is dropped with its body wiped (spec/15 §3.2, §18 42 N9).
extern "C" fn io_complete(jni: JniEnv, _class: JObject, id: i64, status: i32, body: JObject) {
    when_loaded((), || {
        let Ok(id) = u64::try_from(id) else {
            return;
        };
        let (status, body) = if body.is_null() {
            (status, Zeroizing::new(Vec::new()))
        } else {
            match read_bytes(jni, body, io_request::ANSWER_MAX) {
                Some(bytes) => (status, bytes),
                None => (io_request::status::BAD_REQUEST, Zeroizing::new(Vec::new())),
            }
        };
        crate::shell::BROKER.complete(id, status, body);
    });
}

/// `void secretKey(int field, int codeUnit)`: one app-keyboard key (spec/15 §9.2; 2026-11-25 A2-7):
/// the shell feeds it to the open secret window the field token names (`crate::secret_keys`).
/// Before A2-7 a stub.
extern "C" fn secret_key(_jni: JniEnv, _class: JObject, field: i32, code_unit: i32) {
    when_loaded((), || crate::shell::secret_key(field, code_unit));
}

/// `int secretFill(long handle, char[] out)`: a secret display fill (spec/15 §3.2, §9.1; 2026-11-25
/// A2-7). The handle's units (`crate::secret_host::SecretHost::fill`) go straight into `out` with
/// `SetCharArrayRegion` when they fit; the answer is how many were written, 0 (nothing written)
/// for an unknown or closed handle, masked content, a null array or one too short. The Rust copy
/// is wiped when dropped. Before A2-7 a stub that answered 0.
extern "C" fn secret_fill(jni: JniEnv, _class: JObject, handle: i64, out: JObject) -> i32 {
    when_loaded(0, || {
        if out.is_null() {
            return 0;
        }
        match crate::shell::secret_fill(handle) {
            Some(units) => write_chars(jni, out, &units),
            None => 0,
        }
    })
}

/// Writes `units` at the start of the Java `char[]` `array` when they fit; how many were written
/// (0 for none, a failed copy or an array too short).
fn write_chars(jni: JniEnv, array: JObject, units: &[u16]) -> i32 {
    let Ok(count) = i32::try_from(units.len()) else {
        return 0;
    };
    if count == 0 {
        return 0;
    }
    let Some(length_of) = table_fn!(jni, env::GET_ARRAY_LENGTH, GetArrayLengthFn) else {
        return 0;
    };
    // SAFETY: `jni` is the current thread's `JNIEnv*` inside a native call; `array` is the non-null
    // local reference of the `char[]` parameter Java passed.
    let capacity = unsafe { length_of(jni, array) };
    if count > capacity {
        return 0;
    }
    let Some(set_region) = table_fn!(jni, env::SET_CHAR_ARRAY_REGION, SetCharArrayRegionFn) else {
        return 0;
    };
    // SAFETY: As above; `0..count` is inside the array (`count` ≤ its length, just read) and
    // `units` holds `count` UTF-16 units (`jchar`).
    unsafe { set_region(jni, array, 0, count, units.as_ptr()) };
    if exception_pending(jni) {
        return 0;
    }
    count
}

/// The function of each [`METHODS`] entry, in the same order.
fn method_fns() -> [*mut c_void; 5] {
    [
        call as *mut c_void,
        next as *mut c_void,
        io_complete as *mut c_void,
        secret_key as *mut c_void,
        secret_fill as *mut c_void,
    ]
}

/// Registers the five methods on [`NATIVE_CLASS`].
fn register(jni: JniEnv) -> Result<(), ()> {
    let find = table_fn!(jni, env::FIND_CLASS, FindClassFn).ok_or(())?;
    // SAFETY: `jni` is the current thread's `JNIEnv*` inside `JNI_OnLoad` (the class loader of the
    // library's caller); the name is a NUL-terminated modified-UTF-8 class name.
    let class = unsafe { find(jni, NATIVE_CLASS.as_ptr()) };
    if class.is_null() {
        clear_exception(jni);
        return Err(());
    }
    let methods: Vec<NativeMethod> = METHODS
        .iter()
        .zip(method_fns())
        .map(|(method, fn_ptr)| NativeMethod {
            name: method.name.as_ptr(),
            signature: method.signature.as_ptr(),
            fn_ptr,
        })
        .collect();
    let count = i32::try_from(methods.len()).map_err(|_| ())?;
    let registered = match table_fn!(jni, env::REGISTER_NATIVES, RegisterNativesFn) {
        // SAFETY: `class` is a live local reference; `methods` holds `count` entries whose names and
        // signatures are static NUL-terminated strings and whose functions have the C signatures
        // those JNI signatures name (`JNIEnv*`, `jclass`, then the Java parameters).
        Some(register_natives) => unsafe { register_natives(jni, class, methods.as_ptr(), count) },
        None => JNI_ERR,
    };
    if registered != JNI_OK {
        clear_exception(jni);
    }
    if let Some(delete) = table_fn!(jni, env::DELETE_LOCAL_REF, DeleteLocalRefFn) {
        // SAFETY: `class` is a local reference this call made and nothing uses after this.
        unsafe { delete(jni, class) };
    }
    if registered == JNI_OK {
        Ok(())
    } else {
        Err(())
    }
}

/// Sets the process non-dumpable and checks that it took.
fn set_not_dumpable() -> bool {
    let zero: libc::c_ulong = 0;
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` takes integer arguments only and reads no memory of ours.
    let set = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, zero, zero, zero, zero) };
    // SAFETY: `prctl(PR_GET_DUMPABLE)` takes integer arguments only and reads no memory of ours.
    let now = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, zero, zero, zero, zero) };
    set == 0 && now == 0
}

/// The library's load entry (spec/15 §3.2, §5.3).
///
/// # Safety
///
/// Called only by the Java VM when `System.loadLibrary` loads `libyw.so`, with its `JavaVM*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn JNI_OnLoad(java_vm: JavaVm, _reserved: *mut c_void) -> c_int {
    if !set_not_dumpable() {
        return JNI_ERR;
    }
    crate::panic_hook::install();
    let Some(get_env) = table_fn!(java_vm, vm::GET_ENV, GetEnvFn) else {
        return JNI_ERR;
    };
    let mut jni: *mut c_void = core::ptr::null_mut();
    // SAFETY: `java_vm` is the VM ART passed; `jni` is a valid out pointer for this call.
    let got = unsafe { get_env(java_vm, &raw mut jni, JNI_VERSION_1_6) };
    if got != JNI_OK || jni.is_null() {
        return JNI_ERR;
    }
    match register(jni.cast_const().cast()) {
        Ok(()) => {
            LOADED.store(true, Ordering::Release);
            JNI_VERSION_1_6
        }
        Err(()) => JNI_ERR,
    }
}
