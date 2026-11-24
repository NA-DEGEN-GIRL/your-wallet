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
//! nothing (an unknown handle, spec/15 §3.2). A2-6 and A2-7 give them their bodies.

use core::ffi::{c_char, c_int, c_void};

use crate::jni_table::{JNI_ERR, JNI_OK, JNI_VERSION_1_6, METHODS, NATIVE_CLASS, env, vm};

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

/// `byte[] call(byte[] cmd)`: the engine's input (spec/15 §3.2). Stub: no engine yet, no answer.
extern "C" fn call(_jni: JniEnv, _class: JObject, _input: JObject) -> JObject {
    core::ptr::null_mut()
}

/// `byte[] next(long timeoutMs)`: effects, the screen model and platform I/O requests. Stub: none.
extern "C" fn next(_jni: JniEnv, _class: JObject, _timeout_ms: i64) -> JObject {
    core::ptr::null_mut()
}

/// `void ioComplete(long id, int status, byte[] body)`: a platform I/O result. Stub: no request was
/// ever issued, so every id is unknown and dropped (the body is not read).
extern "C" fn io_complete(_jni: JniEnv, _class: JObject, _id: i64, _status: i32, _body: JObject) {}

/// `void secretKey(int field, int codeUnit)`: one app-keyboard key. Stub: no secret window is open.
extern "C" fn secret_key(_jni: JniEnv, _class: JObject, _field: i32, _code_unit: i32) {}

/// `int secretFill(long handle, char[] out)`: a secret display fill. Stub: no handle is valid, so 0
/// and nothing written (spec/15 §3.2).
extern "C" fn secret_fill(_jni: JniEnv, _class: JObject, _handle: i64, _out: JObject) -> i32 {
    0
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
        Ok(()) => JNI_VERSION_1_6,
        Err(()) => JNI_ERR,
    }
}
