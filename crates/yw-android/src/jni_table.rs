//! The hand-declared JNI tables (spec/15 §3.2): the `JNIEnv`/`JavaVM` function-table indices the
//! Android shell calls, and the five native methods `JNI_OnLoad` registers.
//!
//! The compiler cannot check an index into the C function table, so the values are the ones
//! counted from the NDK r30 `jni.h` (`JNINativeInterface`, 233 entries from `reserved0` = 0) and
//! checked under `CheckJNI` on the test device (API 29) and the emulator (API 35) in P0-1 (spec/15
//! §3.2, §16 P0-1, spec/09 §2.6). They are pinned by the unit test below; a new entry is added only
//! with a `CheckJNI` run that calls it. Platform-neutral (no `unsafe`), so the gate's Windows build
//! tests it too.
#![forbid(unsafe_code)]

use core::ffi::CStr;

/// `JNI_VERSION_1_6`, what `JNI_OnLoad` returns and asks `GetEnv` for.
pub const JNI_VERSION_1_6: i32 = 0x0001_0006;
/// `JNI_OK`.
pub const JNI_OK: i32 = 0;
/// `JNI_ERR`: `JNI_OnLoad` returns it to refuse the load (the Java `System.loadLibrary` throws).
pub const JNI_ERR: i32 = -1;

/// `JNINativeInterface` (the `JNIEnv` table) indices, NDK r30 `jni.h`.
pub mod env {
    /// Entries in the table (`reserved0` … `GetObjectRefType`).
    pub const TABLE_LEN: usize = 233;
    /// `jint GetVersion(JNIEnv*)`.
    pub const GET_VERSION: usize = 4;
    /// `jclass FindClass(JNIEnv*, const char*)`.
    pub const FIND_CLASS: usize = 6;
    /// `void ExceptionClear(JNIEnv*)`.
    pub const EXCEPTION_CLEAR: usize = 17;
    /// `void DeleteLocalRef(JNIEnv*, jobject)`.
    pub const DELETE_LOCAL_REF: usize = 23;
    /// `jsize GetArrayLength(JNIEnv*, jarray)`.
    pub const GET_ARRAY_LENGTH: usize = 171;
    /// `jbyteArray NewByteArray(JNIEnv*, jsize)`.
    pub const NEW_BYTE_ARRAY: usize = 176;
    /// `void GetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, jbyte*)`.
    pub const GET_BYTE_ARRAY_REGION: usize = 200;
    /// `void SetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, const jbyte*)`.
    pub const SET_BYTE_ARRAY_REGION: usize = 208;
    /// `void SetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, const jchar*)`.
    pub const SET_CHAR_ARRAY_REGION: usize = 209;
    /// `jint RegisterNatives(JNIEnv*, jclass, const JNINativeMethod*, jint)`.
    pub const REGISTER_NATIVES: usize = 215;
    /// `jboolean ExceptionCheck(JNIEnv*)`.
    pub const EXCEPTION_CHECK: usize = 228;
}

/// `JNIInvokeInterface` (the `JavaVM` table) indices, NDK r30 `jni.h`.
pub mod vm {
    /// Entries in the table (`reserved0` … `AttachCurrentThreadAsDaemon`).
    pub const TABLE_LEN: usize = 8;
    /// `jint GetEnv(JavaVM*, void**, jint)`.
    pub const GET_ENV: usize = 6;
}

// Every index is inside its table (the `table_fn!` reads of `jni.rs` rely on it), at compile time.
const _: () = {
    let indices = [
        env::GET_VERSION,
        env::FIND_CLASS,
        env::EXCEPTION_CLEAR,
        env::DELETE_LOCAL_REF,
        env::GET_ARRAY_LENGTH,
        env::NEW_BYTE_ARRAY,
        env::GET_BYTE_ARRAY_REGION,
        env::SET_BYTE_ARRAY_REGION,
        env::SET_CHAR_ARRAY_REGION,
        env::REGISTER_NATIVES,
        env::EXCEPTION_CHECK,
    ];
    let mut at = 0;
    while at < indices.len() {
        assert!(indices[at] < env::TABLE_LEN);
        at += 1;
    }
    assert!(vm::GET_ENV < vm::TABLE_LEN);
};

/// The Java class that declares the native methods, in JNI form (2026-11-24 A2-1, spec/15 §3.2):
/// `dev.yw.app.Native`. The app namespace is neutral on purpose: the package name of a sideloaded
/// app can leave the device (spec/15 §14.1, P0-1 F1-4).
pub const NATIVE_CLASS: &CStr = c"dev/yw/app/Native";

/// One method `JNI_OnLoad` registers: its Java name and JNI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Method {
    /// Java name.
    pub name: &'static CStr,
    /// JNI type signature.
    pub signature: &'static CStr,
}

/// The five methods of spec/15 §3.2, in registration order. No other method is registered and no
/// `Java_*` symbol is exported.
pub const METHODS: [Method; 5] = [
    Method {
        name: c"call",
        signature: c"([B)[B",
    },
    Method {
        name: c"next",
        signature: c"(J)[B",
    },
    Method {
        name: c"ioComplete",
        signature: c"(JI[B)V",
    },
    Method {
        name: c"secretKey",
        signature: c"(II)V",
    },
    Method {
        name: c"secretFill",
        signature: c"(J[C)I",
    },
];

#[cfg(test)]
mod tests {
    use super::{JNI_ERR, JNI_OK, JNI_VERSION_1_6, METHODS, NATIVE_CLASS, env, vm};

    /// The values P0-1 checked under `CheckJNI` (spec/15 §3.2); a change needs a new `CheckJNI` run.
    #[test]
    fn indices_are_the_checked_ones() {
        let env_indices = [
            env::GET_VERSION,
            env::FIND_CLASS,
            env::EXCEPTION_CLEAR,
            env::DELETE_LOCAL_REF,
            env::GET_ARRAY_LENGTH,
            env::NEW_BYTE_ARRAY,
            env::GET_BYTE_ARRAY_REGION,
            env::SET_BYTE_ARRAY_REGION,
            env::SET_CHAR_ARRAY_REGION,
            env::REGISTER_NATIVES,
            env::EXCEPTION_CHECK,
        ];
        assert_eq!(
            env_indices,
            [4, 6, 17, 23, 171, 176, 200, 208, 209, 215, 228]
        );
        assert!(env_indices.iter().all(|index| *index < env::TABLE_LEN));
        assert_eq!(env::TABLE_LEN, 233);
        assert_eq!(vm::GET_ENV, 6);
        assert_eq!(vm::TABLE_LEN, 8);
        assert_eq!(JNI_VERSION_1_6, 0x0001_0006);
        assert_eq!((JNI_OK, JNI_ERR), (0, -1));
    }

    #[test]
    fn the_five_methods_and_their_class() {
        let pairs: Vec<(&str, &str)> = METHODS
            .iter()
            .map(|method| {
                (
                    method.name.to_str().unwrap(),
                    method.signature.to_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            [
                ("call", "([B)[B"),
                ("next", "(J)[B"),
                ("ioComplete", "(JI[B)V"),
                ("secretKey", "(II)V"),
                ("secretFill", "(J[C)I"),
            ]
        );
        assert_eq!(NATIVE_CLASS.to_str().unwrap(), "dev/yw/app/Native");
    }
}
