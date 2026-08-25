# Generated artifact record

The three C/header files beside this record are generated artifacts. Do not
edit them manually.

- SDK: Windows SDK `10.0.26100.0`, x64 tools
- MIDL compiler banner: `8.01.0628`
- `midl.exe` SHA-256: `57ff0546270ea51e61f87a121f1cc1ea09d100c7ca6e0172a8b3e0b988ab778f`
- `midlc.exe` SHA-256: `b27b8ef9758a7d4b39c622b9fa78ee2f7f8c2601996f1daccbff48c810484915`
- C preprocessor: MSVC toolset `14.44.35207`, `cl.exe` `19.44.35220.0`
- `cl.exe` SHA-256: `f444d471f7926f50928945f16a53081adb276f599db1dfc3aa2cf4bcf20ece17`
- IDL SHA-256: `afebe677da4c26a3ca12a56226a9b368a169d7d3f537d62b9eacb5a3d3240074`
- ACF SHA-256: `6159cfe33142e89d14714efbb3801931368b5b549247283295031ae22e265e2b`

Canonical switches:

```text
/nologo /env x64 /Oicf /robust /protocol dce /char signed /W4
/client stub /server stub
/prefix client YwkasRpcClient_ /prefix server YwkasRpcServer_
```

SDK `10.0.26100.0` MIDL does not accept `/notimestamp`; it reports that switch
as unknown. MIDL `8.01.0628` instead emits the fixed
`Tue Jan 19 12:14:07 2038` timestamp sentinel by default. The verification
script generates into two independent temporary directories and requires the
outputs to be byte-identical to each other and to these checked-in files.

## Pinned MIDL declaration wart

With separate client/server prefixes, this MIDL version emits one unused
compatibility declaration named `YwkasRpc_v1_0_c_ifspec` in the generated
header. Neither generated C file defines it. It MUST remain an unmodified part
of the reproducible MIDL output, but handwritten code MUST NOT define,
reference, or expose it. The linked interface handles are exclusively
`YwkasRpcClient_YwkasRpc_v1_0_c_ifspec` and
`YwkasRpcServer_YwkasRpc_v1_0_s_ifspec` behind the narrow shim getters.

Run `scripts/verify-generated.ps1`. It only locates and hashes the pinned
tools, generates into a validated temporary directory, compares bytes and
symbols, and removes that temporary directory. It never rewrites this tree.
