//! Fixed texts of the Windows shell (`App`: the secret clipboard's notices, the paste notices,
//! the copy band; spec/04 §2, §4, spec/14). 2026-11-23 (spec/15 §11.4 S4d E1): the wallet's texts
//! of this catalogue moved to `yw_engine::wallet::text` (wording unchanged); before, one catalogue
//! of `app.rs`. 2026-11-24 (spec/15 §11.4 S5-5, S5 plan critic C7): the settings note on old
//! copies `T_PASSWORD_OLD_COPIES` moved to the screens' catalogue
//! `yw_engine::screen::build::core::text` (wording unchanged), with the security section's builder.

yw_core::texts! {
    /// The banner after a clear that succeeded only on a retry.
    T_CLIP_CLEARED_LATE = "클립보드에 남아 있던 복구 단어·개인키를 지웠습니다."
        / "The recovery words or private key left on the clipboard were cleared.";
    /// T-PASTE-CLEARED (spec/04 §4.7-4).
    PASTE_CLEARED = "붙여넣은 뒤 클립보드를 비웠습니다. Windows 클립보드 기록(Win+V)을 쓴다면 그 항목도 지우세요."
        / "The clipboard was emptied after pasting. If you use the Windows clipboard history (Win+V), delete that entry too.";
    /// T-PASTE-EDGE-SPACE (spec/04 §4.7-3): a pasted password/passphrase starts or ends with a
    /// space.
    PASTE_EDGE_SPACE = "앞/뒤 공백이 포함되어 있습니다. 공백도 그대로 비밀번호·passphrase의 일부가 됩니다."
        / "It starts or ends with a space. Spaces become part of the password or passphrase as they are.";
    /// Copy in a secret window while copying is off.
    COPY_OFF = "복사가 꺼져 있습니다. 설정에서 바꿀 수 있습니다." / "Copying is off. You can change this in settings.";
    /// Copy in a secret window.
    COPIED_SECRET = "클립보드에 복사했습니다. 30초 뒤 지웁니다." / "Copied to the clipboard. It is cleared in 30 seconds.";
}
