//! Fixed texts of the Windows shell (`App`: the secret clipboard's notices, the paste notices,
//! the settings note on old copies, the copy band; spec/04 §2, §4, spec/14). 2026-11-23 (spec/15
//! §11.4 S4d E1): the wallet's texts of this catalogue moved to `yw_engine::wallet::text` (wording
//! unchanged); before, one catalogue of `app.rs`.

yw_core::texts! {
    /// The banner after a clear that succeeded only on a retry.
    T_CLIP_CLEARED_LATE = "클립보드에 남아 있던 복구 단어·개인키를 지웠습니다."
        / "The recovery words or private key left on the clipboard were cleared.";
    /// The settings note on what a password change does and does not do (review L1).
    T_PASSWORD_OLD_COPIES = "비밀번호를 바꾸면 지갑의 암호화 키도 새로 만듭니다. 그래서 바꾼 뒤에 더하거나 고친 내용(새 복구 단어·가져온 키, 계정 이름·주소록·기록)은 예전 사본과 예전 비밀번호로 열 수 없습니다. 2026-11-13 이전 버전에서 바꾼 비밀번호는 키를 그대로 두었으니, 그때 바꿨다면 지금 한 번 더 바꾸세요. 하지만 바꾸기 전에 만든 지갑 파일 사본(백업해 둔 vault.ywv, vault.ywv.corrupt-… 등)은 예전 비밀번호로 계속 열리고, 그 안에 이미 있던 복구 단어·개인키는 그대로 드러납니다. 예전 비밀번호가 약했다면 그런 사본은 나중에라도 오프라인으로 풀릴 수 있습니다. 예전 비밀번호와 사본이 함께 샜을 수 있다면 사본을 지우고, 새 복구 단어로 따로 만든 새 지갑으로 자산을 옮기세요."
        / "Changing the password also renews the wallet's encryption key. So what you add or change afterwards (new recovery words, imported keys, account names, address book, records) cannot be opened with old copies and the old password. Versions before 2026-11-13 kept the key on a password change, so if you changed it then, change it once more now. Wallet file copies made before the change (a backed-up vault.ywv, vault.ywv.corrupt-… etc.) still open with the old password and reveal the recovery words and private keys they already hold. If the old password was weak, such copies may be cracked offline even later. If the old password and a copy may have leaked together, delete the copy and move your assets to a new wallet created separately with new recovery words.";
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
