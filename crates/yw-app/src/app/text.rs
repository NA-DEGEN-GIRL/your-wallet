//! Fixed texts of the app shell (`App`: notices, secret-window helpers, settings actions;
//! spec/04 §2, §4, spec/14).

yw_core::texts! {
    /// T-CLIP-NOT-CLEARED (spec/04 §4.8): the main-window banner while a secret copy could not
    /// be cleared.
    T_CLIP_NOT_CLEARED = "복사한 복구 단어·개인키를 클립보드에서 지우지 못했습니다(다른 프로그램이 클립보드를 쓰고 있습니다). 아직 클립보드에 남아 있을 수 있으니 다른 텍스트를 복사해 덮어쓰세요."
        / "The copied recovery words or private key could not be cleared from the clipboard (another program is using it). They may still be on the clipboard, so copy some other text over them.";
    /// The banner after a clear that succeeded only on a retry.
    T_CLIP_CLEARED_LATE = "클립보드에 남아 있던 복구 단어·개인키를 지웠습니다."
        / "The recovery words or private key left on the clipboard were cleared.";
    /// The notice after a password change that completed.
    PASSWORD_CHANGED = "비밀번호를 바꾸고 지갑의 암호화 키도 새로 만들었습니다. 이제부터 더하거나 고치는 내용은 바꾸기 전에 만든 지갑 파일 사본(백업한 vault.ywv, 격리된 손상 파일)과 예전 비밀번호로 열 수 없습니다. 그 사본 자체는 예전 비밀번호로 계속 열리고 그 안에 이미 있던 복구 단어·개인키가 드러납니다. 예전 비밀번호가 약했다면 그 사본은 나중에 오프라인으로 풀릴 수 있습니다 — 예전 비밀번호와 사본이 함께 샜을 수 있다면 사본을 지우고 자산을 새로 만든 별도 지갑으로 옮기세요."
        / "The password was changed and the wallet's encryption key was renewed. From now on, what you add or change cannot be opened with wallet file copies made before the change (a backed-up vault.ywv, quarantined damaged files) and the old password. Those copies themselves still open with the old password and reveal the recovery words and private keys they already hold. If the old password was weak, such a copy may be cracked offline later — if the old password and a copy may have leaked together, delete the copy and move your assets to a new, separate wallet.";
    /// The notice after a password change whose sidecars are not re-sealed yet.
    PASSWORD_CHANGED_PREV = "비밀번호를 바꿨습니다. 지금부터는 새 비밀번호로 엽니다. 다만 일부 파일(이전 복사본 vault.ywv.prev, meta.ywm, journal.ywj)을 새 암호화 키로 아직 다시 쓰지 못했습니다. 그 파일들에는 바꾸기 전 내용만 있고, 다음 잠금 해제나 저장 때 마저 바꿉니다. 그때까지 vault.ywv.prev는 예전 비밀번호로 열릴 수 있습니다. 이미 만들어 둔 지갑 파일 사본은 예전 비밀번호로 계속 열리고(예전 비밀번호가 약했다면 나중에 오프라인으로 풀릴 수 있습니다), 예전 비밀번호와 사본이 함께 샜을 수 있다면 자산을 새로 만든 별도 지갑으로 옮기세요."
        / "The password was changed. From now on the wallet opens with the new password. However, some files (the previous copy vault.ywv.prev, meta.ywm, journal.ywj) could not be rewritten with the new encryption key yet. They hold only the content from before the change and are finished at the next unlock or save. Until then, vault.ywv.prev may open with the old password. Wallet file copies made earlier still open with the old password (if it was weak, they may be cracked offline later); if the old password and a copy may have leaked together, move your assets to a new, separate wallet.";
    /// The notice after a password change that could not be confirmed.
    PASSWORD_UNCONFIRMED = "비밀번호 변경이 저장됐는지 확인하지 못해 지갑을 잠갔습니다. 새 비밀번호로 열어 보고, 열리지 않으면 예전 비밀번호로 여세요. 새 비밀번호로 열리면 변경이 적용된 것이고 남은 단계는 그 잠금 해제가 마칩니다."
        / "Whether the password change was saved could not be confirmed, so the wallet was locked. Try the new password; if it does not open, use the old one. If the new password opens it, the change took effect and that unlock finishes the remaining steps.";
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
    /// Secret-window flow name.
    FLOW_CREATE = "새 지갑 만들기" / "Create a new wallet";
    /// Secret-window flow name.
    FLOW_IMPORT = "기존 지갑 가져오기" / "Import an existing wallet";
    /// Secret-window flow name.
    FLOW_KEY_START = "개인키로 시작하기" / "Start with a private key";
    /// Secret-window flow name.
    FLOW_YK_WALLET = "YubiKey 지갑 만들기" / "Create a YubiKey wallet";
    /// W08 countdown note: the words can be seen again.
    TIMEOUT_BACKUP = "(닫혀도 “복구 단어 보고 백업 확인”으로 다시 볼 수 있습니다)"
        / "(after it closes, “View recovery words and check backup” shows them again)";
    /// W08 countdown note: the words are wiped.
    TIMEOUT_YK_WORDS = "(닫히면 이 단어는 지워집니다)" / "(when it closes, these words are erased)";
    /// W08 countdown note: settings shows them again.
    TIMEOUT_MNEMONICS = "(설정 → 복구 단어에서 다시 볼 수 있습니다)" / "(Settings → Recovery words shows them again)";
    /// The idle wipe of an unfinished flow.
    IDLE_WIPED = "오래 입력이 없어 입력하던 비밀번호·복구 단어·개인키를 지웠습니다. 처음부터 다시 진행하세요."
        / "Nothing was typed for a long time, so the password, recovery words and private key being entered were erased. Start again from the beginning.";
    /// Which passphrase is asked for: {0} count, {1} position.
    PASSPHRASE_FOR(2) = "복구 단어 {0}개 중 {1}번째의 passphrase를 입력하세요."
        / "Enter the passphrase of recovery phrase {1} of {0}.";
    /// Processing screen.
    LOADING = "불러오는 중…" / "Loading…";
    /// `.prev` recovery: where the damaged file went, {0} its name.
    RECOVERED_KEPT(1) = " 열리지 않던 지갑 파일은 데이터 폴더에 {0} 이름으로 옮겨 두었습니다. 직접 되돌리는 방법은 복구 안내(recovery-guide)를 보세요."
        / " The wallet file that would not open was moved in the data folder to the name {0}. To undo this yourself, see the recovery guide (recovery-guide).";
    /// `.prev` recovery after a damaged or missing file: {0} the note above or empty.
    RECOVERED_CHECK(1) = "이전 사본(.prev)으로 복구했습니다. 마지막 변경(예: 가져온 개인키)이 빠졌을 수 있으니 확인하세요.{0}"
        / "Restored from the previous copy (.prev). The last change (for example an imported private key) may be missing, so check.{0}";
    /// `.prev` recovery: {0} the note above.
    RECOVERED(1) = "이전 사본(.prev)으로 복구했습니다.{0}" / "Restored from the previous copy (.prev).{0}";
    /// The wallet opened (the recovery found the file fine).
    OPENED = "지갑을 열었습니다." / "The wallet was opened.";
    /// `.prev` recovery without a copy.
    RECOVERY_NO_PREV = "이전 사본(.prev)이 없어 복구할 수 없습니다. 복구 단어로 지갑을 다시 가져오세요. 데이터 폴더의 파일은 그대로 두었습니다."
        / "There is no previous copy (.prev), so nothing can be restored. Import the wallet again with the recovery words. The files in the data folder were left as they are.";
    /// `.prev` recovery with a damaged copy.
    RECOVERY_PREV_DAMAGED = "이전 사본(.prev)도 손상되어 복구할 수 없습니다. 복구 단어로 지갑을 다시 가져오세요. 데이터 폴더의 파일은 그대로 두었습니다."
        / "The previous copy (.prev) is damaged too, so nothing can be restored. Import the wallet again with the recovery words. The files in the data folder were left as they are.";
    /// A secret window that timed out.
    TIMED_OUT = "시간이 지나 창을 닫았습니다." / "The window was closed because time ran out.";
    /// Copy in a secret window while copying is off.
    COPY_OFF = "복사가 꺼져 있습니다. 설정에서 바꿀 수 있습니다." / "Copying is off. You can change this in settings.";
    /// Copy in a secret window.
    COPIED_SECRET = "클립보드에 복사했습니다. 30초 뒤 지웁니다." / "Copied to the clipboard. It is cleared in 30 seconds.";
    /// Processing screen.
    CREATING = "지갑을 만드는 중입니다. 몇 초 걸립니다." / "Creating the wallet. This takes a few seconds.";
    /// Processing screen.
    CHECKING = "확인 중…" / "Checking…";
    /// Processing screen.
    IMPORTING = "지갑을 가져오는 중입니다. 몇 초 걸립니다." / "Importing the wallet. This takes a few seconds.";
    /// Template credentials saved.
    TPL_SAVED = "템플릿 자격 정보를 저장했습니다." / "The template credentials were saved.";
    /// Template credentials saved without addresses.
    TPL_SAVED_NO_ADDRESS = " RPC 주소는 아직 없습니다 — “저장하고 RPC 주소 만들기”를 누르세요."
        / " There are no RPC addresses yet — press “Save and create RPC addresses”.";
    /// The account row source of an imported EVM key.
    IMPORTED_PRIVATE_KEY = "가져온 개인키" / "Imported private key";
    /// Auto-lock saved: {0} minutes.
    AUTO_LOCK_SAVED(1) = "자동 잠금을 {0}분으로 저장했습니다." / "Auto-lock was set to {0} minutes.";
    /// Auto-lock out of range.
    AUTO_LOCK_RANGE = "자동 잠금은 1–60분입니다." / "Auto-lock must be 1–60 minutes.";
    /// The E-KEY-002 item name of the Alchemy key.
    ALCHEMY_KEY = "알케미 키" / "Alchemy key";
    /// Kept entries pruned: {0} count.
    PRUNED(1) = "보관 항목 {0}개를 지웠습니다." / "{0} kept entries were deleted.";
    /// `저장하고 RPC 주소 만들기` with nothing typed (Alchemy).
    ENTER_ALCHEMY = "위 칸에 알케미 API 키를 넣으세요." / "Enter the Alchemy API key in the field above.";
    /// `저장하고 RPC 주소 만들기` with nothing typed (`QuickNode`).
    ENTER_QUICKNODE = "위 칸에 엔드포인트 이름과 토큰(또는 주소 전체)을 넣으세요."
        / "Enter the endpoint name and token (or the whole address) in the fields above.";
    /// T-RPC-GENERATED without new addresses.
    GENERATED_NONE = "새로 만든 RPC 주소가 없습니다. 이미 주소가 있는 네트워크는 '기존 주소 덮어쓰기'를 켰을 때만 바꿉니다."
        / "No new RPC addresses were created. Networks that already have an address change only with 'Overwrite existing addresses' on.";
    /// T-RPC-GENERATED: {0} count.
    GENERATED(1) = "RPC 주소 {0}개를 만들었습니다. 연결을 확인하는 중입니다 — 결과는 아래 각 행에 나옵니다."
        / "{0} RPC addresses were created. Their connections are being checked — the results appear on each row below.";
    /// T-RPC-GENERATED: {0} count, {1} the networks without a template entry.
    GENERATED_SKIPPED(2) = " 템플릿 항목이 없는 {0}개는 직접 입력하세요: {1}"
        / " Enter the {0} networks without a template entry yourself: {1}";
    /// An RPC test on its way.
    TESTING = "테스트 중…" / "Testing…";
    /// S08 `연결하기` with an empty field.
    PASTE_ADDRESS = "주소를 붙여넣으세요." / "Paste the address.";
    /// `개인키 보기` on a `YubiKey` account.
    YK_KEY_STAYS = "YubiKey 계정의 개인키는 YubiKey 밖으로 나오지 않습니다. 백업은 등록할 때 쓴 복구 단어입니다."
        / "The private key of a YubiKey account never leaves the YubiKey. Its backup is the recovery words used at enrolment.";
}
