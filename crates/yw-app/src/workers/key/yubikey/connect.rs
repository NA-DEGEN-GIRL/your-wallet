//! The key worker's part of "`YubiKey` 연결하기 (복구 단어 없이)" (spec/10 §7.6): "저장" scans the
//! confirmed card again (read-only), requires the record the user confirmed, and adds it to the
//! vault — or, from S01, creates the `YubiKey` wallet with the password held since W01.

use yw_core::error::VaultError;
use yw_core::vault::{RecordId, VaultStatus};
use yw_core::yubikey::connect::KeyUse;
use yw_core::yubikey::enrol::Enrolled;
use yw_core::yubikey::plan::CardSlot;
use yw_core::yubikey::record::HwKeyRecord;

use super::super::{KeyWorker, new_slot, now_unix, password};
use crate::events::YubiKeyJobError;
use crate::logging::{self, Field};

impl KeyWorker {
    /// `Connect`.
    pub(super) fn yk_connect(
        &mut self,
        serial: u32,
        choices: &[(CardSlot, KeyUse)],
        expected: &HwKeyRecord,
    ) -> Result<(RecordId, Enrolled), YubiKeyJobError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
        let fresh = vault.status() == VaultStatus::NoVault;
        let records = if fresh {
            Vec::new()
        } else {
            Self::hardware_records(vault).map_err(YubiKeyJobError::Vault)?
        };
        let enrolled = crate::yubikey::connect_card_serial(
            self.cards.as_mut(),
            serial,
            choices,
            expected,
            &records,
        )
        .map_err(YubiKeyJobError::Card)?;
        let id = if fresh {
            let held = self
                .connect_password
                .as_ref()
                .ok_or(YubiKeyJobError::Vault(VaultError::InvalidState))?;
            let password = password(held).map_err(YubiKeyJobError::Vault)?;
            let slot = new_slot().map_err(YubiKeyJobError::Vault)?;
            let lang = self.lang;
            let vault = self.vault().map_err(YubiKeyJobError::Vault)?;
            let id = vault
                .create_with_hardware(&password, enrolled.record.clone(), slot, now_unix())
                .map_err(YubiKeyJobError::Vault)?;
            super::write_yubikey_meta(vault, lang).map_err(YubiKeyJobError::Vault)?;
            // The wallet exists: the password is not needed again.
            self.connect_password = None;
            logging::info("key", "yubikey.wallet_connected", &[]);
            id
        } else {
            self.vault()
                .map_err(YubiKeyJobError::Vault)?
                .add_hardware_key(enrolled.record.clone(), now_unix())
                .map_err(YubiKeyJobError::Vault)?
        };
        logging::info(
            "key",
            "yubikey.connected",
            &[(
                "slots",
                Field::Num(u64::try_from(enrolled.record.slots.len()).unwrap_or(0)),
            )],
        );
        Ok((id, enrolled))
    }
}
