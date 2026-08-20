use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::{
    AnchorError, AnchorValue, CiphertextFormat, DurableBackend, EncryptedPayload, FaultControl,
    FaultPoint, FileRole, RecordClass, RollbackAnchor, StorageAuthenticationKey, StoreConfig,
    StoreCore, StoreError,
};

#[cfg(windows)]
fn windows_store_for_test<A: RollbackAnchor>(
    config: StoreConfig,
    key: StorageAuthenticationKey,
    anchor: A,
) -> Result<StoreCore<super::sys::WindowsBackend, A>, StoreError> {
    let backend = super::sys::WindowsBackend::open(&config)?;
    Ok(StoreCore::new(backend, anchor, config, key))
}

const WIRE_CLASS_OFFSET: usize = 4 + 2 + 32;
const WIRE_FORMAT_OFFSET: usize = WIRE_CLASS_OFFSET + 2;

#[test]
fn recovery_never_downgrades_path_acl_or_io_proof_failures_to_corruption() {
    for error in [
        StoreError::UnsafePath,
        StoreError::InsecurePermissions,
        StoreError::UnprotectedDacl,
        StoreError::UnexpectedAccessControlEntry,
        StoreError::WrongStoragePrincipal,
        StoreError::DurabilityFailure,
        StoreError::BoundsExceeded,
    ] {
        assert_eq!(
            super::reject_nonrecoverable_read_error::<()>(&Err(error)),
            Err(error)
        );
    }
    assert_eq!(
        super::reject_nonrecoverable_read_error::<()>(&Err(StoreError::NotFound)),
        Ok(())
    );
    assert_eq!(
        super::reject_nonrecoverable_read_error::<()>(&Err(StoreError::IntegrityFailure)),
        Ok(())
    );
}

#[derive(Debug)]
struct FailingReadBackend {
    role: FileRole,
    error: StoreError,
}

impl DurableBackend for FailingReadBackend {
    fn read(&self, role: FileRole, _max_bytes: usize) -> Result<Option<Vec<u8>>, StoreError> {
        if role == self.role {
            Err(self.error)
        } else {
            Ok(None)
        }
    }

    fn atomic_write(
        &mut self,
        _role: FileRole,
        _bytes: &[u8],
        _fault: &mut dyn FaultControl,
    ) -> Result<(), StoreError> {
        Err(StoreError::DurabilityFailure)
    }
}

#[test]
fn recovery_propagates_every_path_acl_and_io_read_failure_from_each_file_role()
-> Result<(), StoreError> {
    let config = StoreConfig::new(
        std::path::PathBuf::from("test-root"),
        "read-proof-errors",
        RecordClass::NonceLedger,
        4096,
    )?;
    let errors = [
        StoreError::UnsafePath,
        StoreError::InsecurePermissions,
        StoreError::UnprotectedDacl,
        StoreError::UnexpectedAccessControlEntry,
        StoreError::WrongStoragePrincipal,
        StoreError::DurabilityFailure,
        StoreError::BoundsExceeded,
        StoreError::UnsupportedPlatform,
    ];
    for role in [FileRole::Slot(0), FileRole::Slot(1), FileRole::Manifest] {
        for error in errors {
            let mut core = StoreCore::new(
                FailingReadBackend { role, error },
                MemoryAnchor::default(),
                config.clone(),
                StorageAuthenticationKey::new([0x42; 32])?,
            );
            assert_eq!(core.load(), Err(error));
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct VanishingCorruptManifestBackend {
    manifest_reads: Rc<Cell<u32>>,
}

impl DurableBackend for VanishingCorruptManifestBackend {
    fn read(&self, role: FileRole, _max_bytes: usize) -> Result<Option<Vec<u8>>, StoreError> {
        match role {
            FileRole::Slot(_) => Ok(None),
            FileRole::Manifest => {
                let read = self.manifest_reads.get();
                self.manifest_reads.set(read.saturating_add(1));
                if read == 0 {
                    Ok(Some(vec![0_u8; 1]))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn atomic_write(
        &mut self,
        _role: FileRole,
        _bytes: &[u8],
        _fault: &mut dyn FaultControl,
    ) -> Result<(), StoreError> {
        Err(StoreError::DurabilityFailure)
    }
}

#[test]
fn corrupt_first_manifest_read_cannot_be_reread_as_an_empty_store() -> Result<(), StoreError> {
    let config = StoreConfig::new(
        std::path::PathBuf::from("test-root"),
        "manifest-read-once",
        RecordClass::NonceLedger,
        4096,
    )?;
    let backend = VanishingCorruptManifestBackend::default();
    let read_counter = backend.manifest_reads.clone();
    let mut core = StoreCore::new(
        backend,
        MemoryAnchor::default(),
        config,
        StorageAuthenticationKey::new([0x41; 32])?,
    );

    assert_eq!(core.load(), Err(StoreError::IntegrityFailure));
    assert_eq!(read_counter.get(), 1);
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct MemoryBackend {
    slots: [Option<Vec<u8>>; 2],
    manifest: Option<Vec<u8>>,
}

impl DurableBackend for MemoryBackend {
    fn read(&self, role: FileRole, max_bytes: usize) -> Result<Option<Vec<u8>>, StoreError> {
        let bytes = match role {
            FileRole::Slot(slot) => self.slots[usize::from(slot)].clone(),
            FileRole::Manifest => self.manifest.clone(),
        };
        if bytes.as_ref().is_some_and(|value| value.len() > max_bytes) {
            return Err(StoreError::BoundsExceeded);
        }
        Ok(bytes)
    }

    fn atomic_write(
        &mut self,
        role: FileRole,
        bytes: &[u8],
        fault: &mut dyn FaultControl,
    ) -> Result<(), StoreError> {
        let points = match role {
            FileRole::Slot(_) => [
                FaultPoint::SlotTempCreated,
                FaultPoint::SlotTempWritten,
                FaultPoint::SlotTempFlushed,
                FaultPoint::SlotReplaced,
                FaultPoint::SlotDirectoryFlushed,
            ],
            FileRole::Manifest => [
                FaultPoint::ManifestTempCreated,
                FaultPoint::ManifestTempWritten,
                FaultPoint::ManifestTempFlushed,
                FaultPoint::ManifestReplaced,
                FaultPoint::ManifestDirectoryFlushed,
            ],
        };
        fault.hit(points[0])?;
        fault.hit(points[1])?;
        fault.hit(points[2])?;
        match role {
            FileRole::Slot(slot) => self.slots[usize::from(slot)] = Some(bytes.to_vec()),
            FileRole::Manifest => self.manifest = Some(bytes.to_vec()),
        }
        fault.hit(points[3])?;
        fault.hit(points[4])?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct MemoryAnchor(Rc<RefCell<Option<AnchorValue>>>);

impl RollbackAnchor for MemoryAnchor {
    fn load(&self, _store_id: [u8; 32]) -> Result<Option<AnchorValue>, AnchorError> {
        Ok(*self.0.borrow())
    }

    fn compare_and_advance(
        &self,
        _store_id: [u8; 32],
        expected: Option<AnchorValue>,
        next: AnchorValue,
    ) -> Result<(), AnchorError> {
        let mut value = self.0.borrow_mut();
        if *value != expected {
            return Err(AnchorError::Conflict);
        }
        if let Some(current) = *value
            && (next.generation != current.generation.saturating_add(1)
                || next.generation <= current.generation)
        {
            return Err(AnchorError::Rollback);
        }
        if value.is_none() && next.generation != 1 {
            return Err(AnchorError::Rollback);
        }
        *value = Some(next);
        Ok(())
    }
}

#[derive(Debug)]
struct CrashAt(FaultPoint);

impl FaultControl for CrashAt {
    fn hit(&mut self, point: FaultPoint) -> Result<(), StoreError> {
        if self.0 == point {
            Err(StoreError::InjectedCrash)
        } else {
            Ok(())
        }
    }
}

fn store(
    backend: MemoryBackend,
    anchor: MemoryAnchor,
) -> Result<StoreCore<MemoryBackend, MemoryAnchor>, StoreError> {
    let config = StoreConfig::new(
        std::path::PathBuf::from(r"C:\wallet-test"),
        "nonce",
        RecordClass::NonceLedger,
        4096,
    )?;
    let key = StorageAuthenticationKey::new([0x5a; 32])?;
    Ok(StoreCore::new(backend, anchor, config, key))
}

fn store_for(
    backend: MemoryBackend,
    anchor: MemoryAnchor,
    namespace: &str,
    class: RecordClass,
    max_ciphertext_bytes: usize,
) -> Result<StoreCore<MemoryBackend, MemoryAnchor>, StoreError> {
    let config = StoreConfig::new(
        std::path::PathBuf::from(r"C:\wallet-test"),
        namespace,
        class,
        max_ciphertext_bytes,
    )?;
    let key = StorageAuthenticationKey::new([0x5a; 32])?;
    Ok(StoreCore::new(backend, anchor, config, key))
}

fn vault_blob(marker: u8) -> Vec<u8> {
    let mut bytes = vec![marker; super::VAULT_HEADER_BYTES + super::XCHACHA_TAG_BYTES];
    bytes[..super::VAULT_MAGIC.len()].copy_from_slice(super::VAULT_MAGIC);
    bytes
}

fn payload_for(class: RecordClass, marker: u8) -> Result<EncryptedPayload, StoreError> {
    match class {
        RecordClass::Vault => EncryptedPayload::vault_v1(vault_blob(marker)),
        RecordClass::NonceLedger
        | RecordClass::SignedCandidateJournal
        | RecordClass::LocalSettings => {
            EncryptedPayload::xchacha20poly1305_v1(class, [marker.max(1); 24], vec![marker; 32])
        }
    }
}

fn settings_encrypted(marker: u8) -> Result<EncryptedPayload, StoreError> {
    payload_for(RecordClass::LocalSettings, marker)
}

fn replace_record_mac(bytes: &mut [u8], key: &StorageAuthenticationKey) -> Result<(), StoreError> {
    let body_length = bytes
        .len()
        .checked_sub(super::MAC_BYTES)
        .ok_or(StoreError::IntegrityFailure)?;
    let tag = super::hmac_tag(key, super::RECORD_MAC_DOMAIN, &bytes[..body_length])?;
    bytes[body_length..].copy_from_slice(&tag);
    Ok(())
}

fn replace_manifest_mac(
    bytes: &mut [u8],
    key: &StorageAuthenticationKey,
) -> Result<(), StoreError> {
    let body_length = bytes
        .len()
        .checked_sub(super::MAC_BYTES)
        .ok_or(StoreError::IntegrityFailure)?;
    let tag = super::hmac_tag(key, super::MANIFEST_MAC_DOMAIN, &bytes[..body_length])?;
    bytes[body_length..].copy_from_slice(&tag);
    Ok(())
}

fn encrypted(marker: u8) -> Result<EncryptedPayload, StoreError> {
    let mut bytes = vec![marker; 64];
    bytes.extend_from_slice(&[marker ^ 0xff; 16]);
    EncryptedPayload::xchacha20poly1305_v1(RecordClass::NonceLedger, [marker.max(1); 24], bytes)
}

#[test]
fn local_settings_discriminant_is_stable_and_roundtrips() -> Result<(), StoreError> {
    assert_eq!(RecordClass::Vault as u8, 1);
    assert_eq!(RecordClass::NonceLedger as u8, 2);
    assert_eq!(RecordClass::SignedCandidateJournal as u8, 3);
    assert_eq!(RecordClass::LocalSettings as u8, 4);

    let anchor = MemoryAnchor::default();
    let mut core = store_for(
        MemoryBackend::default(),
        anchor,
        "local-settings",
        RecordClass::LocalSettings,
        4096,
    )?;
    let payload = settings_encrypted(0x34)?;
    let receipt = core.commit(None, &payload)?;
    assert_eq!(receipt.generation(), 1);

    let loaded = core.load()?;
    assert_eq!(loaded.generation(), 1);
    assert_eq!(loaded.payload().class(), RecordClass::LocalSettings);
    assert_eq!(
        loaded.payload().format(),
        CiphertextFormat::XChaCha20Poly1305V1
    );
    assert_eq!(loaded.payload(), &payload);
    Ok(())
}

#[test]
fn ciphertext_format_matrix_is_exact_for_every_record_class() -> Result<(), StoreError> {
    let classes = [
        RecordClass::Vault,
        RecordClass::NonceLedger,
        RecordClass::SignedCandidateJournal,
        RecordClass::LocalSettings,
    ];
    let formats = [
        CiphertextFormat::VaultV1,
        CiphertextFormat::XChaCha20Poly1305V1,
    ];

    for class in classes {
        for format in formats {
            let payload = match format {
                CiphertextFormat::VaultV1 => EncryptedPayload {
                    class,
                    format,
                    nonce: [0; 24],
                    ciphertext: vault_blob(0x41),
                },
                CiphertextFormat::XChaCha20Poly1305V1 => EncryptedPayload {
                    class,
                    format,
                    nonce: [0x42; 24],
                    ciphertext: vec![0x43; super::XCHACHA_TAG_BYTES],
                },
            };
            let allowed = matches!(
                (class, format),
                (RecordClass::Vault, CiphertextFormat::VaultV1)
                    | (
                        RecordClass::NonceLedger
                            | RecordClass::SignedCandidateJournal
                            | RecordClass::LocalSettings,
                        CiphertextFormat::XChaCha20Poly1305V1
                    )
            );
            assert_eq!(
                super::validate_payload(&payload),
                if allowed {
                    Ok(())
                } else {
                    Err(StoreError::InvalidCiphertextEnvelope)
                },
                "unexpected format decision for {class:?}/{format:?}"
            );
        }
    }

    let config = StoreConfig::new(
        std::path::PathBuf::from(r"C:\wallet-test"),
        "local-settings",
        RecordClass::LocalSettings,
        4096,
    )?;
    let key = StorageAuthenticationKey::new([0x5a; 32])?;
    let invalid_settings_vault = EncryptedPayload {
        class: RecordClass::LocalSettings,
        format: CiphertextFormat::VaultV1,
        nonce: [0; 24],
        ciphertext: vault_blob(0x44),
    };
    let encoded = super::encode_record(
        config.store_id(),
        0,
        1,
        0,
        [0; 32],
        &invalid_settings_vault,
        &key,
    )?;
    assert_eq!(
        super::decode_record(
            &encoded,
            config.store_id(),
            RecordClass::LocalSettings,
            0,
            4096,
            &key,
        ),
        Err(StoreError::InvalidCiphertextEnvelope)
    );
    Ok(())
}

#[test]
fn every_record_class_rejects_every_other_payload_class() -> Result<(), StoreError> {
    let classes = [
        RecordClass::Vault,
        RecordClass::NonceLedger,
        RecordClass::SignedCandidateJournal,
        RecordClass::LocalSettings,
    ];
    for expected_class in classes {
        for actual_class in classes {
            if expected_class == actual_class {
                continue;
            }
            let mut core = store_for(
                MemoryBackend::default(),
                MemoryAnchor::default(),
                "class-confusion",
                expected_class,
                4096,
            )?;
            assert_eq!(
                core.commit(None, &payload_for(actual_class, actual_class as u8)?),
                Err(StoreError::RecordClassMismatch),
                "{actual_class:?} payload was accepted by {expected_class:?} store"
            );
        }
    }
    Ok(())
}

#[test]
fn namespace_store_id_and_class_are_bound_on_decode() -> Result<(), StoreError> {
    let root = std::path::PathBuf::from(r"C:\wallet-test");
    let settings_a =
        StoreConfig::new(root.clone(), "settings-a", RecordClass::LocalSettings, 4096)?;
    let settings_b =
        StoreConfig::new(root.clone(), "settings-b", RecordClass::LocalSettings, 4096)?;
    let nonce_a = StoreConfig::new(root, "settings-a", RecordClass::NonceLedger, 4096)?;
    assert_ne!(settings_a.store_id(), settings_b.store_id());
    assert_ne!(settings_a.store_id(), nonce_a.store_id());

    let key = StorageAuthenticationKey::new([0x5a; 32])?;
    let record = super::encode_record(
        settings_a.store_id(),
        0,
        1,
        0,
        [0; 32],
        &settings_encrypted(0x51)?,
        &key,
    )?;
    assert_eq!(
        super::decode_record(
            &record,
            settings_b.store_id(),
            RecordClass::LocalSettings,
            0,
            4096,
            &key,
        ),
        Err(StoreError::IntegrityFailure)
    );
    assert_eq!(
        super::decode_record(
            &record,
            settings_a.store_id(),
            RecordClass::NonceLedger,
            0,
            4096,
            &key,
        ),
        Err(StoreError::IntegrityFailure)
    );

    let record_digest = super::sha256(&record);
    let manifest = super::encode_manifest(
        super::ManifestDescriptor {
            store_id: settings_a.store_id(),
            class: RecordClass::LocalSettings,
            active_slot: 0,
            generation: 1,
            previous_generation: 0,
            record_digest,
            previous_digest: [0; 32],
        },
        &key,
    )?;
    assert_eq!(
        super::decode_manifest(
            &manifest,
            settings_b.store_id(),
            RecordClass::LocalSettings,
            &key,
        ),
        Err(StoreError::IntegrityFailure)
    );
    assert_eq!(
        super::decode_manifest(
            &manifest,
            settings_a.store_id(),
            RecordClass::SignedCandidateJournal,
            &key,
        ),
        Err(StoreError::IntegrityFailure)
    );
    Ok(())
}

#[test]
fn local_settings_tamper_is_rejected_before_decode() -> Result<(), StoreError> {
    let config = StoreConfig::new(
        std::path::PathBuf::from(r"C:\wallet-test"),
        "local-settings",
        RecordClass::LocalSettings,
        4096,
    )?;
    let key = StorageAuthenticationKey::new([0x5a; 32])?;
    let encoded = super::encode_record(
        config.store_id(),
        0,
        1,
        0,
        [0; 32],
        &settings_encrypted(0x61)?,
        &key,
    )?;
    let last = encoded
        .len()
        .checked_sub(1)
        .ok_or(StoreError::IntegrityFailure)?;
    for offset in [
        0,
        WIRE_CLASS_OFFSET,
        WIRE_FORMAT_OFFSET,
        super::RECORD_FIXED_BYTES,
        last,
    ] {
        let mut tampered = encoded.clone();
        tampered[offset] ^= 0x80;
        assert_eq!(
            super::decode_record(
                &tampered,
                config.store_id(),
                RecordClass::LocalSettings,
                0,
                4096,
                &key,
            ),
            Err(StoreError::IntegrityFailure),
            "tamper at byte {offset} was accepted"
        );
    }
    Ok(())
}

#[test]
fn unknown_old_class_and_format_bytes_fail_closed_with_valid_macs() -> Result<(), StoreError> {
    let config = StoreConfig::new(
        std::path::PathBuf::from(r"C:\wallet-test"),
        "local-settings",
        RecordClass::LocalSettings,
        4096,
    )?;
    let key = StorageAuthenticationKey::new([0x5a; 32])?;
    let record = super::encode_record(
        config.store_id(),
        0,
        1,
        0,
        [0; 32],
        &settings_encrypted(0x71)?,
        &key,
    )?;
    let manifest = super::encode_manifest(
        super::ManifestDescriptor {
            store_id: config.store_id(),
            class: RecordClass::LocalSettings,
            active_slot: 0,
            generation: 1,
            previous_generation: 0,
            record_digest: super::sha256(&record),
            previous_digest: [0; 32],
        },
        &key,
    )?;

    for unknown_class in [0_u8, 5, u8::MAX] {
        let mut unknown_record = record.clone();
        unknown_record[WIRE_CLASS_OFFSET] = unknown_class;
        replace_record_mac(&mut unknown_record, &key)?;
        assert_eq!(
            super::decode_record(
                &unknown_record,
                config.store_id(),
                RecordClass::LocalSettings,
                0,
                4096,
                &key,
            ),
            Err(StoreError::IntegrityFailure)
        );

        let mut unknown_manifest = manifest.clone();
        unknown_manifest[WIRE_CLASS_OFFSET] = unknown_class;
        replace_manifest_mac(&mut unknown_manifest, &key)?;
        assert_eq!(
            super::decode_manifest(
                &unknown_manifest,
                config.store_id(),
                RecordClass::LocalSettings,
                &key,
            ),
            Err(StoreError::IntegrityFailure)
        );
    }

    for unknown_format in [0_u8, 3, u8::MAX] {
        let mut unknown_record = record.clone();
        unknown_record[WIRE_FORMAT_OFFSET] = unknown_format;
        replace_record_mac(&mut unknown_record, &key)?;
        assert_eq!(
            super::decode_record(
                &unknown_record,
                config.store_id(),
                RecordClass::LocalSettings,
                0,
                4096,
                &key,
            ),
            Err(StoreError::IntegrityFailure)
        );
    }
    Ok(())
}

#[test]
fn local_settings_keep_ciphertext_bounds_and_rollback_anchor() -> Result<(), StoreError> {
    assert_eq!(
        StoreConfig::new(
            std::path::PathBuf::from(r"C:\wallet-test"),
            "local-settings",
            RecordClass::LocalSettings,
            super::XCHACHA_TAG_BYTES - 1,
        ),
        Err(StoreError::InvalidConfiguration)
    );

    let anchor = MemoryAnchor::default();
    let mut core = store_for(
        MemoryBackend::default(),
        anchor.clone(),
        "local-settings",
        RecordClass::LocalSettings,
        super::XCHACHA_TAG_BYTES,
    )?;
    let smallest = EncryptedPayload::xchacha20poly1305_v1(
        RecordClass::LocalSettings,
        [0x72; 24],
        vec![0x73; super::XCHACHA_TAG_BYTES],
    )?;
    core.commit(None, &smallest)?;
    let generation_one = core.backend.clone();

    let oversized = EncryptedPayload::xchacha20poly1305_v1(
        RecordClass::LocalSettings,
        [0x74; 24],
        vec![0x75; super::XCHACHA_TAG_BYTES + 1],
    )?;
    assert_eq!(
        core.commit(Some(1), &oversized),
        Err(StoreError::BoundsExceeded)
    );

    let second = EncryptedPayload::xchacha20poly1305_v1(
        RecordClass::LocalSettings,
        [0x76; 24],
        vec![0x77; super::XCHACHA_TAG_BYTES],
    )?;
    core.commit(Some(1), &second)?;
    let mut rolled_back = store_for(
        generation_one,
        anchor,
        "local-settings",
        RecordClass::LocalSettings,
        super::XCHACHA_TAG_BYTES,
    )?;
    assert_eq!(rolled_back.load(), Err(StoreError::RollbackDetected));
    Ok(())
}

#[test]
fn commits_and_loads_two_authenticated_generations() -> Result<(), StoreError> {
    let anchor = MemoryAnchor::default();
    let mut core = store(MemoryBackend::default(), anchor)?;
    let first = core.commit(None, &encrypted(1)?)?;
    assert_eq!(first.generation(), 1);
    let second = core.commit(Some(1), &encrypted(2)?)?;
    assert_eq!(second.generation(), 2);
    let loaded = core.load()?;
    assert_eq!(loaded.generation(), 2);
    assert_eq!(loaded.payload(), &encrypted(2)?);
    Ok(())
}

#[test]
fn rejects_generation_conflicts_class_mismatch_and_plaintext_shape() -> Result<(), StoreError> {
    let anchor = MemoryAnchor::default();
    let mut core = store(MemoryBackend::default(), anchor)?;
    core.commit(None, &encrypted(1)?)?;
    assert_eq!(
        core.commit(None, &encrypted(2)?),
        Err(StoreError::GenerationConflict)
    );
    let wrong_class = EncryptedPayload::xchacha20poly1305_v1(
        RecordClass::SignedCandidateJournal,
        [3; 24],
        vec![4; 32],
    )?;
    assert_eq!(
        core.commit(Some(1), &wrong_class),
        Err(StoreError::RecordClassMismatch)
    );
    assert_eq!(
        EncryptedPayload::xchacha20poly1305_v1(
            RecordClass::SignedCandidateJournal,
            [0; 24],
            vec![4; 32]
        ),
        Err(StoreError::InvalidCiphertextEnvelope)
    );
    assert_eq!(
        EncryptedPayload::vault_v1(vec![0; 512]),
        Err(StoreError::InvalidCiphertextEnvelope)
    );
    Ok(())
}

#[test]
fn hmac_detects_slot_and_manifest_corruption_and_truncation() -> Result<(), StoreError> {
    let anchor = MemoryAnchor::default();
    let mut core = store(MemoryBackend::default(), anchor.clone())?;
    core.commit(None, &encrypted(7)?)?;

    let mut corrupted_slot = core.backend.clone();
    let slot = corrupted_slot.slots[0]
        .as_mut()
        .ok_or(StoreError::IntegrityFailure)?;
    let index = slot.len() / 2;
    slot[index] ^= 0x80;
    let mut corrupted = store(corrupted_slot, anchor.clone())?;
    assert_eq!(corrupted.load(), Err(StoreError::RollbackDetected));

    let mut truncated_manifest = core.backend.clone();
    truncated_manifest
        .manifest
        .as_mut()
        .ok_or(StoreError::IntegrityFailure)?
        .truncate(12);
    let mut recovered = store(truncated_manifest, anchor)?;
    assert_eq!(recovered.load()?.generation(), 1);
    assert_eq!(recovered.load()?.generation(), 1);
    Ok(())
}

#[test]
fn external_anchor_detects_complete_filesystem_rollback() -> Result<(), StoreError> {
    let anchor = MemoryAnchor::default();
    let mut core = store(MemoryBackend::default(), anchor.clone())?;
    core.commit(None, &encrypted(1)?)?;
    let generation_one = core.backend.clone();
    core.commit(Some(1), &encrypted(2)?)?;

    let mut rolled_back = store(generation_one, anchor)?;
    assert_eq!(rolled_back.load(), Err(StoreError::RollbackDetected));
    Ok(())
}

#[test]
fn every_commit_crash_stage_recovers_to_old_or_new_anchored_generation() -> Result<(), StoreError> {
    let points = [
        FaultPoint::SlotTempCreated,
        FaultPoint::SlotTempWritten,
        FaultPoint::SlotTempFlushed,
        FaultPoint::SlotReplaced,
        FaultPoint::SlotDirectoryFlushed,
        FaultPoint::ManifestTempCreated,
        FaultPoint::ManifestTempWritten,
        FaultPoint::ManifestTempFlushed,
        FaultPoint::ManifestReplaced,
        FaultPoint::ManifestDirectoryFlushed,
        FaultPoint::BeforeAnchorAdvance,
        FaultPoint::AfterAnchorAdvance,
    ];

    for point in points {
        let anchor = MemoryAnchor::default();
        let mut core = store(MemoryBackend::default(), anchor.clone())?;
        core.commit(None, &encrypted(1)?)?;
        let payload = encrypted(2)?;
        let result = core.commit_with_fault(Some(1), &payload, &mut CrashAt(point));
        assert_eq!(result, Err(StoreError::InjectedCrash));

        let backend = core.backend.clone();
        let mut restarted = store(backend, anchor)?;
        let loaded = restarted.load()?;
        assert!(matches!(loaded.generation(), 1 | 2));
        if loaded.generation() == 1 {
            assert_eq!(loaded.payload(), &encrypted(1)?);
        } else {
            assert_eq!(loaded.payload(), &encrypted(2)?);
        }
    }
    Ok(())
}

#[test]
fn post_manifest_pre_anchor_crash_finishes_exact_one_step_anchor_advance() -> Result<(), StoreError>
{
    let anchor = MemoryAnchor::default();
    let mut core = store(MemoryBackend::default(), anchor.clone())?;
    core.commit(None, &encrypted(1)?)?;
    assert_eq!(
        core.commit_with_fault(
            Some(1),
            &encrypted(9)?,
            &mut CrashAt(FaultPoint::BeforeAnchorAdvance)
        ),
        Err(StoreError::InjectedCrash)
    );
    let backend = core.backend.clone();
    let mut restarted = store(backend, anchor.clone())?;
    assert_eq!(restarted.load()?.generation(), 2);
    assert_eq!(
        anchor
            .load(restarted.store_id)?
            .map(AnchorValue::generation),
        Some(2)
    );
    Ok(())
}

#[test]
fn debug_output_redacts_keys_ciphertext_and_anchor_digests() -> Result<(), StoreError> {
    let key = StorageAuthenticationKey::new([8; 32])?;
    assert_eq!(format!("{key:?}"), "StorageAuthenticationKey([REDACTED])");
    let payload = encrypted(3)?;
    let output = format!("{payload:?}");
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("3, 3, 3"));

    let config = StoreConfig::new(
        std::path::PathBuf::from(r"C:\private-debug-marker\vault"),
        "private_namespace_marker",
        RecordClass::NonceLedger,
        4096,
    )?;
    let config_output = format!("{config:?}");
    assert!(config_output.contains("NonceLedger"));
    assert!(!config_output.contains("private-debug-marker"));
    assert!(!config_output.contains("private_namespace_marker"));

    let core = StoreCore::new(
        MemoryBackend::default(),
        MemoryAnchor::default(),
        config,
        StorageAuthenticationKey::new([0x5a; 32])?,
    );
    let core_output = format!("{core:?}");
    assert!(core_output.contains("[REDACTED]"));
    assert!(!core_output.contains("private-debug-marker"));
    assert!(!core_output.contains("MemoryBackend"));
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_backend_holds_exclusive_lock_and_reopens_committed_generation()
-> Result<(), Box<dyn std::error::Error>> {
    use core::fmt::Write as _;

    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| StoreError::DurabilityFailure)?;
    let mut suffix = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut suffix, "{byte:02x}").map_err(|_| StoreError::DurabilityFailure)?;
    }
    let root = std::env::temp_dir().join(format!("your-wallet-storage-test-{suffix}"));
    let config = StoreConfig::new(root.clone(), "native", RecordClass::NonceLedger, 4096)?;
    let anchor = MemoryAnchor::default();

    {
        let mut store = windows_store_for_test(
            config.clone(),
            StorageAuthenticationKey::new([0x6b; 32])?,
            anchor.clone(),
        )?;
        store.commit(None, &encrypted(4)?)?;
        assert_eq!(store.load()?.generation(), 1);
        store.commit(Some(1), &encrypted(5)?)?;
        assert_eq!(store.load()?.generation(), 2);
        assert_eq!(store.load()?.payload(), &encrypted(5)?);

        let second = windows_store_for_test(
            config.clone(),
            StorageAuthenticationKey::new([0x6b; 32])?,
            anchor.clone(),
        );
        assert!(second.is_err());
    }

    {
        let mut reopened =
            windows_store_for_test(config, StorageAuthenticationKey::new([0x6b; 32])?, anchor)?;
        assert_eq!(reopened.load()?.generation(), 2);
        assert_eq!(reopened.load()?.payload(), &encrypted(5)?);
    }

    let temporary_parent = std::env::temp_dir();
    let safe_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("your-wallet-storage-test-"));
    if !root.starts_with(&temporary_parent) || !safe_name {
        return Err(StoreError::UnsafePath.into());
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_backend_rejects_hard_linked_persistent_file() -> Result<(), Box<dyn std::error::Error>> {
    use core::fmt::Write as _;

    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| StoreError::DurabilityFailure)?;
    let mut suffix = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut suffix, "{byte:02x}").map_err(|_| StoreError::DurabilityFailure)?;
    }
    let root = std::env::temp_dir().join(format!("your-wallet-storage-hardlink-test-{suffix}"));
    let config = StoreConfig::new(root.clone(), "hardlink", RecordClass::NonceLedger, 4096)?;
    let anchor = MemoryAnchor::default();

    {
        let mut store = windows_store_for_test(
            config.clone(),
            StorageAuthenticationKey::new([0x6c; 32])?,
            anchor.clone(),
        )?;
        store.commit(None, &encrypted(6)?)?;
    }

    let manifest = root.join("hardlink.manifest");
    let alias = root.join("hardlink.manifest.alias");
    std::fs::hard_link(&manifest, &alias)?;
    let result = {
        let mut reopened =
            windows_store_for_test(config, StorageAuthenticationKey::new([0x6c; 32])?, anchor)?;
        reopened.load()
    };

    let temporary_parent = std::env::temp_dir();
    let safe_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("your-wallet-storage-hardlink-test-"));
    if !root.starts_with(&temporary_parent) || !safe_name {
        return Err(StoreError::UnsafePath.into());
    }
    std::fs::remove_file(alias)?;
    std::fs::remove_dir_all(root)?;

    assert_eq!(result, Err(StoreError::UnsafePath));
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_backend_rejects_reparse_point_persistent_file() -> Result<(), Box<dyn std::error::Error>>
{
    use core::fmt::Write as _;
    use std::os::windows::fs::symlink_file;

    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| StoreError::DurabilityFailure)?;
    let mut suffix = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut suffix, "{byte:02x}").map_err(|_| StoreError::DurabilityFailure)?;
    }
    let root = std::env::temp_dir().join(format!("your-wallet-storage-reparse-test-{suffix}"));
    let config = StoreConfig::new(root.clone(), "reparse", RecordClass::NonceLedger, 4096)?;
    let anchor = MemoryAnchor::default();

    {
        let mut store = windows_store_for_test(
            config.clone(),
            StorageAuthenticationKey::new([0x6d; 32])?,
            anchor.clone(),
        )?;
        store.commit(None, &encrypted(7)?)?;
    }

    let manifest = root.join("reparse.manifest");
    let backing = root.join("reparse.manifest.backing");
    std::fs::rename(&manifest, &backing)?;
    if let Err(error) = symlink_file(&backing, &manifest) {
        let creation_not_permitted = error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314);
        let temporary_parent = std::env::temp_dir();
        let safe_name = root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("your-wallet-storage-reparse-test-"));
        if !root.starts_with(&temporary_parent) || !safe_name {
            return Err(StoreError::UnsafePath.into());
        }
        std::fs::remove_dir_all(root)?;
        if creation_not_permitted {
            return Ok(());
        }
        return Err(error.into());
    }

    let result = {
        let mut reopened =
            windows_store_for_test(config, StorageAuthenticationKey::new([0x6d; 32])?, anchor)?;
        reopened.load()
    };

    let temporary_parent = std::env::temp_dir();
    let safe_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("your-wallet-storage-reparse-test-"));
    if !root.starts_with(&temporary_parent) || !safe_name {
        return Err(StoreError::UnsafePath.into());
    }
    std::fs::remove_file(manifest)?;
    std::fs::remove_dir_all(root)?;

    assert_eq!(result, Err(StoreError::UnsafePath));
    Ok(())
}
