//! The transfer intent and its canonical transcript (spec/07 §13.2). The transcript bytes are the
//! `SigningPayload::SolTransfer` signing-payload bytes of the approval digest; `intent_hash` is
//! their SHA-256.

use sha2::{Digest, Sha256};

use super::address::SolCluster;
use super::template::{SolAsset, SolTransferCore, SplAccounts};
use crate::codec::transcript::Transcript;
use crate::slip10::SolKeySource;

/// Transcript domain.
pub const INTENT_DOMAIN: &str = "your-wallet/sol/transfer-intent";

/// Warning flags bound into the intent (spec/07 §13.2).
pub mod flags {
    /// bit0: send max (`L08`).
    pub const SEND_MAX: u8 = 1 << 0;
    /// bit1: off-curve recipient (`L02`).
    pub const OFF_CURVE: u8 = 1 << 1;
    /// bit2: first-time recipient (`L06`).
    pub const FIRST_TIME: u8 = 1 << 2;
    /// bit3: lookalike recipient (`L03`).
    pub const LOOKALIKE: u8 = 1 << 3;
    /// bit4: program-owned recipient account (`L04`).
    pub const PROGRAM_OWNED: u8 = 1 << 4;
    /// bit5: simulation failure or CU overrun (`L05`).
    pub const SIM_WARNING: u8 = 1 << 5;
    /// bit6: non-standard path account (`L07`).
    pub const NON_STANDARD_PATH: u8 = 1 << 6;
    /// Every defined bit.
    pub const ALL: u8 = 0x7f;
}

/// One SOL or allowlisted SPL transfer as approved (spec/07 §2). `id` = `ApprovalRequest.id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolTransferIntent {
    /// Approval id (fresh per review).
    pub id: [u8; 16],
    /// Cluster.
    pub cluster: SolCluster,
    /// Key source of `core.from`.
    pub source: SolKeySource,
    /// Message content (blockhash excluded).
    pub core: SolTransferCore,
    /// `5_000 + priority fee` of `core` (spec/07 §10).
    pub max_fee_lamports: u64,
    /// The user cap at intent creation.
    pub fee_cap_lamports: u64,
    /// [`flags`].
    pub flags: u8,
    /// Wall-clock Unix ms of the first Ready display (= `ApprovalRequest.created_unix_ms`).
    pub created_at_ms: u64,
}

fn push_bytes(transcript: &mut Transcript, bytes: &[u8]) {
    // Fixed-size fields only: the u32 length prefix of `push_bytes` written explicitly.
    transcript.push_u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    transcript.push_fixed(bytes);
}

impl SolTransferIntent {
    /// The canonical transcript (spec/07 §13.2), binding the cluster's pinned genesis hash.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let mut t = Transcript::default();
        push_bytes(&mut t, INTENT_DOMAIN.as_bytes());
        t.push_u16(1);
        push_bytes(&mut t, &self.id);
        t.push_u8(self.cluster.code());
        push_bytes(&mut t, &self.cluster.genesis());
        let (a, b) = self.source.params();
        t.push_u8(self.source.tag());
        t.push_u32(a);
        t.push_u32(b);
        push_bytes(&mut t, self.core.from.as_bytes());
        push_bytes(&mut t, self.core.to.as_bytes());
        t.push_u8(self.core.asset.tag());
        if let SolAsset::Spl(entry) = self.core.asset {
            // The ATAs are derived (spec/07 §8.4); an impossible derivation binds zeros and the
            // message encodes empty, so nothing could be signed for it.
            let (from_ata, to_ata) = SplAccounts::of(&self.core).map_or(([0; 32], [0; 32]), |a| {
                (a.from_ata.to_bytes(), a.to_ata.to_bytes())
            });
            push_bytes(&mut t, entry.mint.as_bytes());
            push_bytes(&mut t, entry.token_program.as_bytes());
            t.push_u8(entry.decimals);
            push_bytes(&mut t, &from_ata);
            push_bytes(&mut t, &to_ata);
        }
        t.push_u64(self.core.amount);
        t.push_u32(self.core.cu_limit);
        t.push_u64(self.core.cu_price_micro);
        t.push_u64(self.max_fee_lamports);
        t.push_u64(self.fee_cap_lamports);
        t.push_u8(self.flags);
        t.push_u64(self.created_at_ms);
        t.into_bytes()
    }

    /// `SHA-256(transcript)`.
    #[must_use]
    pub fn intent_hash(&self) -> [u8; 32] {
        Sha256::digest(self.transcript()).into()
    }

    /// Whether a flag bit is set.
    #[must_use]
    pub const fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}
