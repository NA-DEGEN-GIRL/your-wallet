//! The received-history part of each chain's activity card (spec/04 §2.6, 2026-11-11): the
//! switch `받은 내역도 보기` (off by default, one setting for every chain) and, when on, the
//! sub-heading "받은 내역" with the address-poisoning help line, the rows (local time, "받음
//! {금액} {기호}", status, the sender — read only, grouped, never with a copy or select button,
//! with the exact address-book / own-account name or a look-alike warning tag — the hash on its
//! own line, a click copying it, with the ↗ `탐색기에서 열기` icon), and the muted count of hidden
//! dust transfers. One call per card:
//! [`App::received_items`].
//!
//! Unconfirmed rows (2026-11-13: Bitcoin and Zcash mempool, Solana `processed`): "미확정 · 받음
//! …", the status [`text::PENDING_STATUS`] and no sender until confirmed ([`text::PENDING_SENDER`]: a
//! look-alike payment can be replaced back to its sender for the fee only). Before, the status
//! read "상태: 대기 중 (아직 확인되지 않음)", the headline "시각 모름" and the sender was shown.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::received` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

/// Command ids of the received history (17,800–18,399; spec/04 §2.6, `ui::command_ids`).
pub mod ids {
    /// Chains (slots of [`yw_engine::received::RecvChain::slot`]).
    pub const CHAINS: u16 = 5;
    /// `받은 내역도 보기` of each chain's card (one setting; a card's own id).
    pub const TOGGLE_BASE: u16 = 17_800;
    /// `받은 내역 n건 더 보기 ▸` / `접기 ▾` of each chain's card.
    pub const MORE_BASE: u16 = 17_805;
    /// Fixed ids.
    pub const FIXED: [u16; 10] = [
        17_800, 17_801, 17_802, 17_803, 17_804, 17_805, 17_806, 17_807, 17_808, 17_809,
    ];
    /// Row buttons: `ROW_BASE + slot × CHAIN_SPAN + row × ROW_STRIDE`.
    pub const ROW_BASE: u16 = 17_900;
    /// Ids per row: 0 a click on the hash (copy, the `해시 복사` of before), 1 ↗ `탐색기에서 열기`.
    pub const ROW_STRIDE: u16 = 2;
    /// Ids per chain (50 rows × 2).
    pub const CHAIN_SPAN: u16 = 100;
    /// All row ids.
    pub const ROW_SPAN: u16 = 500;

    /// The switch of `chain`'s card.
    #[must_use]
    pub const fn toggle(chain: yw_engine::received::RecvChain) -> u16 {
        TOGGLE_BASE + chain.slot()
    }

    /// `더 보기` of `chain`'s card.
    #[must_use]
    pub const fn more(chain: yw_engine::received::RecvChain) -> u16 {
        MORE_BASE + chain.slot()
    }

    /// The first id of `row` of `chain` (`None` past the 50 rows).
    #[must_use]
    pub fn row(chain: yw_engine::received::RecvChain, row: usize) -> Option<u16> {
        let row = u16::try_from(row)
            .ok()
            .filter(|row| *row < CHAIN_SPAN / ROW_STRIDE)?;
        Some(ROW_BASE + chain.slot() * CHAIN_SPAN + row * ROW_STRIDE)
    }

    /// The press control `id` stands for (2026-11-18, S3 C1: `ui::cmd_table`); a switch carries
    /// its check box's state now. `None` when `id` is not one of this module's.
    #[must_use]
    pub fn press_of(
        id: u16,
        controls: &crate::ui::main_window::ControlSet,
    ) -> Option<yw_engine::cmd::ReceivedPress> {
        use yw_engine::cmd::{ReceivedPress, Row};
        if let Some(chain) = id
            .checked_sub(TOGGLE_BASE)
            .and_then(yw_engine::received::RecvChain::of_slot)
            .filter(|_| id < MORE_BASE)
        {
            return Some(ReceivedPress::Toggle {
                chain,
                checked: controls.checked(id),
            });
        }
        if let Some(chain) = id
            .checked_sub(MORE_BASE)
            .filter(|slot| *slot < CHAINS)
            .and_then(yw_engine::received::RecvChain::of_slot)
        {
            return Some(ReceivedPress::More(chain));
        }
        let offset = id
            .checked_sub(ROW_BASE)
            .filter(|offset| *offset < ROW_SPAN)?;
        let chain = yw_engine::received::RecvChain::of_slot(offset / CHAIN_SPAN)?;
        let row = Row(offset % CHAIN_SPAN / ROW_STRIDE);
        Some(if offset % ROW_STRIDE == 0 {
            ReceivedPress::CopyHash(chain, row)
        } else {
            ReceivedPress::OpenExplorer(chain, row)
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::ReceivedPress) -> u16 {
        use yw_engine::cmd::{ReceivedPress, Row};
        const fn row_id(chain: yw_engine::received::RecvChain, Row(row): Row) -> u16 {
            ROW_BASE
                .wrapping_add(chain.slot().wrapping_mul(CHAIN_SPAN))
                .wrapping_add(row.wrapping_mul(ROW_STRIDE))
        }
        match press {
            ReceivedPress::Toggle { chain, .. } => toggle(chain),
            ReceivedPress::More(chain) => more(chain),
            ReceivedPress::CopyHash(chain, row) => row_id(chain, row),
            ReceivedPress::OpenExplorer(chain, row) => row_id(chain, row).wrapping_add(1),
        }
    }
}
