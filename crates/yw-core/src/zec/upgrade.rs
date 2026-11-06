//! Network upgrades, consensus branch ids and the expiry height (spec/12 §4).
//!
//! The wallet keeps a table of the upgrades it knows. Before every plan it takes the node's
//! `getblockchaininfo` (`consensus.nextblock`, `upgrades`) as an observation and refuses unless
//! (1) the node's next-block branch id is in the table and allows v5 transparent transactions,
//! (2) the table, where it knows the activation height on this network, gives the same branch
//! id for the next block, and (3) the expiry height `next + ZEC_EXPIRY_DELTA` can be capped
//! below the next pending upgrade while leaving at least [`ZEC_MIN_EXPIRY_BLOCKS`] blocks. The
//! signed branch id is the node's (checked) value; a mismatch never signs.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::network::ZecNetwork;

/// Default expiry delta before NU7 (ZIP 203: 40 blocks post-Blossom, 75 s blocks).
pub const ZEC_EXPIRY_DELTA_PRE_NU7: u32 = 40;
/// Default expiry delta from NU7 (ZIP 203 "Changes for NU7", ZIP 218: 120 blocks of 25 s).
pub const ZEC_EXPIRY_DELTA_NU7: u32 = 120;
/// The largest expiry delta of the table (bounds the tip check).
pub const ZEC_EXPIRY_DELTA: u32 = ZEC_EXPIRY_DELTA_NU7;
/// Fewest blocks a transaction must stay valid (zcashd `TX_EXPIRING_SOON_THRESHOLD` = 3: the
/// mempool refuses transactions expiring sooner).
pub const ZEC_MIN_EXPIRY_BLOCKS: u32 = 4;
/// Largest `nExpiryHeight` (ZIP 203).
pub const ZEC_MAX_EXPIRY_HEIGHT: u32 = 499_999_999;

/// One network upgrade the wallet knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upgrade {
    /// Name (`NU5`, `NU6`, …).
    pub name: &'static str,
    /// Consensus branch id.
    pub branch_id: u32,
    /// Mainnet activation height, if known.
    pub mainnet: Option<u32>,
    /// Testnet activation height, if known.
    pub testnet: Option<u32>,
    /// Whether this wallet's v5 transparent transaction is valid under this branch.
    pub v5: bool,
    /// Default expiry delta (blocks after the next block) while this branch is current.
    pub expiry_delta: u32,
    /// Target block spacing in seconds (display only).
    pub block_secs: u32,
}

impl Upgrade {
    /// The activation height on `network`, if the table knows it.
    #[must_use]
    pub const fn height(&self, network: ZecNetwork) -> Option<u32> {
        match network {
            ZecNetwork::Mainnet => self.mainnet,
            ZecNetwork::Testnet => self.testnet,
        }
    }
}

/// The upgrades from NU5 (the first with v5 transactions), in activation order (spec/12 §4.1
/// with sources).
pub const KNOWN_UPGRADES: [Upgrade; 6] = [
    Upgrade {
        name: "NU5",
        branch_id: 0xC2D6_D0B4,
        mainnet: Some(1_687_104),
        testnet: Some(1_842_420),
        v5: true,
        expiry_delta: ZEC_EXPIRY_DELTA_PRE_NU7,
        block_secs: 75,
    },
    Upgrade {
        name: "NU6",
        branch_id: 0xC8E7_1055,
        mainnet: Some(2_726_400),
        testnet: Some(2_976_000),
        v5: true,
        expiry_delta: ZEC_EXPIRY_DELTA_PRE_NU7,
        block_secs: 75,
    },
    Upgrade {
        name: "NU6.1",
        branch_id: 0x4DEC_4DF0,
        mainnet: Some(3_146_400),
        testnet: Some(3_536_500),
        v5: true,
        expiry_delta: ZEC_EXPIRY_DELTA_PRE_NU7,
        block_secs: 75,
    },
    Upgrade {
        name: "NU6.2",
        branch_id: 0x5437_F330,
        mainnet: Some(3_364_600),
        testnet: Some(4_052_000),
        v5: true,
        expiry_delta: ZEC_EXPIRY_DELTA_PRE_NU7,
        block_secs: 75,
    },
    // NU6.3 introduced the v6 format (ZIP 229); v5 stays valid.
    Upgrade {
        name: "NU6.3",
        branch_id: 0x37A5_165B,
        mainnet: Some(3_428_143),
        testnet: Some(4_134_000),
        v5: true,
        expiry_delta: ZEC_EXPIRY_DELTA_PRE_NU7,
        block_secs: 75,
    },
    // NU7 (ZIP 259): v5 and v6 stay valid, v4 is invalid; 25 s blocks, expiry delta 120.
    Upgrade {
        name: "NU7",
        branch_id: 0x7719_0AD9,
        mainnet: Some(3_543_405),
        testnet: Some(4_465_026),
        v5: true,
        expiry_delta: ZEC_EXPIRY_DELTA_NU7,
        block_secs: 25,
    },
];

/// The table entry of `branch_id`.
#[must_use]
pub fn known(branch_id: u32) -> Option<&'static Upgrade> {
    KNOWN_UPGRADES
        .iter()
        .find(|upgrade| upgrade.branch_id == branch_id)
}

/// The branch the table expects at `height` on `network`: the last known upgrade whose
/// activation height is known and ≤ `height` (`None` before NU5).
#[must_use]
pub fn expected_branch(network: ZecNetwork, height: u32) -> Option<&'static Upgrade> {
    KNOWN_UPGRADES
        .iter()
        .rev()
        .find(|upgrade| upgrade.height(network).is_some_and(|at| at <= height))
}

/// The node's consensus view (`getblockchaininfo`), already parsed by the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusObservation {
    /// Tip height (`blocks`).
    pub tip: u32,
    /// `consensus.nextblock` branch id.
    pub next_branch: u32,
    /// Every `upgrades` entry: `(branch_id, activationheight)`.
    pub upgrades: Vec<(u32, u32)>,
}

/// The consensus fields of a transaction we build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxConsensus {
    /// Branch id (checked).
    pub branch_id: u32,
    /// Name of that upgrade.
    pub upgrade_name: &'static str,
    /// Height of the block the transaction is built for (`tip + 1`).
    pub next_height: u32,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// The next pending upgrade's activation height, if any (the expiry stays below it).
    pub next_upgrade_height: Option<u32>,
    /// Target block spacing of the current branch (seconds, display only).
    pub block_secs: u32,
}

/// Why no transaction may be built now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeError {
    /// The node's next-block branch id is not in the table (the wallet is out of date, or the
    /// node is on another chain).
    UnknownBranch(u32),
    /// The branch is known but v5 transparent transactions are not valid under it.
    NotV5(u32),
    /// The table expects another branch for the next block.
    BranchMismatch {
        /// Node's value.
        node: u32,
        /// Table's value.
        table: u32,
    },
    /// A pending upgrade activates too soon for a safe expiry.
    UpgradeTooClose {
        /// Activation height.
        height: u32,
    },
    /// Tip height out of range.
    TipImplausible,
}

impl UpgradeError {
    /// The fixed Korean text (spec/12 §11).
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::UnknownBranch(id) => format!(
                "노드가 이 지갑이 모르는 네트워크 업그레이드(branch id {id:08x})를 알려 주었습니다. 지갑을 업데이트하기 전에는 보낼 수 없습니다."
            ),
            Self::NotV5(id) => format!(
                "현재 네트워크 업그레이드(branch id {id:08x})에서는 이 지갑의 거래 형식(v5)을 쓸 수 없습니다."
            ),
            Self::BranchMismatch { node, table } => format!(
                "노드의 네트워크 업그레이드(branch id {node:08x})가 지갑의 표({table:08x})와 다릅니다. 노드나 지갑 버전을 확인하세요."
            ),
            Self::UpgradeTooClose { height } => format!(
                "네트워크 업그레이드가 곧(블록 {height}) 활성화됩니다. 활성화된 뒤에 다시 보내세요."
            ),
            Self::TipImplausible => "노드의 블록 높이가 올바르지 않습니다.".to_owned(),
        }
    }
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text())
    }
}

impl std::error::Error for UpgradeError {}

/// The checked consensus fields for the next block (see the module comment).
///
/// # Errors
///
/// [`UpgradeError`].
pub fn tx_consensus(
    network: ZecNetwork,
    observed: &ConsensusObservation,
) -> Result<TxConsensus, UpgradeError> {
    let next_height = observed
        .tip
        .checked_add(1)
        .filter(|height| *height < ZEC_MAX_EXPIRY_HEIGHT - ZEC_EXPIRY_DELTA)
        .ok_or(UpgradeError::TipImplausible)?;
    let upgrade =
        known(observed.next_branch).ok_or(UpgradeError::UnknownBranch(observed.next_branch))?;
    if !upgrade.v5 {
        return Err(UpgradeError::NotV5(upgrade.branch_id));
    }
    if let Some(table) = expected_branch(network, next_height)
        && table.branch_id != upgrade.branch_id
    {
        return Err(UpgradeError::BranchMismatch {
            node: upgrade.branch_id,
            table: table.branch_id,
        });
    }
    // The next activation after the next block: from the node's list and from our table.
    let node_pending = observed
        .upgrades
        .iter()
        .filter(|(_, height)| *height > next_height)
        .map(|(_, height)| *height);
    let table_pending = KNOWN_UPGRADES
        .iter()
        .filter_map(|known| known.height(network))
        .filter(|height| *height > next_height);
    let next_upgrade_height = node_pending.chain(table_pending).min();
    let mut expiry_height = next_height.saturating_add(upgrade.expiry_delta);
    if let Some(activation) = next_upgrade_height {
        expiry_height = expiry_height.min(activation.saturating_sub(1));
        if expiry_height < next_height.saturating_add(ZEC_MIN_EXPIRY_BLOCKS) {
            return Err(UpgradeError::UpgradeTooClose { height: activation });
        }
    }
    Ok(TxConsensus {
        branch_id: upgrade.branch_id,
        upgrade_name: upgrade.name,
        next_height,
        expiry_height,
        next_upgrade_height,
        block_secs: upgrade.block_secs,
    })
}
