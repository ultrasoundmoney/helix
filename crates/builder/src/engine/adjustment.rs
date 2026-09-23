//! Testing only: adjustment data for merged blocks, to dry run bid adjustment
//! against them. Proofs are generated off the engine thread, from emitted
//! snapshots.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use crossbeam_channel::Sender;
use ethrex_common::{
    H256,
    constants::EMPTY_KECCAK_HASH,
    types::{AccountState, AccountUpdate, Receipt, Transaction},
};
use ethrex_crypto::native::NativeCrypto;
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode, error::RLPDecodeError};
use ethrex_storage::{Store, error::StoreError};
use ethrex_trie::{Trie, TrieError};
use helix_tcp_types::merging::builder_to_relay::MergedBlockV1;

use crate::engine::convert::{au256, b256};

pub struct AdjustmentConfig {
    /// A funded account standing in for the relay's fee payer.
    pub fee_payer: Address,
    /// Dropped when full.
    pub snapshots: Sender<AdjustmentSnapshot>,
}

pub struct AdjustmentSnapshot {
    pub parent_hash: H256,
    pub parent_beacon_block_root: Option<B256>,
    pub account_updates: Vec<AccountUpdate>,
    pub transactions: Vec<Transaction>,
    pub receipts: Vec<Receipt>,
    /// The base block's proposer payment.
    pub payment_index: usize,
    /// The coinbase.
    pub builder: Address,
    pub proposer: Address,
    pub fee_payer: Address,
    pub block: MergedBlockV1,
}

#[derive(Debug, thiserror::Error)]
pub enum AdjustmentProofError {
    #[error("parent state not found")]
    ParentStateNotFound,
    /// Code, including an EIP-7702 delegation, can observe the rewritten values.
    #[error("{0} has code")]
    HasCode(Address),
    #[error("payment index {0} out of range")]
    PaymentIndexOutOfRange(usize),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("trie: {0}")]
    Trie(#[from] TrieError),
    #[error("account decode: {0}")]
    AccountDecode(#[from] RLPDecodeError),
}

pub struct AdjustmentProofs {
    pub builder_proof: Vec<Bytes>,
    pub fee_payer_proof: Vec<Bytes>,
    pub proposer_proof: Vec<Bytes>,
    pub transaction_proof: Vec<Bytes>,
    pub receipt_proof: Vec<Bytes>,
    pub transactions_root: B256,
    pub placeholder_gas_used: u64,
    /// The merged block's post-state, kept to recompute the root independently
    /// of the adjustment's own trie code.
    state_trie: Trie,
}

impl AdjustmentProofs {
    pub fn account(&self, address: Address) -> Result<Option<(U256, u64)>, AdjustmentProofError> {
        let Some(encoded) = self.state_trie.get(&account_path(address))? else {
            return Ok(None);
        };
        let account = AccountState::decode(&encoded)?;

        Ok(Some((au256(account.balance), account.nonce)))
    }

    /// The post-state root with the given accounts' balance and nonce replaced.
    pub fn state_root_with(
        mut self,
        accounts: impl IntoIterator<Item = (Address, U256, u64)>,
    ) -> Result<B256, AdjustmentProofError> {
        for (address, balance, nonce) in accounts {
            let path = account_path(address);
            let encoded = self.state_trie.get(&path)?.unwrap_or_default();
            let mut account = AccountState::decode(&encoded)?;

            account.balance = ethrex_common::U256::from_big_endian(&balance.to_be_bytes::<32>());
            account.nonce = nonce;

            self.state_trie.insert(path, account.encode_to_vec())?;
        }

        Ok(b256(self.state_trie.hash_no_commit(&NativeCrypto)))
    }
}

/// Merkle proofs of the payment and the three adjusted accounts against the
/// merged block's roots. The fee payer must exist in the post-state:
/// adjustment rewrites an existing leaf and cannot insert one.
pub fn generate_proofs(
    store: &Store,
    snapshot: &AdjustmentSnapshot,
) -> Result<AdjustmentProofs, AdjustmentProofError> {
    let index = snapshot.payment_index;
    let receipt = snapshot
        .receipts
        .get(index)
        .ok_or(AdjustmentProofError::PaymentIndexOutOfRange(index))?;
    let cumulative_before =
        index.checked_sub(1).map_or(0, |previous| snapshot.receipts[previous].cumulative_gas_used);

    let mut state_trie =
        store.state_trie(snapshot.parent_hash)?.ok_or(AdjustmentProofError::ParentStateNotFound)?;
    store.apply_account_updates_from_trie_batch(&mut state_trie, &snapshot.account_updates)?;

    for address in [snapshot.builder, snapshot.proposer, snapshot.fee_payer] {
        let code_hash = state_trie
            .get(&account_path(address))?
            .map(|encoded| AccountState::decode(&encoded))
            .transpose()?
            .map(|account| account.code_hash);

        if code_hash.is_some_and(|hash| hash != *EMPTY_KECCAK_HASH) {
            return Err(AdjustmentProofError::HasCode(address));
        }
    }

    let account_proof = |address: Address| state_trie.get_proof(&account_path(address));
    let builder_proof = into_bytes(account_proof(snapshot.builder)?);
    let fee_payer_proof = into_bytes(account_proof(snapshot.fee_payer)?);
    let proposer_proof = into_bytes(account_proof(snapshot.proposer)?);

    let transaction_trie =
        indexed_trie(snapshot.transactions.iter().map(|tx| tx.encode_canonical_to_vec()))?;
    let receipt_trie = indexed_trie(
        snapshot.receipts.iter().map(|receipt| receipt.encode_inner_with_bloom(&NativeCrypto)),
    )?;

    Ok(AdjustmentProofs {
        builder_proof,
        fee_payer_proof,
        proposer_proof,
        transaction_proof: into_bytes(transaction_trie.get_proof(&index.encode_to_vec())?),
        receipt_proof: into_bytes(receipt_trie.get_proof(&index.encode_to_vec())?),
        transactions_root: b256(transaction_trie.hash_no_commit(&NativeCrypto)),
        placeholder_gas_used: receipt.cumulative_gas_used - cumulative_before,
        state_trie,
    })
}

fn account_path(address: Address) -> Vec<u8> {
    keccak256(address).to_vec()
}

/// Tx and receipt tries are keyed by the RLP of the index.
fn indexed_trie(values: impl Iterator<Item = Vec<u8>>) -> Result<Trie, TrieError> {
    let mut trie = Trie::new_temp();
    for (index, value) in values.enumerate() {
        trie.insert(index.encode_to_vec(), value)?;
    }
    Ok(trie)
}

fn into_bytes(nodes: Vec<Vec<u8>>) -> Vec<Bytes> {
    nodes.into_iter().map(Bytes::from).collect()
}
