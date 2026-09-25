use std::time::Instant;

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use crossbeam_channel::Sender;
use ethrex_common::types::{AccountState, Receipt, Transaction};
use ethrex_crypto::native::NativeCrypto;
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode, error::RLPDecodeError};
use ethrex_trie::{Trie, TrieError};
use helix_tcp_types::merging::builder_to_relay::MergedBlockV1;

use crate::engine::convert::{au256, b256};

pub struct AdjustmentConfig {
    pub fee_payer: Address,
    /// Dropped when full.
    pub snapshots: Sender<AdjustmentSnapshot>,
}

pub struct AdjustmentSnapshot {
    pub parent_beacon_block_root: Option<B256>,
    pub payment_index: usize,
    /// The proposer payment's sender.
    pub builder: Address,
    pub proposer: Address,
    pub fee_payer: Address,
    pub block: MergedBlockV1,
    pub proofs: Result<AdjustmentProofs, AdjustmentProofError>,
}

#[derive(Debug, thiserror::Error)]
pub enum AdjustmentProofError {
    #[error("payment index {0} out of range")]
    PaymentIndexOutOfRange(usize),
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
    pub payment: Transaction,
    pub account_proofs_us: u128,
    pub payment_proofs_us: u128,
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

/// The fee payer must exist in the post-state: adjustment cannot insert a leaf.
pub fn generate_proofs(
    state_trie: Trie,
    transactions: &[Transaction],
    receipts: &[Receipt],
    payment_index: usize,
    builder: Address,
    proposer: Address,
    config: &AdjustmentConfig,
) -> Result<AdjustmentProofs, AdjustmentProofError> {
    let started = Instant::now();
    let (payment, receipt) = transactions
        .get(payment_index)
        .zip(receipts.get(payment_index))
        .ok_or(AdjustmentProofError::PaymentIndexOutOfRange(payment_index))?;
    let cumulative_before = payment_index
        .checked_sub(1)
        .map_or(0, |previous| receipts[previous].cumulative_gas_used);

    let account_proof = |address: Address| state_trie.get_proof(&account_path(address));
    let builder_proof = into_bytes(account_proof(builder)?);
    let fee_payer_proof = into_bytes(account_proof(config.fee_payer)?);
    let proposer_proof = into_bytes(account_proof(proposer)?);
    let account_proofs_us = started.elapsed().as_micros();

    let started = Instant::now();
    let transaction_trie =
        indexed_trie(transactions.iter().map(|tx| tx.encode_canonical_to_vec()))?;
    let receipt_trie = indexed_trie(
        receipts.iter().map(|receipt| receipt.encode_inner_with_bloom(&NativeCrypto)),
    )?;
    let transaction_proof = into_bytes(transaction_trie.get_proof(&payment_index.encode_to_vec())?);
    let receipt_proof = into_bytes(receipt_trie.get_proof(&payment_index.encode_to_vec())?);
    let transactions_root = b256(transaction_trie.hash_no_commit(&NativeCrypto));
    let payment_proofs_us = started.elapsed().as_micros();

    Ok(AdjustmentProofs {
        builder_proof,
        fee_payer_proof,
        proposer_proof,
        transaction_proof,
        receipt_proof,
        transactions_root,
        placeholder_gas_used: receipt.cumulative_gas_used - cumulative_before,
        payment: payment.clone(),
        account_proofs_us,
        payment_proofs_us,
        state_trie,
    })
}

fn account_path(address: Address) -> Vec<u8> {
    keccak256(address).to_vec()
}

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
