use merkle::{hash_concat, merkle_mountain_range::MMRProof};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use derive_builder::Builder;
use merkle::{
    sparse_merkle_tree::{InclusionProof, NonInclusionProof, DEFAULT_HASHES}, HashDigest
};

pub type Amount = u64;
pub type PublicKey = Vec<u8>;

pub mod merkle;

/// All three proofs that have to be checked per coin or previous account state proof
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitmentMerkleProofs {
    // Root of the commitment tree.
    pub commitment_root: HashDigest,
    // Proves that commitment is included in commitment tree.
    pub commitment_proof: InclusionProof,
    // Proves that the commitment root is included in the commitment history tree.
    pub commitment_root_history_proof: MMRProof,
    pub commitment_root_mmr_sibling: HashDigest,
    // Proves that the previous commitment history root is included in the commitment history tree.
    // This proof is different from commitment_root_history_proof and commitmentProof because we
    // store tuples of (SMTRoot, MMRRoot) in the MMR.
    pub previous_root_history_proof: (HashDigest, MMRProof),
    // The commitment is hash(hash(account_state) || out_coins_root)
    pub commitment_account_state_hash: HashDigest,
    pub commitment_out_coins_root: HashDigest,
}

impl CommitmentMerkleProofs {
    fn verify_commitment_root(&self, commitment_history_root: HashDigest) -> bool {
        self.commitment_root_history_proof.verify(
            hash_concat(&self.commitment_root, &self.commitment_root_mmr_sibling),
            commitment_history_root,
        )
    }

    fn commitment(&self) -> HashDigest {
        hash_concat(
            &self.commitment_account_state_hash,
            &self.commitment_out_coins_root,
        )
    }

    pub fn verify_commitment(&self, commitment_history_root: HashDigest) -> bool {
        let valid_smt_in_history = self.verify_commitment_root(commitment_history_root);
        let valid_commitment_in_smt = self
            .commitment_proof
            .verify(self.commitment(), self.commitment_root);
        valid_smt_in_history && valid_commitment_in_smt
    }

    pub fn verify_previous_root(
        &self,
        previous_root: HashDigest,
        commitment_history_root: HashDigest,
    ) -> bool {
        self.previous_root_history_proof.1.verify(
            hash_concat(&self.previous_root_history_proof.0, &previous_root),
            commitment_history_root,
        )
    }
}

pub const MINTING_ADDRESS: HashDigest = [44, 153, 26, 227, 141, 88, 195, 127, 88, 144, 228, 143, 121, 49, 51, 158, 111, 205, 183, 53, 133, 35, 183, 240, 183, 165, 104, 116, 66, 228, 94, 242];

pub fn hash(data: &[u8]) -> HashDigest {
    Sha256::digest(data).into()
}

#[derive(Deserialize, Serialize, Clone)]
pub enum ProofType {
    InitialProof,
    AccountUpdateProof,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ProofData {
    pub vk: [u32; 8],
    pub account_state_hash: HashDigest,
    pub output_coins_root: HashDigest,
    pub commitment_history_root: HashDigest,
    pub coin_history_root: HashDigest,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct CoinTemplate {
    pub recipient: HashDigest,
    pub amount: Amount,
}

impl CoinTemplate {
    pub fn new(recipient: HashDigest, amount: Amount) -> Self {
        CoinTemplate { recipient, amount }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Coin {
    pub identifier: HashDigest,
    pub recipient: HashDigest,
    pub amount: Amount,
}

impl Coin {
    pub fn new(template: CoinTemplate, identifier: HashDigest) -> Coin {
        Coin {
            recipient: template.recipient,
            amount: template.amount,
            identifier,
        }
    }

    /// Checks that the coin identifier is generated as expected.
    pub fn verify_identifier(
        &self,
        account_state_hash: HashDigest,
        coin_index: u32,
    ) -> Result<(), &'static str> {
        if calculate_coin_identifier(account_state_hash, coin_index) == self.identifier {
            Ok(())
        } else {
            Err("Incorrect preimages provided.")
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AccountState {
    pub owner: HashDigest,
    pub balance: u64,
    pub public_key: PublicKey,
}

impl AccountState {
    pub fn new(initial_public_key: PublicKey) -> Self {
        // TODO: The randomness here is annoying why do we not hash the public key directly and
        // skip the first one in the commitments?
        // We add random bytes to the public key as a blinding factor for the address.
        // This ensures that the on-chain commited public keys can not be linked to the address.
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        let address = hash(&[initial_public_key.clone(), random_bytes.to_vec()].concat());
        AccountState {
            owner: address,
            balance: 0,
            public_key: initial_public_key,
        }
    }

    pub fn apply_coin(mut self, coin: &Coin) -> Result<Self, &'static str> {
        if coin.recipient != self.owner {
            return Err("Cannot receive coin: User is not the recipient");
        }

        self.balance = match self.balance.checked_add(coin.amount) {
            Some(balance) => balance,
            None => return Err("Receiving coin causes an overflow")
        };
        Ok(self)
    }

    // Applies all coins to the account state and returns the out_coins_root.
    pub fn send_coins(
        &mut self,
        coins: Vec<Coin>,
        coin_proofs: Vec<NonInclusionProof>,
        next_public_key: PublicKey,
    ) -> Result<HashDigest, &'static str> {
        // Create an empty coins tree
        let mut out_coins_root = DEFAULT_HASHES[0];

        // Verify and apply sent coins.
        for (coin_path, coin) in coin_proofs.iter().zip(&coins) {
            // Make sure the proof has the correct root.
            if out_coins_root != coin_path.root {
                return Err("Update path has incorrect root");
            }
            // Update the out_coins_root. (Providing a wrong path only means that the coin may not be
            // receivable. Thus, we do not have to verify the path)
            out_coins_root = coin_path.insert(coin.identifier)?;
            // Apply coin.
            self.balance = match self.balance.checked_sub(coin.amount) {
                Some(balance) => balance,
                None => return Err("Balance too small to create Coin.")
            };
        }

        // Verify that each identifier is uniquely derived from account_state after all sends.
        let account_hash = self.hash();
        for (i, coin) in coins.iter().enumerate() {
            // NOTE: Expected coin identifier to be hash( hash( account state ) || coin index )
            coin.verify_identifier(account_hash, i as u32)?;
        }
        // Advance the public key.
        self.public_key = next_public_key;
        Ok(out_coins_root)
    }

    pub fn hash(&self) -> HashDigest {
        let serialized = bincode::serialize(self).expect("Serialization failed");
        hash(&serialized)
    }
}

#[derive(Builder, Serialize, Deserialize)]
pub struct ProgramInputs {
    pub proof_type: ProofType,
    pub verification_key: [u32; 8],
    pub account_state: AccountState,
    pub current_history_root: HashDigest,

    // Prev proof is the previous account_state proof.
    #[builder(default)]
    pub prev_proof_public_values: Option<Vec<u8>>,
    #[builder(default)]
    pub prev_proof_history_proofs: Option<CommitmentMerkleProofs>,

    pub in_coins: Vec<Coin>,
    pub in_coin_proofs_public_values: Vec<Vec<u8>>,
    pub in_coin_proofs_history_proofs: Vec<CommitmentMerkleProofs>,
    // Proofs for each coin in in_coins that it hasn't been received yet.
    pub in_coin_proofs_non_inclusion_proofs: Vec<NonInclusionProof>,
    // Proofs for each coin in in_coins that it was part of the in_coin_proof's out_coins.
    pub in_coins_inclusion_proofs: Vec<InclusionProof>,

    pub out_coins: Vec<Coin>,
    // Used to generate the out_coins root.
    pub out_coin_proofs: Vec<NonInclusionProof>,
    pub next_public_key: PublicKey,
}

/// The coin identifier is generated from the account state hash (after updating it with the coin
/// send) and the coin index.
pub fn calculate_coin_identifier(account_state_hash: HashDigest, coin_index: u32) -> HashDigest {
    hash(
        &[
            account_state_hash.to_vec(),
            coin_index.to_be_bytes().to_vec(),
        ]
        .concat(),
    )
}

// TODO: Write a test for the send_coins function (we can compare to the actual smt after inserting
// values)
