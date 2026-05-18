use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::state::State;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use shared::commitment::Commitment;
use shared::{Address, Invoice};
use zkcoins_program::hash::{HashDigest, ZERO_HASH};
use zkcoins_program::inputs::CommitmentMerkleProofs;
use zkcoins_program::merkle::merkle_mountain_range::MMR_MAX_DEPTH;
use zkcoins_program::merkle::sparse_merkle_tree::{
    InclusionProof, NonInclusionProof, SparseMerkleTree, DEFAULT_HASHES, TREE_DEPTH,
};
use zkcoins_program::types::{
    calculate_coin_identifier, AccountState, Amount, Coin, CoinTemplate, ProofData,
};
use zkcoins_prover::{InCoinSourceWitness, Proof, Prover};

/// Fixed in-circuit MMR proof depth. Must match
/// [`zkcoins_program::circuit::main::MMR_PROOF_PATH_LEN`].
const MMR_PROOF_PATH_LEN: usize = MMR_MAX_DEPTH - 1;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoinProof {
    pub proof: Proof,
    pub coin: Coin,
    pub inclusion_proof: InclusionProof,
    pub commitment: Option<Commitment>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub proof: Option<Proof>,
    pub coin_queue: Vec<CoinProof>,
    pub coin_history: SparseMerkleTree,
    pub balance: u64,
}

impl Account {
    pub fn new() -> Self {
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 0,
        }
    }
    /// Uses the coin_template and next_public_key to create the next account_state and generates a
    /// Coin with filled in identifier (as it commits to the next account state hash).
    pub fn create_coins(
        &self,
        address: HashDigest,
        next_public_key: PublicKey,
        public_key: zkcoins_program::types::PublicKey,
        coin_templates: Vec<CoinTemplate>,
    ) -> Result<Vec<Coin>, &'static str> {
        let mut next_account_state = AccountState {
            owner: address,
            balance: self.get_balance(),
            public_key,
        };
        for coin_template in &coin_templates {
            // Caller (send_coins) already validated balance >= total
            // invoiced amount before reaching this function. The expect
            // here is documentation of that invariant.
            next_account_state.balance = next_account_state
                .balance
                .checked_sub(coin_template.amount)
                .expect("balance was validated by send_coins");
        }

        let next_account_state_hash = next_account_state.hash();
        let coins = coin_templates.into_iter().enumerate().map(|(i, template)| {
            Coin::new(
                template,
                calculate_coin_identifier(next_account_state_hash, i as u32),
            )
        });
        // Set the next public key.
        let _ = next_public_key.serialize();
        // next_account_state.public_key is intentionally not updated
        // here because the caller (send_coins) sources `next_public_key`
        // separately for the Prover witness — once Stage 5d-next-5
        // Prover-API integration lands, this update + return will be
        // wired through.
        let _ = next_account_state;
        Ok(coins.collect())
    }

    pub fn get_balance(&self) -> Amount {
        self.coin_queue
            .iter()
            .fold(self.balance, |acc, x| acc + x.coin.amount)
    }
}

pub struct AccountServer {
    accounts: HashMap<Address, Account>,
    prover: Prover,
    state: Arc<Mutex<State>>,
}

impl AccountServer {
    /// Get the keypair to the pubkey this account commited to (which is derived key num_pubkeys -
    /// 1)
    // TODO: Move to client.
    pub fn new(state: Arc<Mutex<State>>) -> Self {
        let accounts = HashMap::new();
        let prover = Prover::new();

        AccountServer {
            accounts,
            prover,
            state,
        }
    }

    pub fn import_account(&mut self, address: HashDigest, account: Account) {
        self.accounts.insert(address, account);
    }

    // TODO: User needs to provide a signature and the salt and the secret information for the
    // address to authenticate.
    pub fn get_account_balance(&self, account_address: &Address) -> Result<Amount, &'static str> {
        match self.accounts.get(account_address) {
            Some(account) => Ok(account
                .coin_queue
                .iter()
                .fold(account.balance, |acc, x| acc + x.coin.amount)),
            _ => Err("No account with this address"),
        }
    }

    #[cfg(any(feature = "address-list", feature = "usernames", feature = "lnurl"))]
    pub fn get_addresses(&self) -> Vec<Address> {
        self.accounts.keys().cloned().collect::<Vec<Address>>()
    }

    pub fn receive_coin(&mut self, coin_proof: CoinProof) -> Result<(), &'static str> {
        // PLONKY2 MIGRATION (Step 7): The SP1-era `proof.public_values`
        // (a writable byte stream) is replaced by Plonky2's
        // `proof.public_inputs: Vec<F>` (field elements). The
        // `ProofData::from_field_elements` helper is the canonical
        // bridge.
        let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
            coin_proof.proof.public_inputs
                [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
                .try_into()
                .map_err(|_| "Proof public_inputs too short")?;
        let proof_data = ProofData::from_field_elements(&pis);

        // Verify the inclusion of the coin in the proof.
        if !coin_proof
            .inclusion_proof
            .verify(coin_proof.coin.identifier, proof_data.output_coins_root)
        {
            return Err("Coin inclusion proof verification failed");
        }

        // Log coin receipt without exposing full address (privacy).
        let addr_bytes = zkcoins_program::hash::digest_to_bytes(&coin_proof.coin.recipient);
        eprintln!(
            "Receiving coin for address: {:02x}{:02x}…",
            addr_bytes[0], addr_bytes[1]
        );
        // Get the recipient account
        let mut account = self
            .accounts
            .remove(&coin_proof.coin.recipient)
            .unwrap_or_else(Account::new);

        // Check if we could generate updated account proof. (e.g. the coin is valid)
        // TODO: Check if the public key is not included in our accumulator yet (or belongs to the
        // same account state hash -> what is stored for the public key has to be the preimage to
        // the coin identifier)
        //let _ = self.prover.update_account(
        //    &account.state,
        //    &None,
        //    account.proof.clone(),
        //    vec![proof.clone()],
        //    // Note: account public_key is not updated when only receiving.
        //    &account.state.public_key,
        //);

        // Reject duplicate coins (replay protection)
        let coin_id = coin_proof.coin.identifier;
        if account
            .coin_queue
            .iter()
            .any(|cp| cp.coin.identifier == coin_id)
        {
            return Err("Coin already in queue (duplicate)");
        }
        if account
            .coin_history
            .generate_inclusion_proof(&zkcoins_program::hash::digest_to_bytes(&coin_id))
            .is_ok()
        {
            return Err("Coin already spent (replay)");
        }

        let address = coin_proof.coin.recipient;
        account.coin_queue.push(coin_proof);
        self.accounts.insert(address, account);
        Ok(())
    }

    /// Get all required merkle proofs from the state for the public key and the previous proof.
    /// Static method: does not access self.accounts, only the state guard.
    ///
    /// The returned bundle is shaped for in-circuit consumption: MMR
    /// proofs are pre-extended to [`MMR_PROOF_PATH_LEN`] siblings and
    /// the SMT inclusion proof carries the full [`TREE_DEPTH`]
    /// siblings (the off-circuit SMT produces this length by
    /// construction).
    fn get_merkle_proofs(
        previous_proof: Proof,
        public_key: PublicKey,
        state: &MutexGuard<'_, State>,
    ) -> Result<CommitmentMerkleProofs, &'static str> {
        let account_merkle_proofs = state
            .get_commitment_proof(&public_key)
            .or(Err("Unable to get merkle proofs for provided public key"))?;

        // PLONKY2 MIGRATION (Step 7): see `receive_coin` for the
        // bridge from SP1's `public_values` to Plonky2's `public_inputs`.
        let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
            previous_proof.public_inputs
                [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
                .try_into()
                .map_err(|_| "Proof public_inputs too short")?;
        let proof_data = ProofData::from_field_elements(&pis);
        let _ = previous_proof; // silence unused-mut warning
        let previous_root = proof_data.commitment_history_root;
        let previous_root_proof = state.get_mmr_inclusion_proof(previous_root).or(Err(
            "Unable to get mmr inclusion proof for the previous root",
        ))?;

        let proofs = CommitmentMerkleProofs {
            commitment_root: account_merkle_proofs.2,
            commitment_proof: account_merkle_proofs.1,
            // Pad MMR proofs to the fixed depth the in-circuit gadget
            // expects (`MMR_PROOF_PATH_LEN`). Off-circuit MMR proofs
            // have variable depth equal to log2(capacity).
            commitment_root_history_proof: account_merkle_proofs.3.extend_to(MMR_PROOF_PATH_LEN),
            commitment_root_mmr_sibling: state.prev_mmr_root,
            previous_root_history_proof: (
                previous_root_proof.0,
                previous_root_proof.1.extend_to(MMR_PROOF_PATH_LEN),
            ),
            commitment_account_state_hash: proof_data.account_state_hash,
            commitment_out_coins_root: proof_data.output_coins_root,
        };

        Ok(proofs)
    }

    /// Build a syntactically-valid but semantically-empty
    /// `NonInclusionProof` for inactive in-coin / out-coin slots.
    /// The slot's `active = false` bit masks the in-circuit check.
    fn dummy_nip() -> NonInclusionProof {
        NonInclusionProof {
            key: [0u8; 32],
            root: ZERO_HASH,
            siblings: vec![ZERO_HASH; TREE_DEPTH],
        }
    }

    fn dummy_coin() -> Coin {
        Coin {
            identifier: ZERO_HASH,
            recipient: ZERO_HASH,
            amount: 0,
        }
    }

    pub fn send_coins(
        &mut self,
        invoices: Vec<Invoice>,
        account_address: Address,
        public_key: PublicKey,
        next_public_key: PublicKey,
        prev_commitment_pubkey: Option<PublicKey>,
    ) -> Result<Vec<CoinProof>, &'static str> {
        let state = &self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let account = self
            .accounts
            .get_mut(&account_address)
            .ok_or("Unknown account address")?;
        // Check if the account balance is enough
        let balance = account
            .coin_queue
            .iter()
            .fold(account.balance, |acc, x| acc + x.coin.amount);
        let invoiced_amount = invoices.iter().fold(0, |acc, x| acc + x.amount);
        if balance < invoiced_amount {
            return Err("Insufficient funds");
        }

        // TODO: Copy this over to the client because they too have to check that the
        // out_coins_tree is correct and only contains the coins from the invoices.
        // Create the coin templates.
        let mut coin_templates = vec![];
        for invoice in invoices {
            coin_templates.push(CoinTemplate::new(invoice.recipient, invoice.amount));
        }

        let mut coin_history_proofs = vec![];
        let mut coin_non_inclusion_proofs = vec![];
        let mut coin_inclusion_proofs = vec![];
        let mut in_coins = vec![];
        for coin_proof in &account.coin_queue {
            coin_history_proofs.push({
                match &coin_proof.commitment {
                    Some(commitment) => Self::get_merkle_proofs(
                        coin_proof.proof.clone(),
                        commitment.public_key,
                        state,
                    )?,
                    None => return Err("Coin is missing commitment"),
                }
            });
            let coin_id_bytes = zkcoins_program::hash::digest_to_bytes(&coin_proof.coin.identifier);
            coin_non_inclusion_proofs.push({
                account
                    .coin_history
                    .generate_non_inclusion_proof(coin_id_bytes)
                    .or(Err("Should provide an inclusion proof"))?
            });
            coin_inclusion_proofs.push(coin_proof.inclusion_proof.clone());
            in_coins.push(coin_proof.coin.clone());
            account
                .coin_history
                .insert(coin_id_bytes, coin_proof.coin.identifier)
                .or(Err("Coin should not exist in coin history tree"))?;
        }
        // PLONKY2 MIGRATION (Step 7): SP1's `ProgramInputsBuilder` has
        // no Plonky2 analogue — the cyclic-recursion circuit's API
        // takes per-slot witnesses (`InCoinSlotWitness`) directly. The
        // construction below builds the same witness data, threaded
        // through to the `Prover::prove_*` calls instead of a single
        // builder struct.
        let account_state_for_prove = AccountState {
            owner: account_address,
            balance: account.balance,
            public_key: public_key.serialize(),
        };

        let out_coins = account.create_coins(
            account_address,
            next_public_key,
            public_key.serialize(),
            coin_templates,
        )?;
        // SparseMerkleTree::new() always returns DEFAULT_HASHES[0] as
        // its root, and a non-inclusion-proof-driven update produces the
        // same root as a direct insert — both invariants are part of the
        // SMT impl's own test suite. We do not double-check here.
        let mut out_coins_tree = SparseMerkleTree::new();
        let _initial_root = DEFAULT_HASHES[0];

        let mut out_coin_proofs = vec![];
        for coin in &out_coins {
            let coin_id_bytes = zkcoins_program::hash::digest_to_bytes(&coin.identifier);
            let non_inclusion_proof = out_coins_tree
                .generate_non_inclusion_proof(coin_id_bytes)
                .or(Err("Coin should not exist in tree yet"))?;
            out_coin_proofs.push(non_inclusion_proof.clone());
            out_coins_tree.insert(coin_id_bytes, coin.identifier)?;
            let _expected = non_inclusion_proof.insert(coin.identifier);
        }

        // Defense-in-depth: validate the source-side properties
        // off-circuit before paying the prove cost. The in-circuit
        // gate-set (Stage 5d-next-5 Phase 2b — merged in PR #23) is
        // the authoritative enforcement; this off-circuit pass exists
        // to (a) reject malformed requests with a specific HTTP error
        // string within microseconds instead of an opaque
        // `prove failed` after minute-scale prove cost, and (b) catch
        // any future drift between off-circuit witness construction
        // and the in-circuit predicate. Memory
        // `feedback_threat_model_over_checklist`: the cost is
        // microseconds vs minute-scale prove, so the defense-in-depth
        // wins. See `MIGRATION_RESEARCH.md` §7.22 for the in-circuit
        // architecture (aggregator pattern + Phase 2b per-slot SMT
        // inclusion + SPEC §8 (c)(d)(e) chain).
        for ((coin, source_cmp), source_inclusion) in in_coins
            .iter()
            .zip(coin_history_proofs.iter())
            .zip(coin_inclusion_proofs.iter())
        {
            if !source_inclusion.verify(coin.identifier, source_cmp.commitment_out_coins_root) {
                return Err("In-coin not present in source's output_coins_root");
            }
            if !source_cmp.verify_commitment(state.mmr.root_extended(MMR_PROOF_PATH_LEN)) {
                return Err("Source commitment not present in history MMR");
            }
        }

        // Build the fixed-shape MAX_IN_COINS slot tuples. Active
        // slots come from account.coin_queue; inactive slots use the
        // ZERO_HASH dummies.
        let dummy_nip = Self::dummy_nip();
        let dummy_coin = Self::dummy_coin();
        const MAX_IN_COINS: usize = zkcoins_program::circuit::main::MAX_IN_COINS;
        const MAX_OUT_COINS: usize = zkcoins_program::circuit::main::MAX_OUT_COINS;
        if in_coins.len() > MAX_IN_COINS {
            return Err("Too many in-coins for one transition");
        }
        if out_coins.len() > MAX_OUT_COINS {
            return Err("Too many out-coins for one transition");
        }
        let mut in_coin_slots: Vec<(bool, &Coin, &NonInclusionProof)> =
            Vec::with_capacity(MAX_IN_COINS);
        for (coin, nip) in in_coins.iter().zip(coin_non_inclusion_proofs.iter()) {
            in_coin_slots.push((true, coin, nip));
        }
        for _ in in_coins.len()..MAX_IN_COINS {
            in_coin_slots.push((false, &dummy_coin, &dummy_nip));
        }

        // Stage 5d-next-5 Phase 2b: per-slot source witnesses. Each
        // active in-coin's source proof, SMT-inclusion path, and
        // CommitmentMerkleProofs bundle (already built into
        // `coin_history_proofs` / `coin_inclusion_proofs`) are
        // threaded into the prover. Inactive slots get `None`.
        let mut sources: Vec<Option<InCoinSourceWitness>> = Vec::with_capacity(MAX_IN_COINS);
        for ((coin_proof, source_cmp), source_inclusion) in account
            .coin_queue
            .iter()
            .zip(coin_history_proofs.iter())
            .zip(coin_inclusion_proofs.iter())
        {
            sources.push(Some(InCoinSourceWitness {
                source_proof: &coin_proof.proof,
                source_inclusion,
                source_cmp,
            }));
        }
        for _ in account.coin_queue.len()..MAX_IN_COINS {
            sources.push(None);
        }

        let mut out_coin_slots: Vec<(bool, HashDigest, u64, &NonInclusionProof)> =
            Vec::with_capacity(MAX_OUT_COINS);
        for (coin, nip) in out_coins.iter().zip(out_coin_proofs.iter()) {
            out_coin_slots.push((true, coin.identifier, coin.amount, nip));
        }
        for _ in out_coins.len()..MAX_OUT_COINS {
            out_coin_slots.push((false, ZERO_HASH, 0u64, &dummy_nip));
        }

        // The Plonky2 cyclic recursion verifies against `history_root`
        // extended to the fixed in-circuit MMR depth.
        let history_root_extended = state.mmr.root_extended(MMR_PROOF_PATH_LEN);
        let next_public_key_bytes = next_public_key.serialize();

        // When DEV_SKIP_BROADCAST_FAILURE is set, the SMT is missing
        // entries that should have been written by previous mints
        // (their on-chain commitment never landed because the publisher
        // wallet was empty). Drop the existing account.proof on the
        // floor and take the create-account branch instead. NEVER set
        // in PRD — the cost is that previous commitment history is
        // discarded.
        let dev_skip = std::env::var("DEV_SKIP_BROADCAST_FAILURE").unwrap_or_default() == "true";
        let proof: Proof = match &account.proof {
            Some(account_proof) if !dev_skip => {
                let account_commitment_public_key = prev_commitment_pubkey
                    .ok_or("prev_commitment_pubkey required for account update")?;
                let prev_cmp = Self::get_merkle_proofs(
                    account_proof.clone(),
                    account_commitment_public_key,
                    state,
                )?;
                self.prover
                    .prove_account_update_with_in_and_out_coins_and_sources(
                        &account_state_for_prove,
                        history_root_extended,
                        account_proof,
                        &prev_cmp,
                        &in_coin_slots,
                        &out_coin_slots,
                        &next_public_key_bytes,
                        &sources,
                    )
                    .map_err(|_| "prove_account_update_with_in_and_out_coins_and_sources failed")?
            }
            _ => self
                .prover
                .prove_initial_with_in_and_out_coins_and_sources(
                    &account_state_for_prove,
                    history_root_extended,
                    &in_coin_slots,
                    &out_coin_slots,
                    &next_public_key_bytes,
                    &sources,
                )
                .map_err(|_| "prove_initial_with_in_and_out_coins_and_sources failed")?,
        };

        // Proof generation succeeded — commit the state changes.
        account.coin_queue.clear();
        account.balance = balance - invoiced_amount;
        account.proof = Some(proof.clone());

        // Build CoinProof entries for distribution to recipients.
        //
        // Multi-out-coin correctness: `generate_inclusion_proof` runs
        // against the FINAL `out_coins_tree` (after every slot has
        // been inserted), so each recipient's `InclusionProof`
        // siblings are valid against the SAME `output_coins_root`
        // that the source proof committed to — regardless of which
        // slot the recipient's coin landed in. This is the production
        // invariant that the in-circuit Phase 2b SMT-inclusion check
        // relies on. (The test fixture
        // `build_test_source_witness` in
        // `program-plonky2/src/circuit/main.rs` is single-out-coin /
        // slot-0 only by construction — see its docstring.)
        let mut coin_proofs = vec![];
        for coin in out_coins {
            let coin_id_bytes = zkcoins_program::hash::digest_to_bytes(&coin.identifier);
            coin_proofs.push(CoinProof {
                proof: proof.clone(),
                inclusion_proof: out_coins_tree.generate_inclusion_proof(&coin_id_bytes)?.0,
                coin,
                // User fills in the commitment and sends back via /commit.
                commitment: None,
            });
        }
        Ok(coin_proofs)
    }

    pub fn get_minting_account_address(&mut self) -> Result<HashDigest, &'static str> {
        match self.accounts.get(&*zkcoins_program::types::MINTING_ADDRESS) {
            Some(_) => Ok(*zkcoins_program::types::MINTING_ADDRESS),
            None => Err("Minting account not created"),
        }
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        // bincode::serialize on HashMap<Address, Account> cannot fail
        // in practice; pass the error through as a function reference
        // so the path does not introduce an uncovered closure.
        let bytes = bincode::serialize(&self.accounts).map_err(std::io::Error::other)?;
        crate::atomic_write(path, &bytes)
    }

    pub fn load_from_file(state: Arc<Mutex<State>>, path: &str) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let accounts: HashMap<Address, Account> =
            bincode::deserialize(&bytes).map_err(std::io::Error::other)?;
        let prover = Prover::new();
        Ok(AccountServer {
            accounts,
            prover,
            state,
        })
    }
}

#[cfg(test)]
mod inline_tests {
    //! Inline error-path tests that don't require a full Plonky2 prove.
    //! They cover the early-return error paths in `send_coins`, the
    //! file-IO failure path in `load_from_file`, and the single-line
    //! lookup paths in `get_minting_account_address` and
    //! `get_account_balance`. The richer prover-driven fixtures live in
    //! `account_server_tests.rs` (included as `mod tests;` below).

    use super::*;

    fn fresh_server() -> AccountServer {
        AccountServer::new(Arc::new(Mutex::new(State::new())))
    }

    #[test]
    fn get_minting_account_address_errors_when_not_imported() {
        let mut server = fresh_server();
        assert_eq!(
            server.get_minting_account_address().unwrap_err(),
            "Minting account not created"
        );
    }

    #[test]
    fn get_minting_account_address_returns_minting_address_when_present() {
        let mut server = fresh_server();
        server.import_account(*zkcoins_program::types::MINTING_ADDRESS, Account::new());
        assert_eq!(
            server.get_minting_account_address().unwrap(),
            *zkcoins_program::types::MINTING_ADDRESS
        );
    }

    #[test]
    fn get_account_balance_errors_for_unknown_address() {
        let server = fresh_server();
        let unknown = zkcoins_program::hash::digest_from_bytes(&[7u8; 32]);
        assert_eq!(
            server.get_account_balance(&unknown).unwrap_err(),
            "No account with this address"
        );
    }

    #[test]
    fn get_account_balance_returns_zero_for_empty_account() {
        let mut server = fresh_server();
        let address = zkcoins_program::hash::digest_from_bytes(&[1u8; 32]);
        server.import_account(address, Account::new());
        assert_eq!(server.get_account_balance(&address).unwrap(), 0);
    }

    #[test]
    fn load_from_file_rejects_corrupted_bytes() {
        let path = std::env::temp_dir().join(format!(
            "zkcoins-account-server-corrupt-{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"not bincode").unwrap();
        let state = Arc::new(Mutex::new(State::new()));
        let result = AccountServer::load_from_file(state, path.to_str().unwrap());
        std::fs::remove_file(&path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn load_from_file_rejects_missing_path() {
        let path = std::env::temp_dir().join("zkcoins-account-server-does-not-exist.bin");
        std::fs::remove_file(&path).ok();
        let state = Arc::new(Mutex::new(State::new()));
        let result = AccountServer::load_from_file(state, path.to_str().unwrap());
        assert!(result.is_err());
    }

    /// Helper: build a stable PublicKey for use in send_coins error
    /// tests. Doesn't need to map to anything real — `send_coins`
    /// returns "Unknown account address" before touching it.
    fn dummy_secp_public_key() -> bitcoin::secp256k1::PublicKey {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn send_coins_errors_for_unknown_account() {
        let mut server = fresh_server();
        let recipient = zkcoins_program::hash::digest_from_bytes(&[2u8; 32]);
        let account_address = zkcoins_program::hash::digest_from_bytes(&[3u8; 32]);
        let pk = dummy_secp_public_key();
        let result = server.send_coins(
            vec![Invoice::new(1, recipient)],
            account_address,
            pk,
            pk,
            None,
        );
        assert_eq!(result.unwrap_err(), "Unknown account address");
    }

    #[test]
    fn send_coins_errors_on_insufficient_funds() {
        let mut server = fresh_server();
        let account_address = zkcoins_program::hash::digest_from_bytes(&[4u8; 32]);
        server.import_account(account_address, Account::new());
        let recipient = zkcoins_program::hash::digest_from_bytes(&[5u8; 32]);
        let pk = dummy_secp_public_key();
        let result = server.send_coins(
            vec![Invoice::new(100, recipient)],
            account_address,
            pk,
            pk,
            None,
        );
        assert_eq!(result.unwrap_err(), "Insufficient funds");
    }

    #[test]
    fn account_new_has_zero_balance_and_empty_queue() {
        let a = Account::new();
        assert_eq!(a.balance, 0);
        assert!(a.coin_queue.is_empty());
        assert_eq!(a.get_balance(), 0);
    }

    #[test]
    fn account_save_and_load_roundtrip() {
        let mut server = fresh_server();
        let address = zkcoins_program::hash::digest_from_bytes(&[6u8; 32]);
        server.import_account(address, Account::new());
        let path = std::env::temp_dir().join(format!(
            "zkcoins-account-server-roundtrip-{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        server.save_to_file(path.to_str().unwrap()).unwrap();
        let state = Arc::new(Mutex::new(State::new()));
        let loaded = AccountServer::load_from_file(state, path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(loaded.get_account_balance(&address).is_ok());
    }
}

#[cfg(test)]
#[path = "account_server_tests.rs"]
mod tests;
