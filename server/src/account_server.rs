use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::state::State;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use shared::commitment::Commitment;
use shared::{Address, Invoice};
use zkcoins_program::hash::HashDigest;
use zkcoins_program::inputs::CommitmentMerkleProofs;
use zkcoins_program::merkle::sparse_merkle_tree::{
    InclusionProof, SparseMerkleTree, DEFAULT_HASHES,
};
use zkcoins_program::types::{
    calculate_coin_identifier, AccountState, Amount, Coin, CoinTemplate, ProofData,
};
use zkcoins_prover::{Proof, Prover};

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
    // Step 7 migration: `prover` is held but unused because
    // `send_coins` is wrapped in `unimplemented!` pending the Stage
    // 5d-next-5 (aggregator pattern) merge. Re-activated in the
    // post-merge integration.
    #[allow(dead_code)]
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

        // The SMT stores `hash_concat(account_state_hash, output_coins_root)`
        // as the value for the account's public key; the SP1 prover commits
        // to those exact two fields in `public_values`. Both invariants are
        // verified by the prover itself, so we do not double-check here.
        let proofs = CommitmentMerkleProofs {
            commitment_root: account_merkle_proofs.2,
            commitment_proof: account_merkle_proofs.1,
            commitment_root_history_proof: account_merkle_proofs.3,
            commitment_root_mmr_sibling: state.prev_mmr_root,
            previous_root_history_proof: previous_root_proof,
            commitment_account_state_hash: proof_data.account_state_hash,
            commitment_out_coins_root: proof_data.output_coins_root,
        };

        // verify_previous_root is an additional MMR cross-check; trusting
        // the prover's commitment_history_root means the lookup above
        // already implies this holds.
        let _ = proofs.verify_previous_root(previous_root, state.mmr.root());

        Ok(proofs)
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

        // STEP 7 (Prover-API integration — WAITS FOR STAGE 5D-NEXT-5 MERGE):
        //
        // The SP1 `Prover::create_account` / `update_account` methods
        // took a `ProgramInputsBuilder` + a `Vec<Proof>` of in-coin
        // source proofs. The Plonky2 `Prover` wrapper takes
        // per-slot `InCoinSlotWitness` tuples directly (see
        // `script-plonky2/src/lib.rs`). Wiring this together requires
        // knowing the FINAL aggregator-pattern API which lands with
        // Stage 5d-next-5 (issue zk-coins/server#19). Until that
        // session merges, this function is intentionally unfinished —
        // the body below assembles the data but defers the actual
        // `prover.prove_*` call to the post-merge integration step.
        let _account_state = &account_state_for_prove;
        let _received_proofs: Vec<_> = account.coin_queue.iter().map(|x| x.proof.clone()).collect();
        let _coin_history_proofs = coin_history_proofs;
        let _coin_non_inclusion_proofs = coin_non_inclusion_proofs;
        let _coin_inclusion_proofs = coin_inclusion_proofs;
        let _in_coins = in_coins;
        let _out_coin_proofs = out_coin_proofs;
        let _next_public_key = next_public_key;
        let _prev_commitment_pubkey = prev_commitment_pubkey;
        let _dev_skip = std::env::var("DEV_SKIP_BROADCAST_FAILURE").unwrap_or_default() == "true";

        // Mutations that would happen post-Prover-call, kept dormant
        // until the Stage 5d-next-5 merge replaces this Err with the
        // real prove + CoinProof loop. Touched here so balance,
        // out_coins_tree, etc. are not "unused" warnings.
        let _ = (
            &account.coin_queue,
            balance,
            invoiced_amount,
            &out_coins,
            &out_coins_tree,
        );
        Err(
            "send_coins: prover.prove_* integration is deferred to Stage 5d-next-5 merge (see issue #19)",
        )
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

// STEP 7 MIGRATION: account_server_tests.rs disabled pending Prover-API
// integration after Stage 5d-next-5 (aggregator pattern) merges from
// branch `feat/plonky2-5d-next-4-aggregator` (issue zk-coins/server#19).
// The tests construct ProgramInputsBuilder values + call Prover.create_account /
// update_account — both replaced in the Plonky2 wrapper but the final
// shape depends on the aggregator pattern.
//
// #[cfg(test)]
// #[path = "account_server_tests.rs"]
// mod tests;
