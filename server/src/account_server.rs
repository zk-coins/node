use std::sync::{Arc, Mutex, MutexGuard};
use std::collections::HashMap;

use crate::state::State;
use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::PublicKey;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use shared::commitment::Commitment;
use shared::{Address, Invoice};
use zkcoins_program::merkle::sparse_merkle_tree::{
    InclusionProof, SparseMerkleTree, DEFAULT_HASHES,
};
use zkcoins_program::merkle::{hash_concat, HashDigest};
use zkcoins_program::{
    calculate_coin_identifier, AccountState, Amount, Coin, CoinTemplate, CommitmentMerkleProofs,
    ProgramInputsBuilder, ProofData, ProofType,
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
        public_key: zkcoins_program::PublicKey,
        coin_templates: Vec<CoinTemplate>,
    ) -> Result<Vec<Coin>, &'static str> {
        let mut next_account_state = AccountState {
            owner: address,
            balance: self.get_balance(),
            public_key,
        };
        for coin_template in &coin_templates {
            // Apply all coins.
            next_account_state.balance = match next_account_state.balance.checked_sub(coin_template.amount) {
                Some(balance) => balance,
                None => return Err("Balance too small to create Coin. This should have been checked beforehand and is a bug :(")
            };
        }

        let next_account_state_hash = next_account_state.hash();
        let coins = coin_templates.into_iter().enumerate().map(|(i, template)| {
            Coin::new(
                template,
                calculate_coin_identifier(next_account_state_hash, i as u32),
            )
        });
        // Set the next public key.
        next_account_state.public_key = next_public_key.serialize().to_vec();
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
    // TODO: Move to client.
    /// Get the keypair to the pubkey this account commited to (which is derived key num_pubkeys -
    /// 1)

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

    pub fn get_addresses(&self) -> Vec<Address> {
        self.accounts.keys().cloned().collect::<Vec<Address>>()
    }

    pub fn receive_coin(&mut self, coin_proof: CoinProof) -> Result<(), &'static str> {
        // Deserialze proof data
        let proof_data = coin_proof.proof.public_values.clone().read::<ProofData>();

        // Verify the inclusion of the coin in the proof.
        // TODO: Return an err and also verify the proof verification itself. (Dry-run the
        // aggregation)
        // TODO: Verify that the commitment was not included in our state.
        coin_proof
            .inclusion_proof
            .verify(coin_proof.coin.identifier, proof_data.output_coins_root);

        println!("Receiving coin for address: {:?}", coin_proof.coin.recipient);
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
        if account.coin_queue.iter().any(|cp| cp.coin.identifier == coin_id) {
            return Err("Coin already in queue (duplicate)");
        }
        if account.coin_history.generate_inclusion_proof(&coin_id).is_ok() {
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
        mut previous_proof: Proof,
        public_key: PublicKey,
        state: &MutexGuard<'_, State>,
    ) -> Result<CommitmentMerkleProofs, &'static str> {
        let account_merkle_proofs = state
            .get_commitment_proof(&public_key)
            .map_err(|_| "Unable to get merkle proofs for provided public key")?;

        let proof_data = previous_proof.public_values.read::<ProofData>();
        let previous_root = proof_data.commitment_history_root;
        let previous_root_proof = state
            .get_mmr_inclusion_proof(previous_root)
            .map_err(|_| "Unable to get mmr inclusion proof for the previous root")?;

        if hash_concat(
            &proof_data.account_state_hash,
            &proof_data.output_coins_root,
        ) != account_merkle_proofs.0
        {
            return Err("Commitment is not hash(hash(account_state) || out_coins_root)");
        }

        let proofs = CommitmentMerkleProofs {
            commitment_root: account_merkle_proofs.2,
            commitment_proof: account_merkle_proofs.1,
            commitment_root_history_proof: account_merkle_proofs.3,
            commitment_root_mmr_sibling: state.prev_mmr_root,
            previous_root_history_proof: previous_root_proof,
            commitment_account_state_hash: proof_data.account_state_hash,
            commitment_out_coins_root: proof_data.output_coins_root,
        };

        if !proofs.verify_previous_root(previous_root, state.mmr.root()) {
            return Err("Previous root history proof verification failed.");
        }
        Ok(proofs)
    }

    pub fn send_coins(
        &mut self,
        invoices: Vec<Invoice>,
        account_address: Address,
        public_key: PublicKey,
        next_public_key: PublicKey,
    ) -> Result<Vec<CoinProof>, &'static str> {
        let state = &self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Check if the account balance is enough
        let balance = self.get_account_balance(&account_address)?;
        let invoiced_amount = invoices.iter().fold(0, |acc, x| acc + x.amount);
        if balance < invoiced_amount {
            return Err("Insufficient funds");
        }

        let account = match self.accounts.get_mut(&account_address) {
            Some(account) => account,
            None => return Err("Unknown account address"),
        };

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
            coin_non_inclusion_proofs.push({
                account
                    .coin_history
                    .generate_non_inclusion_proof(coin_proof.coin.identifier)
                    .map_err(|_| "Should provide an inclusion proof")?
            });
            coin_inclusion_proofs.push(coin_proof.inclusion_proof.clone());
            in_coins.push(coin_proof.coin.clone());
            account
                .coin_history
                .insert(coin_proof.coin.identifier, coin_proof.coin.identifier)
                .map_err(|_| "Coin should not exist in coin history tree")?;
        }
        let mut proof_hints_builder = ProgramInputsBuilder::default();
        let proof_hints_builder = proof_hints_builder
            .account_state(AccountState {
                owner: account_address,
                balance: account.balance,
                public_key: public_key.serialize().to_vec(),
            })
            .next_public_key(next_public_key.clone().serialize().to_vec())
            // Create the coin. (In case of multiple coins adjust AccountState.create_coin to apply
            // all coin templates first and then create the identifier from the final account
            // state.)
            .in_coins(in_coins)
            .in_coins_inclusion_proofs(coin_inclusion_proofs)
            .in_coin_proofs_history_proofs(coin_history_proofs)
            .in_coin_proofs_non_inclusion_proofs(coin_non_inclusion_proofs)
            .current_history_root(state.mmr.root());

        let out_coins = account.create_coins(
            account_address,
            next_public_key,
            public_key.serialize().to_vec(),
            coin_templates,
        )?;
        let mut out_coins_tree = SparseMerkleTree::new();
        let mut current_root = DEFAULT_HASHES[0];
        if current_root != out_coins_tree.root() {
            return Err("Empty tree has an unexpected root.");
        }

        let mut out_coin_proofs = vec![];
        for coin in &out_coins {
            let non_inclusion_proof = out_coins_tree
                .generate_non_inclusion_proof(coin.identifier)
                .map_err(|_| "Coin should not exist in tree yet")?;
            out_coin_proofs.push(non_inclusion_proof.clone());
            out_coins_tree.insert(coin.identifier, coin.identifier)?;
            current_root = non_inclusion_proof.insert(coin.identifier)?;
            if current_root != out_coins_tree.root() {
                return Err(
                    "Roots deviate after inserting manually and updating with non_inclusion_proof",
                );
            }
        }

        let proof_hints_builder = proof_hints_builder
            .out_coins(out_coins.clone())
            .out_coin_proofs(out_coin_proofs);

        let received_proofs: Vec<_> = account.coin_queue
            .iter()
            .map(|x| x.proof.clone())
            .collect();

        let proof = match &account.proof {
            Some(account_proof) => {
                let account_commitment_public_key = public_key;
                let merkle_proofs = Self::get_merkle_proofs(
                    account_proof.clone(),
                    account_commitment_public_key,
                    state,
                )?;
                proof_hints_builder.prev_proof_history_proofs(Some(merkle_proofs));
                proof_hints_builder.proof_type(ProofType::AccountUpdateProof);
                self.prover
                    .update_account(proof_hints_builder, account_proof.clone(), received_proofs)?
            }
            None => self
                .prover
                .create_account(proof_hints_builder, received_proofs)?,
        };

        // Proof generation succeeded — now commit the state changes.
        // coin_queue and proof were read non-destructively above,
        // so the account is unchanged if we got an error before this point.
        account.coin_queue.clear();
        account.balance = balance - invoiced_amount;
        account.proof = Some(proof.clone());
        let public_values = bincode::deserialize::<ProofData>(&proof.public_values.to_vec())
            .map_err(|_| "Failed to deserialize proof public values")?;
        if public_values.output_coins_root != out_coins_tree.root() {
            return Err(
                "The simulated out_coins_tree root does not match the commited output_coins_root",
            );
        }

        // Create the coin_proofs to be distributed to recipients
        let mut coin_proofs = vec![];
        for coin in out_coins {
            coin_proofs.push(CoinProof {
                proof: proof.clone(),
                inclusion_proof: out_coins_tree.generate_inclusion_proof(&coin.identifier)?.0,
                coin,
                // User will fill in the commitment and send back this proof to the server.
                commitment: None,
            });
        }

        Ok(coin_proofs)
    }

    pub fn get_minting_account_address(&mut self) -> Result<HashDigest, &'static str> {
        match self.accounts.get(&zkcoins_program::MINTING_ADDRESS) {
            Some(_) => Ok(zkcoins_program::MINTING_ADDRESS),
            None => Err("Minting account not created"),
        }
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let bytes = bincode::serialize(&self.accounts)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        crate::atomic_write(path, &bytes)
    }

    pub fn load_from_file(state: Arc<Mutex<State>>, path: &str) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let accounts: HashMap<Address, Account> = bincode::deserialize(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let prover = Prover::new();
        Ok(AccountServer {
            accounts,
            prover,
            state,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use zkcoins_program::hash;

    use super::*;
    use crate::state::State;
    use bitcoin::{
        bip32::{ChildNumber, Xpriv, Xpub},
        key::Secp256k1,
        secp256k1::{All, PublicKey as BitcoinPublicKey, SecretKey},
        Network,
    };
    use lazy_static::lazy_static;
    use shared::{commitment::Commitment, ProofData};
    use zkcoins_program::MINTING_ADDRESS;

    lazy_static! {
        static ref SECP256K1_TEST_CTX: Secp256k1<All> = Secp256k1::new();
    }

    // Fixed seed for deterministic address generation in tests for generic accounts
    const TEST_ACCOUNT_RANDOM_SEED_FOR_ADDRESS: [u8; 32] = [1u8; 32];

    fn generate_test_public_key(private_key: &Xpriv, index: u32) -> BitcoinPublicKey {
        Xpub::from_priv(&SECP256K1_TEST_CTX, private_key)
            .derive_pub(&SECP256K1_TEST_CTX, &[ChildNumber::Normal { index }])
            .expect("Failed to derive public key for test")
            .public_key
    }

    fn derive_test_secret_key(private_key: &Xpriv, index: u32) -> SecretKey {
        private_key
            .derive_priv(&SECP256K1_TEST_CTX, &[ChildNumber::Normal { index }])
            .expect("Unable to derive private key for test")
            .private_key
    }

    struct TestAccountData {
        xpriv: Xpriv,
        address: Address,
        num_pubkeys: u32,
    }

    impl TestAccountData {
        fn new_minting_account() -> Self {
            let secret = include_bytes!("../minting_secret.bin");
            let xpriv = Xpriv::new_master(Network::Bitcoin, secret)
                .expect("Failed to create private key for minting account.");

            TestAccountData {
                xpriv,
                address: MINTING_ADDRESS,
                num_pubkeys: 0,
            }
        }

        fn new_generic(seed: &[u8; 32], network: Network) -> Self {
            let xpriv = Xpriv::new_master(network, seed)
                .expect("Failed to create private key for generic account.");

            let initial_pk_bytes = generate_test_public_key(&xpriv, 0).serialize().to_vec();
            let address = zkcoins_program::hash(&initial_pk_bytes);

            TestAccountData {
                xpriv,
                address,
                num_pubkeys: 0,
            }
        }

        fn execute_send_coins(
            &mut self,
            server: &mut AccountServer,
            invoices: Vec<Invoice>,
        ) -> Result<Vec<CoinProof>, String> {
            let current_pk = generate_test_public_key(&self.xpriv, self.num_pubkeys);
            let next_pk = generate_test_public_key(&self.xpriv, self.num_pubkeys + 1);

            let mut coin_proofs = server.send_coins(invoices, self.address, current_pk, next_pk)?;

            // The key used for the commitment corresponds to current_pk
            let signing_secret_key = derive_test_secret_key(&self.xpriv, self.num_pubkeys);

            self.num_pubkeys += 1; // Increment after deriving signing key for current op, before it's used for next op

            for cp in &mut coin_proofs {
                let proof_data =
                    bincode::deserialize::<ProofData>(&cp.proof.public_values.to_vec())
                        .expect("ProofData deserialization failed in test");
                let commitment_hash_input = zkcoins_program::merkle::hash_concat(
                    &proof_data.account_state_hash,
                    &proof_data.output_coins_root,
                );
                cp.commitment = Some(
                    Commitment::new(&signing_secret_key, commitment_hash_input.to_vec())
                        .expect("Failed to create commitment for coin proof in test"),
                );
            }
            Ok(coin_proofs)
        }
    }

    #[test]
    fn test_wallet_operations() {
        let state_arc = Arc::new(Mutex::new(State::new()));
        let mut server = AccountServer::new(Arc::clone(&state_arc));

        let mut minting_account_data = TestAccountData::new_minting_account();
        println!(
            "minting account address: {:?}",
            minting_account_data.address
        );
        server.import_account(
            minting_account_data.address,
            Account {
                proof: None,
                coin_queue: vec![],
                coin_history: SparseMerkleTree::new(),
                balance: 10_000,
            },
        );
        assert_eq!(
            MINTING_ADDRESS,
            server.get_minting_account_address().unwrap(),
            "Minting address in server and program are different"
        );

        let mut account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
        let mut account_2_data = TestAccountData::new_generic(&[2u8; 32], Network::Signet);

        assert_eq!(
            server.get_account_balance(&MINTING_ADDRESS).unwrap(),
            10_000
        );
        assert!(server.get_account_balance(&account_1_data.address).is_err());
        assert!(server.get_account_balance(&account_2_data.address).is_err());

        // Note: Invoices use addresses.
        let account_2_invoice = Invoice::new(100, account_2_data.address);
        let account_1_invoice = Invoice::new(100, account_1_data.address);

        let mut coin_proofs = minting_account_data
            .execute_send_coins(
                &mut server,
                vec![account_2_invoice.clone(), account_1_invoice.clone()],
            )
            .unwrap();

        state_arc
            .lock()
            .unwrap()
            .update(
                &coin_proofs
                    .iter()
                    .map(|x| x.commitment.clone().unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        server
            .receive_coin(coin_proofs.pop().unwrap()) // Order might matter if tied to invoice order
            .expect("Unable to receive coin for account_1_invoice"); // Assuming account_1_invoice was last in vec or order doesn't strictly map here
        server
            .receive_coin(coin_proofs.pop().unwrap())
            .expect("Unable to receive coin for account_2_invoice");

        assert_eq!(
            server.get_account_balance(&account_1_data.address).unwrap(),
            100
        );
        assert_eq!(
            server.get_account_balance(&account_2_data.address).unwrap(),
            100
        );
        println!("Minting successful");

        let mut coin_proofs_from_acc2 = account_2_data
            .execute_send_coins(&mut server, vec![account_1_invoice.clone()]) // account_2 sends to account_1
            .expect("Unable to send coin from account_2");

        state_arc
            .lock()
            .unwrap()
            .update(
                &coin_proofs_from_acc2
                    .iter()
                    .map(|x| x.commitment.clone().unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        // Balances before receiving the new coin by account_1
        assert_eq!(
            server.get_account_balance(&account_1_data.address).unwrap(),
            100
        );
        assert_eq!(
            server.get_account_balance(&account_2_data.address).unwrap(),
            0
        ); // account_2's balance reduced after send

        server
            .receive_coin(coin_proofs_from_acc2.pop().unwrap())
            .expect("Unable to receive coin by account_1 from account_2");
        assert_eq!(
            server.get_account_balance(&account_1_data.address).unwrap(),
            200
        );
        assert_eq!(
            server.get_account_balance(&account_2_data.address).unwrap(),
            0
        );

        // Send with timer
        let start_time = Instant::now();
        let mut coin_proofs_from_acc1 = account_1_data
            .execute_send_coins(&mut server, vec![account_2_invoice.clone()]) // account_1 sends to account_2
            .expect("Unable to send coin from account_1");
        let duration = start_time.elapsed();

        state_arc
            .lock()
            .unwrap()
            .update(
                &coin_proofs_from_acc1
                    .iter()
                    .map(|x| x.commitment.clone().unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        println!("TIME ELAPSED FOR ONE RECURSIVE SEND: {:?}", duration);
        server
            .receive_coin(coin_proofs_from_acc1.pop().unwrap())
            .expect("Unable to receive coin by account_2 from account_1");
        assert_eq!(
            server.get_account_balance(&account_1_data.address).unwrap(),
            100
        ); // 200 - 100
        assert_eq!(
            server.get_account_balance(&account_2_data.address).unwrap(),
            100
        ); // 0 + 100
    }

    #[test]
    fn test_create_minting_account() {
        let state_arc = Arc::new(Mutex::new(State::new()));
        let mut server = AccountServer::new(state_arc);

        let minting_account_data = TestAccountData::new_minting_account();
        println!(
            "minting account address: {:?}",
            minting_account_data.address
        );

        server.import_account(
            minting_account_data.address, // This is MINTING_ADDRESS
            Account {
                proof: None,
                coin_queue: vec![],
                coin_history: SparseMerkleTree::new(),
                balance: 10_000,
            },
        );
        assert_eq!(
            server.get_minting_account_address().unwrap(),
            MINTING_ADDRESS,
            "Minting address is not stored in server correctly."
        );
        assert_eq!(
            server.get_account_balance(&MINTING_ADDRESS).unwrap(),
            10_000
        );
    }

    #[test]
    fn test_mint_single_invoice() {
        let state_arc = Arc::new(Mutex::new(State::new()));
        let mut server = AccountServer::new(Arc::clone(&state_arc));

        let mut minting_account_data = TestAccountData::new_minting_account();
        server.import_account(
            minting_account_data.address,
            Account {
                proof: None,
                coin_queue: vec![],
                coin_history: SparseMerkleTree::new(),
                balance: 10_000,
            },
        );

        let account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
        let invoice = Invoice::new(100, account_1_data.address);

        let coin_proofs = minting_account_data
            .execute_send_coins(&mut server, vec![invoice])
            .expect("Mint with single invoice failed");

        assert_eq!(coin_proofs.len(), 1);
    }

    /// Reproduces the exact configuration of /api/mint on the live DEV server:
    /// balance = u64::MAX, recipient = raw [1u8; 32] bytes, amount = 1.
    #[test]
    fn test_mint_repro_live_setup() {
        let state_arc = Arc::new(Mutex::new(State::new()));
        let mut server = AccountServer::new(Arc::clone(&state_arc));

        let mut minting_account_data = TestAccountData::new_minting_account();
        server.import_account(
            minting_account_data.address,
            Account {
                proof: None,
                coin_queue: vec![],
                coin_history: SparseMerkleTree::new(),
                balance: u64::MAX,
            },
        );

        let recipient: Address = [1u8; 32];
        let invoice = Invoice::new(1, recipient);

        let coin_proofs = minting_account_data
            .execute_send_coins(&mut server, vec![invoice])
            .expect("Mint repro failed");

        assert_eq!(coin_proofs.len(), 1);
    }
}
