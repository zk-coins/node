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
use zkcoins_program::types::MINTING_ADDRESS;

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
        let prev_pk = if self.num_pubkeys > 0 {
            Some(generate_test_public_key(&self.xpriv, self.num_pubkeys - 1))
        } else {
            None
        };

        let mut coin_proofs =
            server.send_coins(invoices, self.address, current_pk, next_pk, prev_pk)?;

        // The key used for the commitment corresponds to current_pk
        let signing_secret_key = derive_test_secret_key(&self.xpriv, self.num_pubkeys);

        self.num_pubkeys += 1; // Increment after deriving signing key for current op, before it's used for next op

        for cp in &mut coin_proofs {
            let proof_data = bincode::deserialize::<ProofData>(&cp.proof.public_values.to_vec())
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

#[test]
fn test_receive_duplicate_coin_rejected() {
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
        .expect("Mint failed");

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

    let coin_proof = coin_proofs.into_iter().next().unwrap();
    let duplicate = coin_proof.clone();

    // First receive should succeed
    server
        .receive_coin(coin_proof)
        .expect("First receive should succeed");

    // Second receive of the same coin should be rejected
    let result = server.receive_coin(duplicate);
    assert!(result.is_err(), "Duplicate coin receive must be rejected");
}

#[test]
fn test_receive_updates_balance() {
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
    let invoice = Invoice::new(250, account_1_data.address);

    // Balance should not exist before any receive
    assert!(
        server.get_account_balance(&account_1_data.address).is_err(),
        "Account should not exist before receiving coins"
    );

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut server, vec![invoice])
        .expect("Mint failed");

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

    for cp in coin_proofs {
        server.receive_coin(cp).expect("Receive should succeed");
    }

    // Balance should reflect the received coin amount
    let balance = server
        .get_account_balance(&account_1_data.address)
        .expect("Account should exist after receive");
    assert_eq!(
        balance, 250,
        "Balance should equal the received coin amount"
    );
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

#[test]
fn test_save_and_load_roundtrip() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut server = AccountServer::new(Arc::clone(&state_arc));

    let address: HashDigest = [42u8; 32];
    server.import_account(address, Account::new());

    let path = std::env::temp_dir().join(format!(
        "zkcoins-account-server-test-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    server.save_to_file(path.to_str().unwrap()).unwrap();

    let loaded = AccountServer::load_from_file(state_arc, path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.get_account_balance(&address).unwrap(), 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn test_get_minting_account_address_returns_err_when_not_imported() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut server = AccountServer::new(state_arc);
    assert!(server.get_minting_account_address().is_err());
}

#[test]
fn test_get_account_balance_returns_err_for_unknown_address() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let server = AccountServer::new(state_arc);
    let unknown: Address = [7u8; 32];
    assert!(server.get_account_balance(&unknown).is_err());
}

#[test]
fn test_load_from_file_rejects_corrupted_bytes() {
    let path = std::env::temp_dir().join(format!(
        "zkcoins-account-server-corrupt-{}.bin",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, b"not bincode").unwrap();
    let state_arc = Arc::new(Mutex::new(State::new()));
    let result = AccountServer::load_from_file(state_arc, path.to_str().unwrap());
    assert!(result.is_err());
    std::fs::remove_file(&path).ok();
}

#[test]
fn test_send_coins_returns_err_for_unknown_account() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut server = AccountServer::new(state_arc);
    let account_data = TestAccountData::new_generic(&[1u8; 32], Network::Bitcoin);

    let recipient: Address = [2u8; 32];
    let invoice = Invoice::new(1, recipient);

    let current_pk = generate_test_public_key(&account_data.xpriv, 0);
    let next_pk = generate_test_public_key(&account_data.xpriv, 1);

    let result = server.send_coins(
        vec![invoice],
        account_data.address,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(result.unwrap_err(), "Unknown account address");
}

#[test]
fn test_send_coins_returns_err_insufficient_funds() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut server = AccountServer::new(state_arc);
    let account_data = TestAccountData::new_generic(&[1u8; 32], Network::Bitcoin);
    server.import_account(account_data.address, Account::new());

    let recipient: Address = [2u8; 32];
    let invoice = Invoice::new(100, recipient);

    let current_pk = generate_test_public_key(&account_data.xpriv, 0);
    let next_pk = generate_test_public_key(&account_data.xpriv, 1);

    let result = server.send_coins(
        vec![invoice],
        account_data.address,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(result.unwrap_err(), "Insufficient funds");
}

#[test]
fn test_receive_coin_rejects_invalid_inclusion_proof() {
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

    let recipient: Address = [1u8; 32];
    let invoice = Invoice::new(100, recipient);

    let mut coin_proofs = minting_account_data
        .execute_send_coins(&mut server, vec![invoice])
        .expect("send_coins should succeed");

    // Tamper with the coin identifier so the existing inclusion proof
    // no longer verifies against it. receive_coin must reject.
    let mut coin_proof = coin_proofs.pop().unwrap();
    coin_proof.coin.identifier = [99u8; 32];

    let result = server.receive_coin(coin_proof);
    assert_eq!(
        result.unwrap_err(),
        "Coin inclusion proof verification failed"
    );
}

#[test]
fn test_send_coins_twice_from_same_account_uses_update_account() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut server = AccountServer::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    server.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
        },
    );

    let recipient: Address = [42u8; 32];

    // First send: account.proof is None -> create_account branch.
    let coin_proofs_1 = minting
        .execute_send_coins(&mut server, vec![Invoice::new(100, recipient)])
        .expect("first send should succeed");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs_1
                .iter()
                .map(|cp| cp.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();

    // After the first send, account.proof = Some. A second send from the
    // same account must therefore take the AccountUpdateProof branch
    // (update_account, not create_account).
    let coin_proofs_2 = minting
        .execute_send_coins(&mut server, vec![Invoice::new(50, recipient)])
        .expect("second send should succeed (update_account path)");
    assert_eq!(coin_proofs_2.len(), 1);
}

#[test]
fn test_receive_coin_rejects_replay_via_coin_history() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut server = AccountServer::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    server.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
        },
    );
    let recipient: Address = [9u8; 32];
    let coin_proofs = minting
        .execute_send_coins(&mut server, vec![Invoice::new(50, recipient)])
        .unwrap();
    let coin_proof = coin_proofs[0].clone();
    let coin_id = coin_proof.coin.identifier;

    // First receive — succeeds, coin lands in the recipient's coin_queue.
    server.receive_coin(coin_proof.clone()).unwrap();

    // Simulate the recipient having spent the coin: identifier goes
    // from coin_queue into coin_history.
    {
        let recipient_account = server.accounts.get_mut(&recipient).unwrap();
        recipient_account
            .coin_history
            .insert(coin_id, coin_id)
            .unwrap();
        recipient_account
            .coin_queue
            .retain(|cp| cp.coin.identifier != coin_id);
    }

    // Replay: receiving the same coin again must be rejected via the
    // coin_history check rather than the coin_queue check.
    let result = server.receive_coin(coin_proof);
    assert_eq!(result.unwrap_err(), "Coin already spent (replay)");
}

#[test]
fn test_send_coins_rejects_coin_queue_entry_without_commitment() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut server = AccountServer::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    server.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
        },
    );
    let recipient: Address = [10u8; 32];
    let coin_proofs = minting
        .execute_send_coins(&mut server, vec![Invoice::new(50, recipient)])
        .unwrap();
    let mut coin_proof = coin_proofs[0].clone();
    // Strip the commitment so the next send attempt from the recipient
    // hits the "Coin is missing commitment" branch.
    coin_proof.commitment = None;

    server.receive_coin(coin_proof).unwrap();

    let mut recipient_data = TestAccountData::new_generic(&[10u8; 32], bitcoin::Network::Signet);
    // Force the test data to use the same address as the recipient.
    recipient_data.address = recipient;

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = server.send_coins(
        vec![Invoice::new(1, [11u8; 32])],
        recipient_data.address,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(result.unwrap_err(), "Coin is missing commitment");
}
