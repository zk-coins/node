use std::time::Instant;

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
use zkcoins_program::hash::{
    digest_from_bytes, digest_to_bytes, hash_bytes, hash_concat, ZERO_HASH,
};
use zkcoins_program::types::MINTING_ADDRESS;

lazy_static! {
    static ref SECP256K1_TEST_CTX: Secp256k1<All> = Secp256k1::new();
}

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
            address: *MINTING_ADDRESS,
            num_pubkeys: 0,
        }
    }

    fn new_generic(seed: &[u8; 32], network: Network) -> Self {
        let xpriv = Xpriv::new_master(network, seed)
            .expect("Failed to create private key for generic account.");

        let initial_pk_bytes = generate_test_public_key(&xpriv, 0).serialize().to_vec();
        let address = hash_bytes(&initial_pk_bytes);

        TestAccountData {
            xpriv,
            address,
            num_pubkeys: 0,
        }
    }

    fn execute_send_coins(
        &mut self,
        node: &mut AccountNode,
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
            node.send_coins(invoices, self.address, current_pk, next_pk, prev_pk)?;

        // The key used for the commitment corresponds to current_pk
        let signing_secret_key = derive_test_secret_key(&self.xpriv, self.num_pubkeys);

        self.num_pubkeys += 1; // Increment after deriving signing key for current op, before it's used for next op

        for cp in &mut coin_proofs {
            // Plonky2 bridge: SP1's `proof.public_values: Vec<u8>` (bincode
            // blob) is replaced by `proof.public_inputs: Vec<F>` (Goldilocks
            // field elements). The first
            // `N_PROOF_DATA_PUBLIC_INPUTS = 16` slots reconstruct `ProofData`.
            let pis: [zkcoins_program::F;
                zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] = cp
                .proof
                .public_inputs[..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
                .try_into()
                .expect("Proof public_inputs too short");
            let proof_data = ProofData::from_field_elements(&pis);
            let commitment_hash_input = hash_concat(
                &proof_data.account_state_hash,
                &proof_data.output_coins_root,
            );
            cp.commitment = Some(
                Commitment::new(
                    &signing_secret_key,
                    digest_to_bytes(&commitment_hash_input).to_vec(),
                )
                .expect("Failed to create commitment for coin proof in test"),
            );
        }
        Ok(coin_proofs)
    }
}

#[test]
fn test_wallet_operations() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    node.import_account(
        minting_account_data.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );
    assert_eq!(
        *MINTING_ADDRESS,
        node.get_minting_account_address().unwrap(),
        "Minting address in node and program are different"
    );

    let mut account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
    let mut account_2_data = TestAccountData::new_generic(&[2u8; 32], Network::Signet);

    assert_eq!(node.get_account_balance(&MINTING_ADDRESS).unwrap(), 10_000);
    assert!(node.get_account_balance(&account_1_data.address).is_err());
    assert!(node.get_account_balance(&account_2_data.address).is_err());

    // Note: Invoices use addresses.
    let account_2_invoice = Invoice::new(100, account_2_data.address);
    let account_1_invoice = Invoice::new(100, account_1_data.address);

    let mut coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![account_2_invoice, account_1_invoice])
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

    node.receive_coin(coin_proofs.pop().unwrap()) // Order might matter if tied to invoice order
        .expect("Unable to receive coin for account_1_invoice"); // Assuming account_1_invoice was last in vec or order doesn't strictly map here
    node.receive_coin(coin_proofs.pop().unwrap())
        .expect("Unable to receive coin for account_2_invoice");

    assert_eq!(
        node.get_account_balance(&account_1_data.address).unwrap(),
        100
    );
    assert_eq!(
        node.get_account_balance(&account_2_data.address).unwrap(),
        100
    );
    println!("Minting successful");

    let mut coin_proofs_from_acc2 = account_2_data
        .execute_send_coins(&mut node, vec![account_1_invoice]) // account_2 sends to account_1
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
        node.get_account_balance(&account_1_data.address).unwrap(),
        100
    );
    assert_eq!(
        node.get_account_balance(&account_2_data.address).unwrap(),
        0
    ); // account_2's balance reduced after send

    node.receive_coin(coin_proofs_from_acc2.pop().unwrap())
        .expect("Unable to receive coin by account_1 from account_2");
    assert_eq!(
        node.get_account_balance(&account_1_data.address).unwrap(),
        200
    );
    assert_eq!(
        node.get_account_balance(&account_2_data.address).unwrap(),
        0
    );

    // Send with timer
    let start_time = Instant::now();
    let mut coin_proofs_from_acc1 = account_1_data
        .execute_send_coins(&mut node, vec![account_2_invoice]) // account_1 sends to account_2
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
    node.receive_coin(coin_proofs_from_acc1.pop().unwrap())
        .expect("Unable to receive coin by account_2 from account_1");
    assert_eq!(
        node.get_account_balance(&account_1_data.address).unwrap(),
        100
    ); // 200 - 100
    assert_eq!(
        node.get_account_balance(&account_2_data.address).unwrap(),
        100
    ); // 0 + 100
}

#[test]
fn test_create_minting_account() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(state_arc);

    let minting_account_data = TestAccountData::new_minting_account();

    node.import_account(
        minting_account_data.address, // This is MINTING_ADDRESS
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );
    assert_eq!(
        node.get_minting_account_address().unwrap(),
        *MINTING_ADDRESS,
        "Minting address is not stored in node correctly."
    );
    assert_eq!(node.get_account_balance(&MINTING_ADDRESS).unwrap(), 10_000);
}

#[test]
fn test_mint_single_invoice() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    node.import_account(
        minting_account_data.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
    let invoice = Invoice::new(100, account_1_data.address);

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("Mint with single invoice failed");

    assert_eq!(coin_proofs.len(), 1);
}

#[test]
fn test_receive_duplicate_coin_rejected() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    node.import_account(
        minting_account_data.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
    let invoice = Invoice::new(100, account_1_data.address);

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
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
    node.receive_coin(coin_proof)
        .expect("First receive should succeed");

    // Second receive of the same coin should be rejected
    let result = node.receive_coin(duplicate);
    assert!(result.is_err(), "Duplicate coin receive must be rejected");
}

#[test]
fn test_receive_updates_balance() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    node.import_account(
        minting_account_data.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
    let invoice = Invoice::new(250, account_1_data.address);

    // Balance should not exist before any receive
    assert!(
        node.get_account_balance(&account_1_data.address).is_err(),
        "Account should not exist before receiving coins"
    );

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
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
        node.receive_coin(cp).expect("Receive should succeed");
    }

    // Balance should reflect the received coin amount
    let balance = node
        .get_account_balance(&account_1_data.address)
        .expect("Account should exist after receive");
    assert_eq!(
        balance, 250,
        "Balance should equal the received coin amount"
    );
}

/// Reproduces the exact configuration of /api/mint on the live DEV node:
/// recipient = raw [1u8; 32] bytes, amount = 1.
#[test]
fn test_mint_repro_live_setup() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    node.import_account(
        minting_account_data.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 1_000_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let recipient: Address = digest_from_bytes(&[1u8; 32]);
    let invoice = Invoice::new(1, recipient);

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("Mint repro failed");

    assert_eq!(coin_proofs.len(), 1);
}

/// PR-A3 replacement for the previous file-based `save_and_load_roundtrip`:
/// persist an imported account via `persist_account` (the same helper
/// the handler sites call), then rebuild a fresh `AccountNode` via
/// `load_from_pg` and assert the imported account survived round-trip.
#[tokio::test]
async fn test_persist_and_load_from_pg_roundtrip() {
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = crate::db::connect_and_migrate(&url)
        .await
        .expect("connect_and_migrate failed");

    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let address: HashDigest = digest_from_bytes(&[42u8; 32]);
    let mut acct = Account::new();
    acct.balance = 11;
    node.import_account(address, acct);

    // Snapshot + upsert mirrors the handler-site pattern.
    let account_snapshot = node.get_account(&address).cloned_via_bincode();
    crate::account_node::persist_account(&pool, &address, &account_snapshot)
        .await
        .expect("persist_account ok");

    // Rebuild from PG and verify the row came back.
    let loaded = AccountNode::load_from_pg(state_arc, &pool)
        .await
        .expect("load_from_pg ok");
    assert_eq!(loaded.get_account_balance(&address).unwrap(), 11);
}

/// `Account` does not implement `Clone` (its inner Plonky2 proof types
/// are sealed). The test above only needs an owned copy for the
/// persistence call, so bounce it through bincode locally. Kept as a
/// trait extension to keep the test body readable without polluting
/// the production `Account` API.
trait CloneViaBincode {
    fn cloned_via_bincode(self) -> Account;
}

impl CloneViaBincode for Option<&Account> {
    fn cloned_via_bincode(self) -> Account {
        let a = self.expect("account present");
        let bytes = bincode::serialize(a).expect("serialize");
        bincode::deserialize(&bytes).expect("deserialize")
    }
}

#[test]
fn test_get_minting_account_address_returns_err_when_not_imported() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(state_arc);
    assert!(node.get_minting_account_address().is_err());
}

#[test]
fn test_get_account_balance_returns_err_for_unknown_address() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let node = AccountNode::new(state_arc);
    let unknown: Address = digest_from_bytes(&[7u8; 32]);
    assert!(node.get_account_balance(&unknown).is_err());
}

/// PR-A3 replacement for the previous `test_load_from_file_rejects_corrupted_bytes`:
/// plant a row whose `data` blob is not valid bincode and assert
/// `load_from_pg` surfaces the corruption as `LoadAccountNodeError
/// ::Deserialize` rather than panicking or silently dropping the row.
#[tokio::test]
async fn test_load_from_pg_rejects_corrupted_blob() {
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = crate::db::connect_and_migrate(&url)
        .await
        .expect("connect_and_migrate failed");

    let bad_addr = vec![0xAAu8; 32];
    sqlx::query("INSERT INTO accounts (address, data) VALUES ($1, $2)")
        .bind(&bad_addr)
        .bind(b"not bincode".to_vec())
        .execute(&pool)
        .await
        .unwrap();

    let state_arc = Arc::new(Mutex::new(State::new()));
    // `AccountNode` is intentionally not `Debug`, so `expect_err`
    // isn't available; match the Result instead.
    match AccountNode::load_from_pg(state_arc, &pool).await {
        Ok(_) => panic!("expected deserialize error"),
        Err(err) => assert!(
            matches!(
                err,
                crate::account_node::LoadAccountNodeError::Deserialize(_)
            ),
            "unexpected: {:?}",
            err
        ),
    }
}

/// PR-A3 negative test: plant a row whose `address` column is not the
/// expected 32 bytes and assert the loader surfaces the mismatch as
/// `LoadAccountNodeError::BadAddressLength`.
#[tokio::test]
async fn test_load_from_pg_rejects_wrong_address_length() {
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = crate::db::connect_and_migrate(&url)
        .await
        .expect("connect_and_migrate failed");

    // The 0010 CHECK constraint `accounts_address_length` would
    // otherwise reject the wrong-length row at insert time, masking
    // the actual subject of this test: the Rust-side
    // `LoadAccountNodeError::BadAddressLength` defense in
    // `load_from_pg`. Drop the constraint inside this per-test
    // container so the corrupt-row plant succeeds. The 0008
    // `accounts_history_trigger` would also fail on the matching
    // `account_history_address_length` CHECK if it fired against
    // the 7-byte address, so disable the trigger for this test —
    // we are not exercising the history path here.
    sqlx::query("ALTER TABLE accounts DISABLE TRIGGER accounts_history_trigger")
        .execute(&pool)
        .await
        .expect("disable accounts_history_trigger");
    sqlx::query("ALTER TABLE accounts DROP CONSTRAINT accounts_address_length")
        .execute(&pool)
        .await
        .expect("drop accounts_address_length");

    sqlx::query("INSERT INTO accounts (address, data) VALUES ($1, $2)")
        .bind(vec![0u8; 7]) // wrong length
        .bind(b"anything".to_vec())
        .execute(&pool)
        .await
        .unwrap();

    let state_arc = Arc::new(Mutex::new(State::new()));
    match AccountNode::load_from_pg(state_arc, &pool).await {
        Ok(_) => panic!("expected bad-address length"),
        Err(err) => assert!(
            matches!(
                err,
                crate::account_node::LoadAccountNodeError::BadAddressLength(7)
            ),
            "unexpected: {:?}",
            err
        ),
    }
}

#[test]
fn test_send_coins_returns_err_for_unknown_account() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(state_arc);
    let account_data = TestAccountData::new_generic(&[1u8; 32], Network::Bitcoin);

    let recipient: Address = digest_from_bytes(&[2u8; 32]);
    let invoice = Invoice::new(1, recipient);

    let current_pk = generate_test_public_key(&account_data.xpriv, 0);
    let next_pk = generate_test_public_key(&account_data.xpriv, 1);

    let result = node.send_coins(
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
    let mut node = AccountNode::new(state_arc);
    let account_data = TestAccountData::new_generic(&[1u8; 32], Network::Bitcoin);
    node.import_account(account_data.address, Account::new());

    let recipient: Address = digest_from_bytes(&[2u8; 32]);
    let invoice = Invoice::new(100, recipient);

    let current_pk = generate_test_public_key(&account_data.xpriv, 0);
    let next_pk = generate_test_public_key(&account_data.xpriv, 1);

    let result = node.send_coins(
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
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    node.import_account(
        minting_account_data.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let recipient: Address = digest_from_bytes(&[1u8; 32]);
    let invoice = Invoice::new(100, recipient);

    let mut coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("send_coins should succeed");

    // Tamper with the coin identifier so the existing inclusion proof
    // no longer verifies against it. receive_coin must reject.
    let mut coin_proof = coin_proofs.pop().unwrap();
    coin_proof.coin.identifier = digest_from_bytes(&[99u8; 32]);

    let result = node.receive_coin(coin_proof);
    assert_eq!(
        result.unwrap_err(),
        "Coin inclusion proof verification failed"
    );
}

#[test]
fn test_send_coins_twice_from_same_account_uses_update_account() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let recipient: Address = digest_from_bytes(&[42u8; 32]);

    // First send: account.proof is None -> create_account branch.
    let coin_proofs_1 = minting
        .execute_send_coins(&mut node, vec![Invoice::new(100, recipient)])
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
        .execute_send_coins(&mut node, vec![Invoice::new(50, recipient)])
        .expect("second send should succeed (update_account path)");
    assert_eq!(coin_proofs_2.len(), 1);

    // Invariant check: after two sends the three coupled fields are
    // all "updated" — `proof = Some`, `num_sends = 2`, and
    // `commitment_public_key = Some(pubkey_used_in_send_2)`. The
    // AccountUpdate branch reads this last value (not a caller
    // parameter) on the NEXT send, so its presence here is the
    // load-bearing post-condition.
    let acct = node
        .get_account(&minting.address)
        .expect("minting account still in map after send");
    assert!(
        acct.proof.is_some(),
        "account.proof must be Some after send"
    );
    assert_eq!(
        acct.num_sends, 2,
        "num_sends bumps once per successful send_coins_inner"
    );
    let expected_cpk =
        generate_test_public_key(&minting.xpriv, minting.num_pubkeys.saturating_sub(1));
    assert_eq!(
        acct.commitment_public_key,
        Some(expected_cpk),
        "commitment_public_key holds the pubkey used in the most recent send"
    );
}

/// Regression: a second `send_coins` from an account whose
/// `account.proof = Some(...)` MUST succeed when the caller passes
/// `None` for `prev_commitment_pubkey` — the AccountUpdate branch
/// reads `account.commitment_public_key` from its own state instead
/// of consulting the caller-supplied parameter. Pre-refactor this
/// returned the 400-mapped error
/// `"prev_commitment_pubkey required for account update"`.
///
/// Live-server analogue is the api_remote test
/// `second_send_succeeds_without_prev_commitment_pubkey_field` —
/// this one drives the same code path through `account_node` directly
/// (no prover, no HTTP) so the contract is pinned even when the
/// `api_remote` suite is skipped (slim CI).
#[test]
fn test_send_coins_second_send_succeeds_without_prev_commitment_pubkey() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let recipient: Address = digest_from_bytes(&[43u8; 32]);

    // First send: account.proof is None -> prove_initial branch.
    // The caller-supplied prev_commitment_pubkey is ignored on this
    // branch (it's only consulted on the AccountUpdate branch, and
    // post-refactor not even there); pass None to make that explicit.
    let coin_proofs_1 = minting
        .execute_send_coins(&mut node, vec![Invoice::new(100, recipient)])
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

    // Second send WITHOUT prev_commitment_pubkey. Pre-refactor this
    // returned `"prev_commitment_pubkey required for account update"`
    // and was mapped to 400 by `map_send_coins_error`. Post-refactor
    // the AccountUpdate branch reads `account.commitment_public_key`
    // (set atomically in the first send) and the prove succeeds.
    let current_pk = generate_test_public_key(&minting.xpriv, minting.num_pubkeys);
    let next_pk = generate_test_public_key(&minting.xpriv, minting.num_pubkeys + 1);
    let coin_proofs_2 = node
        .send_coins(
            vec![Invoice::new(50, recipient)],
            minting.address,
            current_pk,
            next_pk,
            None, // <-- the contract under test: prev_commitment_pubkey omitted
        )
        .expect("second send must succeed without prev_commitment_pubkey");
    assert_eq!(coin_proofs_2.len(), 1);

    let acct = node
        .get_account(&minting.address)
        .expect("minting account still in map after send");
    assert_eq!(acct.num_sends, 2);
    assert_eq!(acct.commitment_public_key, Some(current_pk));
}

/// Regression pinning the exact in-process state-machine shape the
/// failing api_remote test
/// `second_send_succeeds_without_prev_commitment_pubkey_field` /
/// app E2E `07-send-success` exercise: mint → recipient sends →
/// commit → mint AGAIN to the SAME recipient → recipient sends again.
///
/// The differentiator from
/// `test_send_coins_twice_from_same_account_uses_update_account` is
/// the SECOND mint into the sender's account between her first and
/// second send. That changes the second send's witness shape because
/// the sender now has both `account.proof = Some(send_1.proof)` AND a
/// freshly-received in-coin in her queue whose source proof
/// references a MORE-RECENT MMR root than `account.proof` does.
///
/// This unit test passes locally (the off-circuit witness assembly
/// produces a Plonky2-valid input) — the failing api_remote / E2E
/// tests must therefore be hitting a path that differs only in
/// effects this unit test cannot reach: scanner timing, MMR state
/// after dozens of other tests' commits, or a deeper in-circuit
/// constraint that activates only at a larger MMR depth. The
/// regression here documents that as long as the local state machine
/// is the only thing under test, the AccountUpdate branch with a
/// mint-2-sourced in-coin proves successfully — so any future change
/// that breaks that shape lands as a test failure here rather than
/// as a silent live-server regression.
#[test]
fn test_send_after_mint_receive_into_account_with_existing_proof() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let mut alice = TestAccountData::new_generic(&[7u8; 32], Network::Signet);
    let bob: Address = digest_from_bytes(&[8u8; 32]);

    // ---- Mint #1: minting -> alice (100). Alice receives.
    let mint1 = minting
        .execute_send_coins(&mut node, vec![Invoice::new(100, alice.address)])
        .expect("mint #1 should succeed");
    state_arc
        .lock()
        .unwrap()
        .update(
            &mint1
                .iter()
                .map(|cp| cp.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    for cp in mint1 {
        node.receive_coin(cp).expect("alice receives mint #1");
    }

    // ---- Alice's first send: alice -> bob (40). prove_initial branch.
    let send1 = alice
        .execute_send_coins(&mut node, vec![Invoice::new(40, bob)])
        .expect("alice send #1 should succeed");
    state_arc
        .lock()
        .unwrap()
        .update(
            &send1
                .iter()
                .map(|cp| cp.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();

    // Sanity: alice has proof=Some + cpk=Some + num_sends=1 now.
    {
        let a = node
            .get_account(&alice.address)
            .expect("alice account in map");
        assert!(a.proof.is_some(), "alice.proof must be Some after send #1");
        assert_eq!(a.num_sends, 1);
        assert!(a.commitment_public_key.is_some());
    }

    // ---- Mint #2: minting -> alice (100). Alice receives ON TOP of
    // her existing proof. This is the differentiator from the
    // currently-passing `_twice_from_same_account_uses_update_account`
    // test, and matches the api_remote / app `07-send-success`
    // sequence exactly.
    let mint2 = minting
        .execute_send_coins(&mut node, vec![Invoice::new(100, alice.address)])
        .expect("mint #2 should succeed");
    state_arc
        .lock()
        .unwrap()
        .update(
            &mint2
                .iter()
                .map(|cp| cp.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    for cp in mint2 {
        node.receive_coin(cp).expect("alice receives mint #2");
    }

    // ---- Alice's second send: prove_account_update branch with a
    // freshly-received in-coin from mint #2. This is the path the
    // live server takes on /api/send #2 and is the one that 500's
    // with "prove failed" against DEV.
    let send2 = alice
        .execute_send_coins(&mut node, vec![Invoice::new(30, bob)])
        .expect("alice send #2 must succeed (prove_account_update with new in-coin from mint #2)");
    assert_eq!(send2.len(), 1);

    // Post-conditions: all three coupled fields advanced together.
    let a = node
        .get_account(&alice.address)
        .expect("alice still in map");
    assert!(a.proof.is_some());
    assert_eq!(a.num_sends, 2);
    let expected_cpk = generate_test_public_key(&alice.xpriv, alice.num_pubkeys.saturating_sub(1));
    assert_eq!(a.commitment_public_key, Some(expected_cpk));
}

#[test]
fn test_receive_coin_rejects_replay_via_coin_history() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );
    let recipient: Address = digest_from_bytes(&[9u8; 32]);
    let coin_proofs = minting
        .execute_send_coins(&mut node, vec![Invoice::new(50, recipient)])
        .unwrap();
    let coin_proof = coin_proofs[0].clone();
    let coin_id = coin_proof.coin.identifier;

    // First receive — succeeds, coin lands in the recipient's coin_queue.
    node.receive_coin(coin_proof.clone()).unwrap();

    // Simulate the recipient having spent the coin: identifier goes
    // from coin_queue into coin_history.
    {
        let recipient_account = node.accounts.get_mut(&recipient).unwrap();
        recipient_account
            .coin_history
            .insert(digest_to_bytes(&coin_id), coin_id)
            .unwrap();
        recipient_account
            .coin_queue
            .retain(|cp| cp.coin.identifier != coin_id);
    }

    // Replay: receiving the same coin again must be rejected via the
    // coin_history check rather than the coin_queue check.
    let result = node.receive_coin(coin_proof);
    assert_eq!(result.unwrap_err(), "Coin already spent (replay)");
}

/// Stage 5d-next-5 Phase 2b negative regression: an in-coin whose
/// off-circuit `source_inclusion` siblings have been tampered with
/// must NOT make it to the prover. The defense-in-depth shim in
/// `send_coins` fast-fails with the documented error string;
/// without the shim the in-circuit SMT-inclusion check would still
/// reject, but only after a minute-scale prove.
///
/// Construction: do a real mint → recipient receive flow so that
/// the recipient's `account.coin_queue[0]` carries an HONEST
/// `inclusion_proof` produced by `out_coins_tree.generate_inclusion_proof`.
/// Then reach into the node's internal `accounts` map and flip
/// one sibling on the queued entry's `inclusion_proof`. The next
/// `send_coins` call from that recipient must surface the
/// "In-coin not present in source's output_coins_root" error.
#[test]
fn test_send_coins_rejects_tampered_source_proof_inclusion() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    // Real recipient with a deterministic seed; pin the address so
    // we can reach back into `node.accounts` after `receive_coin`.
    let recipient_data = TestAccountData::new_generic(&[42u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    // Mint emits one coin to the recipient — honest end-to-end flow,
    // so the `inclusion_proof` returned in `CoinProof` is well-formed
    // by construction.
    let mut coin_proofs = minting
        .execute_send_coins(&mut node, vec![Invoice::new(100, recipient_addr)])
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");

    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    // Tamper the queued `inclusion_proof.siblings[0]` directly on the
    // node's internal `accounts` map. The honest off-circuit
    // `source_inclusion.verify` walks the path siblings; flipping
    // the topmost sibling produces a recomputed root that doesn't
    // match the source's committed `output_coins_root`.
    {
        let account = node
            .accounts
            .get_mut(&recipient_addr)
            .expect("recipient account present after receive_coin");
        assert_eq!(
            account.coin_queue.len(),
            1,
            "recipient has exactly one queued in-coin after a single mint"
        );
        account.coin_queue[0].inclusion_proof.siblings[0] = hash_bytes(b"tampered-sibling");
    }

    // The defense-in-depth off-circuit pre-check fires before the
    // expensive prove and surfaces the specific rejection string.
    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(1, digest_from_bytes(&[99u8; 32]))],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(
        result.unwrap_err(),
        "In-coin not present in source's output_coins_root",
        "tampered source-inclusion siblings must surface the off-circuit defense-in-depth rejection"
    );
}

/// Slot-count guard: `invoices.len() > MAX_OUT_COINS` fires at the
/// top of `send_coins` before the heavy in-coin loop and prove cost.
/// Empty account + (`MAX_OUT_COINS + 1`) invoices triggers it
/// without paying a prove.
#[test]
fn test_send_coins_rejects_too_many_invoices() {
    use zkcoins_program::circuit::main::MAX_OUT_COINS;
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));
    let minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 1_000_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let invoices: Vec<Invoice> = (0..(MAX_OUT_COINS + 1) as u8)
        .map(|i| Invoice::new(1, digest_from_bytes(&[i; 32])))
        .collect();

    let current_pk = generate_test_public_key(&minting.xpriv, minting.num_pubkeys);
    let next_pk = generate_test_public_key(&minting.xpriv, minting.num_pubkeys + 1);
    let result = node.send_coins(invoices, minting.address, current_pk, next_pk, None);
    assert_eq!(result.unwrap_err(), "Too many out-coins for one transition");
}

/// Slot-count guard: `account.coin_queue.len() > MAX_IN_COINS` fires
/// at the top of `send_coins` before the heavy in-coin loop and
/// prove cost. We mint one coin honestly (one Init prove), then
/// clone it `MAX_IN_COINS + 1` times into the recipient's
/// `coin_queue` and confirm send_coins fails fast.
#[test]
fn test_send_coins_rejects_too_many_coins_in_queue() {
    use zkcoins_program::circuit::main::MAX_IN_COINS;
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );
    let recipient_data = TestAccountData::new_generic(&[20u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    // One honest mint produces one valid CoinProof we can clone.
    let mut coin_proofs = minting
        .execute_send_coins(&mut node, vec![Invoice::new(100, recipient_addr)])
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");

    let cp = coin_proofs.pop().expect("at least one coin");
    node.receive_coin(cp.clone())
        .expect("recipient receive_coin");

    // Force `coin_queue.len()` past the budget by cloning the single
    // honest entry. The slot-count guard fires before any siblings
    // are walked or any prove is attempted, so the clones being
    // identical doesn't matter.
    {
        let account = node
            .accounts
            .get_mut(&recipient_addr)
            .expect("recipient account present after receive_coin");
        for _ in 0..MAX_IN_COINS {
            account.coin_queue.push(cp.clone());
        }
        assert!(
            account.coin_queue.len() > MAX_IN_COINS,
            "test fixture must overflow the in-coin slot budget"
        );
    }

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(1, digest_from_bytes(&[99u8; 32]))],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(result.unwrap_err(), "Too many in-coins for one transition");
}

/// In-coin loop: a queued `CoinProof` whose `commitment.public_key`
/// is not registered in `state.commitment_proofs` makes
/// `get_merkle_proofs` return its "Unable to get merkle proofs..."
/// error string. Set up by minting → receiving WITHOUT calling
/// `state.update` first, so the recipient's queue entry references a
/// commitment public_key the state never indexed.
#[test]
fn test_send_coins_errors_when_state_lacks_commitment_for_in_coin() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );
    let recipient_data = TestAccountData::new_generic(&[21u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    let mut coin_proofs = minting
        .execute_send_coins(&mut node, vec![Invoice::new(75, recipient_addr)])
        .expect("mint send_coins");
    // Intentionally SKIP `state_arc.update(...)` — state never sees
    // the minting account's commitment, so get_merkle_proofs cannot
    // look up the commitment proof on the recipient's send_coins call.
    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(1, digest_from_bytes(&[99u8; 32]))],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(
        result.unwrap_err(),
        "Unable to get merkle proofs for provided public key"
    );
}

/// AccountUpdate branch: when `account.proof = Some(...)` and the
/// account's stored `commitment_public_key` is for a commitment that
/// the state's commitment-proof index does not contain, the second
/// call to `get_merkle_proofs` (inside the AccountUpdate-prove
/// preparation) surfaces "Unable to get merkle proofs..." just like
/// the in-coin loop's call. Set up via one honest mint + receive +
/// state.update; then forge an `account.proof = Some(...)` plus a
/// `commitment_public_key` that is fresh and not indexed in the SMT.
///
/// As of the `Account::commitment_public_key` refactor the
/// AccountUpdate branch reads the previous commitment pubkey from the
/// account itself (not from a caller-supplied parameter), so the test
/// drives the failure through that field.
#[test]
fn test_send_coins_errors_when_state_lacks_commitment_for_prev_account_proof() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );
    let recipient_data = TestAccountData::new_generic(&[22u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    let mut coin_proofs = minting
        .execute_send_coins(&mut node, vec![Invoice::new(50, recipient_addr)])
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");
    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    // Forge an `account.proof = Some(...)` on the recipient by reusing
    // the minting account's proof we just produced (signature
    // verification doesn't happen on this path — `get_merkle_proofs`
    // only consults state for the commitment-pubkey lookup).
    //
    // To drive the "Unable to get merkle proofs..." error path we
    // also set the recipient's `commitment_public_key` to a fresh,
    // never-indexed pubkey. Post-refactor the AccountUpdate branch
    // reads THIS field (not a caller parameter) for the lookup, so
    // the unknown pubkey lives on the account itself.
    let stranger_seed = Xpriv::new_master(Network::Signet, &[99u8; 32]).expect("stranger xpriv");
    let unknown_commitment_pk = generate_test_public_key(&stranger_seed, 0);
    {
        let mint_account = node
            .accounts
            .get_mut(&minting.address)
            .expect("minting account present");
        let proof = mint_account.proof.clone();
        let recipient_account = node
            .accounts
            .get_mut(&recipient_addr)
            .expect("recipient account present after receive_coin");
        recipient_account.proof = proof;
        // Maintain the invariant documented on `Account`:
        // `proof.is_some() iff num_sends > 0 iff
        // commitment_public_key.is_some()`. Forging only `proof`
        // would leave an inconsistent shape that the balance handler
        // would mis-emit AND that the AccountUpdate branch would
        // panic on (the field's `expect` guards the invariant).
        recipient_account.num_sends = 1;
        recipient_account.commitment_public_key = Some(unknown_commitment_pk);
    }

    // Caller-supplied `prev_commitment_pubkey` is ignored by the
    // post-refactor server — pass `None` here to make that explicit.
    // The AccountUpdate branch reads the recipient's stored
    // `commitment_public_key` (the stranger pubkey installed above),
    // hits the SMT lookup miss, and surfaces "Unable to get merkle
    // proofs...". The HTTP mapping in `map_send_coins_error`
    // translates this to 422 (caller-fixable).
    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(1, digest_from_bytes(&[99u8; 32]))],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(
        result.unwrap_err(),
        "Unable to get merkle proofs for provided public key"
    );
}

#[test]
fn test_send_coins_rejects_coin_queue_entry_without_commitment() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );
    let recipient: Address = digest_from_bytes(&[10u8; 32]);
    let coin_proofs = minting
        .execute_send_coins(&mut node, vec![Invoice::new(50, recipient)])
        .unwrap();
    let mut coin_proof = coin_proofs[0].clone();
    // Strip the commitment so the next send attempt from the recipient
    // hits the "Coin is missing commitment" branch.
    coin_proof.commitment = None;

    node.receive_coin(coin_proof).unwrap();

    let mut recipient_data = TestAccountData::new_generic(&[10u8; 32], bitcoin::Network::Signet);
    // Force the test data to use the same address as the recipient.
    recipient_data.address = recipient;

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(1, digest_from_bytes(&[11u8; 32]))],
        recipient_data.address,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(result.unwrap_err(), "Coin is missing commitment");
}

/// In-coin loop: when the off-circuit pre-check at
/// `account_node.rs:419` rebuilds a source `CommitmentMerkleProofs`
/// whose `commitment_root_mmr_sibling` does not match the actual
/// MMR leaf for that source, `verify_commitment` returns false and
/// `send_coins` surfaces "Source commitment not present in history
/// MMR". This is the companion of
/// `test_send_coins_rejects_tampered_source_proof_inclusion`: it
/// closes the line-419 error branch the way the inclusion-proof
/// test closes the line-416 branch, and it is the off-circuit
/// defense-in-depth analogue of the in-circuit history-MMR check.
///
/// Construction: honest mint → `state.update` → recipient
/// `receive_coin`, so the recipient's `coin_queue[0]` carries a
/// well-formed `inclusion_proof` (line 416 passes) and the source
/// commitment is genuinely indexed in `state.smt` / `state.mmr`
/// (line-241 `get_mmr_inclusion_proof` lookup succeeds). Then
/// overwrite `state.prev_mmr_root` with `ZERO_HASH` directly. The
/// `get_merkle_proofs` builder reads that field verbatim into
/// `commitment_root_mmr_sibling`, so the source CMP recomputes a
/// leaf `hash_concat(commitment_root, ZERO_HASH)` that does not
/// appear in `state.mmr`. The genuine MMR proof is still threaded
/// through, so the recomputed root mismatches the actual history
/// root and only the MMR half of `verify_commitment` rejects —
/// leaving the line-416 SMT-out_coins-inclusion path untouched,
/// which is exactly the branch line 419 is meant to gate.
#[test]
fn test_send_coins_rejects_source_commitment_missing_from_history_mmr() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    node.import_account(
        minting.address,
        Account {
            proof: None,
            coin_queue: vec![],
            coin_history: SparseMerkleTree::new(),
            balance: 10_000,
            num_sends: 0,
            commitment_public_key: None,
        },
    );

    let recipient_data = TestAccountData::new_generic(&[43u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    let mut coin_proofs = minting
        .execute_send_coins(&mut node, vec![Invoice::new(100, recipient_addr)])
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");

    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    // Desync `state.prev_mmr_root` from the actual history-MMR
    // leaf. `get_merkle_proofs` writes this verbatim into source
    // CMP's `commitment_root_mmr_sibling`, so the off-circuit
    // `verify_commitment_root` recomputes a leaf that doesn't
    // appear in `state.mmr` — without touching the out-coins SMT
    // inclusion path that line 416 gates.
    {
        let mut state = state_arc.lock().unwrap();
        state.prev_mmr_root = ZERO_HASH;
    }

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(1, digest_from_bytes(&[99u8; 32]))],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(
        result.unwrap_err(),
        "Source commitment not present in history MMR",
        "desynced `state.prev_mmr_root` must surface the off-circuit history-MMR rejection at account_node.rs:419",
    );
}

#[test]
fn log_prove_account_update_failure_emits_label_and_logs_chain() {
    // The helper exists purely to surface the plonky2 anyhow chain on
    // stderr (operator visibility via `docker logs`) while keeping the
    // caller-facing wire body at the static
    // `"prove_account_update_with_in_and_out_coins_and_sources failed"`
    // label that `map_send_coins_error` collapses to 500 "prove failed".
    //
    // The label assertion pins that contract; the stderr line is a
    // side-effect we cannot directly observe in-process, but its
    // existence keeps the line statement-covered for the gate.
    let label = super::log_prove_account_update_failure(anyhow::anyhow!("plonky2-rejected"));
    assert_eq!(
        label,
        "prove_account_update_with_in_and_out_coins_and_sources failed"
    );
}

#[test]
fn log_prove_initial_failure_emits_label_and_logs_chain() {
    // Mirror of `log_prove_account_update_failure_emits_label_and_logs_chain`
    // for the AccountCreation branch.
    let label = super::log_prove_initial_failure(anyhow::anyhow!("plonky2-rejected"));
    assert_eq!(
        label,
        "prove_initial_with_in_and_out_coins_and_sources failed"
    );
}
