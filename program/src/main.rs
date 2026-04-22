#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use zkcoins_program::merkle::sparse_merkle_tree::{InclusionProof, DEFAULT_HASHES};
use zkcoins_program::merkle::HashDigest;
use zkcoins_program::{AccountState, Coin, CommitmentMerkleProofs, ProofData, ProofType};
use zkcoins_program::{ProgramInputs, MINTING_ADDRESS};

fn verify_proof(public_values: Vec<u8>, vkey: [u32; 8]) -> ProofData {
    let previous_proof_data = bincode::deserialize::<ProofData>(&public_values)
        .expect("Unable to deserialize previous proof data");
    // Check that the previous proof was generated using the same circuit.
    assert_eq!(vkey, previous_proof_data.vk, "Verification keys not equal");
    let public_values_digest = Sha256::digest(public_values);
    sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &public_values_digest.into());
    previous_proof_data
}

fn verify_account_state_proof(
    account_state: &AccountState,
    public_values: Vec<u8>,
    vkey: [u32; 8],
    merkle_proofs: CommitmentMerkleProofs,
    commitment_history_root: HashDigest,
) -> HashDigest {
    let previous_proof_data = verify_proof(public_values, vkey);
    let account_state_hash = account_state.hash();
    assert_eq!(
        account_state_hash, previous_proof_data.account_state_hash,
        "Provided account state does not match hash."
    );

    assert_eq!(
        account_state_hash, merkle_proofs.commitment_account_state_hash,
        "Commitment Verification failed."
    );
    // Verify that the commitment is in the commitment tree.
    assert!(merkle_proofs.verify_commitment(
        commitment_history_root,
    ), "Incorrect merkle path for the inclusion of the account state hash in the commitmentment tree.");

    // Verify that the commitment root is in commitment root history.
    assert!(
        merkle_proofs.verify_previous_root(previous_proof_data.commitment_history_root, commitment_history_root),
        "Incorrect merkle path for the inclusion of the previous commitment history root in the current commitment history tree"
    );
    previous_proof_data.coin_history_root
}

fn verify_coin_proof(
    public_values: Vec<u8>,
    vkey: [u32; 8],
    merkle_proofs: CommitmentMerkleProofs,
    commitment_history_root: HashDigest,
    coin: &Coin,
    coin_proof: InclusionProof,
) {
    let coin_proof_data = verify_proof(public_values, vkey);
    let out_coin_root = coin_proof_data.output_coins_root;

    assert!(coin_proof.verify(coin.identifier, out_coin_root),
    "coin is not included in the provided proof's output_coins_root");

    // Verify that the commitment includes this out_coin_root. The account_state_hash part is
    // checked implicitely because each coin commits to the account_state_hash.
    assert_eq!(out_coin_root, merkle_proofs.commitment_out_coins_root, "Incorrect out_coin_root for the commitment");

    // Verify that the commitment is in the commitment tree.
    assert!(merkle_proofs.verify_commitment(
        commitment_history_root,
    ), "Incorrect merkle path for the inclusion of the coin identifier (the account state hash part) in the commitmentment tree.");

    // Verify that the commitment root is in commitment root history.
    assert!(
        merkle_proofs.verify_previous_root(coin_proof_data.commitment_history_root, commitment_history_root),
        "Incorrect merkle path for the inclusion of the coin's commitment history root in the current commitment history tree"
    );
}

pub fn main() {
    let hidden_inputs = sp1_zkvm::io::read::<ProgramInputs>();
    let vkey = hidden_inputs.verification_key;
    let mut account_state = hidden_inputs.account_state;
    let commitment_history_root = hidden_inputs.current_history_root;

    // Verify the account state.
    let mut coin_history_root = match hidden_inputs.proof_type {
        ProofType::AccountUpdateProof => verify_account_state_proof(
            &account_state,
            hidden_inputs
                .prev_proof_public_values
                .expect("Missing previous proofs public values"),
            vkey,
            hidden_inputs
                .prev_proof_history_proofs
                .expect("Missing previous proof's history proofs"),
            commitment_history_root,
        ),
        ProofType::InitialProof => {
            if account_state.owner != MINTING_ADDRESS {
                assert_eq!(account_state.balance, 0, "Starting balance has to be 0.")
            }
            DEFAULT_HASHES[0]
        }
    };

    // Verify coin proofs and apply them to the account state.
    let mut coin_history_proofs = hidden_inputs.in_coin_proofs_history_proofs.into_iter();
    let mut non_inclusion_proofs = hidden_inputs.in_coin_proofs_non_inclusion_proofs.into_iter();
    let mut public_values = hidden_inputs.in_coin_proofs_public_values.into_iter();
    let mut inclusion_proofs = hidden_inputs.in_coins_inclusion_proofs.into_iter();
    for coin in &hidden_inputs.in_coins {
        // Verify the coin's proof and inclusion in it's output_coins_root.
        verify_coin_proof(
            public_values.next().expect("Missing coin proof public values"),
            vkey,
            coin_history_proofs
                .next()
                .expect("Missing coin proof history proofs"),
            commitment_history_root,
            coin,
            inclusion_proofs.next().expect("Missing coin inclusion proof"),
        );

        // Check that we didn't integrate this coin already in our history.
        let coin_non_inclusion_proof = non_inclusion_proofs
            .next()
            .expect("Missing coin proof non_inclusion_proofs");
        assert_eq!(
            coin_history_root, coin_non_inclusion_proof.root,
            "Non inclusion proof provided has a different root than expected"
        );
        coin_history_root = coin_non_inclusion_proof
            .verify_and_insert(coin.identifier)
            .expect("Coin was already integrated");
        account_state = account_state.apply_coin(coin).unwrap();
    }

    // Apply out coins and update public key.
    let output_coins_root = account_state.send_coins(
        hidden_inputs.out_coins,
        hidden_inputs.out_coin_proofs,
        hidden_inputs.next_public_key
    ).unwrap();

    // Commit to the verification key, new account_state_hash, coin and history roots.
    let commitment = ProofData {
        vk: vkey,
        account_state_hash: account_state.hash(),
        output_coins_root,
        commitment_history_root,
        coin_history_root
    };
    sp1_zkvm::io::commit::<ProofData>(&commitment);
}
