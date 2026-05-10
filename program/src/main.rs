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
    assert_eq!(account_state_hash, previous_proof_data.account_state_hash);
    assert_eq!(
        account_state_hash,
        merkle_proofs.commitment_account_state_hash
    );
    assert!(merkle_proofs.verify_commitment(commitment_history_root));
    assert!(merkle_proofs.verify_previous_root(
        previous_proof_data.commitment_history_root,
        commitment_history_root
    ));
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
    assert!(coin_proof.verify(coin.identifier, out_coin_root));
    assert_eq!(out_coin_root, merkle_proofs.commitment_out_coins_root);
    assert!(merkle_proofs.verify_commitment(commitment_history_root));
    assert!(merkle_proofs.verify_previous_root(
        coin_proof_data.commitment_history_root,
        commitment_history_root
    ));
}

pub fn main() {
    let hidden_inputs = sp1_zkvm::io::read::<ProgramInputs>();
    let vkey = hidden_inputs.verification_key;
    let mut account_state = hidden_inputs.account_state;
    let commitment_history_root = hidden_inputs.current_history_root;

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

    let mut coin_history_proofs = hidden_inputs.in_coin_proofs_history_proofs.into_iter();
    let mut non_inclusion_proofs = hidden_inputs
        .in_coin_proofs_non_inclusion_proofs
        .into_iter();
    let mut public_values = hidden_inputs.in_coin_proofs_public_values.into_iter();
    let mut inclusion_proofs = hidden_inputs.in_coins_inclusion_proofs.into_iter();
    for coin in &hidden_inputs.in_coins {
        verify_coin_proof(
            public_values
                .next()
                .expect("Missing coin proof public values"),
            vkey,
            coin_history_proofs
                .next()
                .expect("Missing coin proof history proofs"),
            commitment_history_root,
            coin,
            inclusion_proofs
                .next()
                .expect("Missing coin inclusion proof"),
        );
        let coin_non_inclusion_proof = non_inclusion_proofs
            .next()
            .expect("Missing non_inclusion_proofs");
        assert_eq!(coin_history_root, coin_non_inclusion_proof.root);
        coin_history_root = coin_non_inclusion_proof
            .verify_and_insert(coin.identifier)
            .expect("Coin was already integrated");
        account_state = account_state.apply_coin(coin).unwrap();
    }

    let output_coins_root = account_state
        .send_coins(
            hidden_inputs.out_coins,
            hidden_inputs.out_coin_proofs,
            hidden_inputs.next_public_key,
        )
        .unwrap();

    let commitment = ProofData {
        vk: vkey,
        account_state_hash: account_state.hash(),
        output_coins_root,
        commitment_history_root,
        coin_history_root,
    };
    sp1_zkvm::io::commit::<ProofData>(&commitment);
}
