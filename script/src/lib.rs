use sp1_sdk::{
    include_elf, EnvProver, HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};

use zkcoins_program::ProofType;
use zkcoins_program::{ProgramInputs, ProgramInputsBuilder};

pub const ZKCOINS_ELF: &[u8] = include_elf!("zkcoins-program");

pub type Proof = SP1ProofWithPublicValues;

pub struct Prover {
    pub client: EnvProver,
    pub pk: SP1ProvingKey,
    pub vk: SP1VerifyingKey,
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover {
    pub fn new() -> Self {
        // Initialize the proving client.
        let client = ProverClient::from_env();

        // Setup the logger.
        sp1_sdk::utils::setup_logger();
        // Setup the proving and verifying keys.
        let (pk, vk) = client.setup(ZKCOINS_ELF);
        Prover { client, pk, vk }
    }

    /// Used for sending the first time.
    pub fn create_account(
        &self,
        program_inputs_builder: &mut ProgramInputsBuilder,
        coin_proofs: Vec<SP1ProofWithPublicValues>,
    ) -> Result<SP1ProofWithPublicValues, &'static str> {
        let mut stdin = SP1Stdin::new();
        let program_inputs = match program_inputs_builder.in_coin_proofs_public_values(
            coin_proofs.iter().map(|proof| proof.public_values.to_vec()).collect::<Vec<_>>(),
        ).proof_type(ProofType::InitialProof).verification_key(self.vk.vk.hash_u32()).build() {
            Ok(fields) => fields,
            Err(_) => return Err("didnt provide all fields")
        };
        stdin.write::<ProgramInputs>(&program_inputs);
        for proof in coin_proofs {
            let SP1Proof::Compressed(proof) = proof.proof else {
                return Err("Proof doesnt match Compressed(SP1ReduceProof)");
            };
            stdin.write_proof(*proof, self.vk.vk.clone());
        }

        tracing::info_span!("FIRST_SEND").in_scope(|| {
            // Generate the compressed proof.
            match self.client.prove(&self.pk, &stdin).compressed().run() {
                Ok(proof) => Ok(proof),
                Err(_) => Err("proving failed")
            }
        })
    }

    pub fn update_account(
        &self,
        program_inputs_builder: &mut ProgramInputsBuilder,
        account_proof: SP1ProofWithPublicValues,
        coin_proofs: Vec<SP1ProofWithPublicValues>,
    ) -> Result<SP1ProofWithPublicValues, &'static str> {
        let mut stdin = SP1Stdin::new();
        let program_inputs = {
            let result = program_inputs_builder.in_coin_proofs_public_values(
                coin_proofs
                    .iter()
                    .map(|proof| proof.public_values.to_vec())
                    .collect::<Vec<_>>(),
            ).prev_proof_public_values(Some(account_proof.public_values.to_vec())).
                proof_type(ProofType::InitialProof).verification_key(self.vk.vk.hash_u32()).build();
            if let Err(_) = result {
                return Err("didnt provide all fields");
            }
            result.unwrap()
        };
        stdin.write::<ProgramInputs>(&program_inputs);
        // Write the account proof
        let SP1Proof::Compressed(proof) = account_proof.proof else {
            return Err("account proof doesnt match Compressed(SP1ReduceProof)");
        };
        stdin.write_proof(*proof, self.vk.vk.clone());
        // Write coin proofs
        for proof in coin_proofs {
            let SP1Proof::Compressed(proof) = proof.proof else {
                return Err("Coin proof doesnt match Compressed(SP1ReduceProof)");
            };
            stdin.write_proof(*proof, self.vk.vk.clone());
        }

        tracing::info_span!("UPDATE_SEND").in_scope(|| {
            // Generate the compressed proof.
            match self.client.prove(&self.pk, &stdin).compressed().run() {
                Ok(proof) => Ok(proof),
                Err(_) => Err("proving failed")
            }
        })
    }
}
