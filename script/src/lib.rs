//! Stub prover for Docker builds without SP1 toolchain.
//! Mimics the SP1 API surface used by the server.

use serde::{Deserialize, Serialize};
pub use zkcoins_program::ProgramInputsBuilder;

/// Mock proof that mimics SP1ProofWithPublicValues.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub public_values: PublicValues,
}

/// Mock public values that mimics SP1PublicValues.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicValues {
    data: Vec<u8>,
}

impl PublicValues {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Mimics SP1PublicValues::read::<T>() — deserializes from the internal buffer.
    pub fn read<T: for<'de> Deserialize<'de>>(&self) -> T {
        bincode::deserialize(&self.data).expect("Failed to deserialize public values")
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }
}

pub struct Prover;

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover {
    pub fn new() -> Self {
        Prover
    }

    pub fn create_account(
        &self,
        _program_inputs_builder: &mut ProgramInputsBuilder,
        _coin_proofs: Vec<Proof>,
    ) -> Result<Proof, &'static str> {
        Ok(Proof {
            public_values: PublicValues::new(vec![0u8; 256]),
        })
    }

    pub fn update_account(
        &self,
        _program_inputs_builder: &mut ProgramInputsBuilder,
        _account_proof: Proof,
        _coin_proofs: Vec<Proof>,
    ) -> Result<Proof, &'static str> {
        Ok(Proof {
            public_values: PublicValues::new(vec![0u8; 256]),
        })
    }
}
