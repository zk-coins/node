//! Stub prover for Docker builds without SP1 toolchain.
//! All proof operations return mock data when SP1_PROVER=mock.

use serde::{Deserialize, Serialize};
use zkcoins_program::ProgramInputsBuilder;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub public_values: Vec<u8>,
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
            public_values: vec![0u8; 32],
        })
    }

    pub fn update_account(
        &self,
        _program_inputs_builder: &mut ProgramInputsBuilder,
        _account_proof: Proof,
        _coin_proofs: Vec<Proof>,
    ) -> Result<Proof, &'static str> {
        Ok(Proof {
            public_values: vec![0u8; 32],
        })
    }
}
