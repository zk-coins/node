use bitcoin::secp256k1::{
    self, schnorr::Signature, Keypair, Message, PublicKey, Secp256k1, SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zkcoins_program::merkle::HashDigest;

use crate::SECP256K1;

/// A commitment consisting of a public key, a Schnorr signature, and a message.
#[derive(Clone, Serialize, Deserialize)]
pub struct Commitment {
    /// The public key used to verify the signature
    pub public_key: PublicKey,
    /// The Schnorr signature over the message
    pub signature: Signature,
    /// The message that was signed
    pub message: Vec<u8>,
}

impl Commitment {
    /// Creates a new commitment by signing the provided message with the given private key
    pub fn new(secret_key: &SecretKey, message: Vec<u8>) -> Result<Self, secp256k1::Error> {
        // Hash the message only for the signature, but store the original message
        let msg_hash = if message.len() != 32 {
            let mut hasher = Sha256::new();
            hasher.update(&message);
            hasher.finalize().to_vec()
        } else {
            message.clone()
        };

        let msg = Message::from_digest_slice(&msg_hash)?;

        let keypair = Keypair::from_secret_key(&SECP256K1, secret_key);
        // Sign the message using Schnorr signature with the keypair
        let signature = SECP256K1.sign_schnorr_no_aux_rand(&msg, &keypair);

        Ok(Self {
            public_key: keypair.public_key(),
            signature,
            message, // Store the original message, not the hash
        })
    }

    /// Verifies that the signature is valid for the message using the public key
    pub fn verify(&self) -> bool {
        let secp = Secp256k1::new();

        // Hash the message for verification if needed
        let msg_hash = if self.message.len() != 32 {
            let mut hasher = Sha256::new();
            hasher.update(&self.message);
            hasher.finalize().to_vec()
        } else {
            self.message.clone()
        };

        match Message::from_digest_slice(&msg_hash) {
            Ok(msg) => {
                // Get the x-only public key for verification
                let x_only_pubkey = self.public_key.x_only_public_key().0;
                secp.verify_schnorr(&self.signature, &msg, &x_only_pubkey)
                    .is_ok()
            }
            Err(_) => false,
        }
    }

    pub fn get_account_state_hash(&self) -> HashDigest {
        let msg_hash = if self.message.len() != 32 {
            let mut hasher = Sha256::new();
            hasher.update(&self.message);
            hasher.finalize().to_vec()
        } else {
            self.message.clone()
        };
        let mut array = [0u8; 32];
        // This will panic if vec.len() < 32
        array.copy_from_slice(&msg_hash[..32]);
        array
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Commitment")
            .field("public_key", &self.public_key.to_string())
            .field("signature", &hex::encode(self.signature.as_ref()))
            .field("message", &hex::encode(&self.message))
            .finish()
    }
}
