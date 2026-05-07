use bitcoin::{
    bip32::{ChildNumber, Xpriv, Xpub},
    key::{
        rand::{rngs::OsRng, RngCore},
        Secp256k1,
    },
    secp256k1::{All, PublicKey, SecretKey},
    Network,
};
use commitment::Commitment;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use zkcoins_program::{
    merkle::{hash_concat, HashDigest},
    AccountState, Amount,
};

pub mod commitment;
pub use zkcoins_program::ProofData;

lazy_static! {
    pub static ref SECP256K1: Secp256k1<All> = Secp256k1::new();
}

pub type Address = HashDigest;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Invoice {
    pub amount: Amount,
    pub recipient: Address,
}

impl Invoice {
    pub fn new(amount: Amount, recipient: HashDigest) -> Self {
        Invoice { amount, recipient }
    }
}

// TODO: Eventually move all of this to the client directly
pub struct ClientAccount {
    pub address: Address,
    pub num_pubkeys: u32,
    pub private_key: Xpriv,
}

pub fn new_master_private_key() -> Xpriv {
    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create private key.")
}

impl ClientAccount {
    fn current_private_key(&self) -> SecretKey {
        self.private_key
            .derive_priv(
                &SECP256K1,
                &[ChildNumber::Normal {
                    index: self
                        .num_pubkeys
                        .checked_sub(1)
                        .expect("This account was never commited to."),
                }],
            )
            .expect("Unable to derive private key for account")
            .private_key
    }

    pub fn create_commitment(
        &self,
        account_state_hash: &HashDigest,
        output_coins_root: &HashDigest,
    ) -> Commitment {
        Commitment::new(
            &self.current_private_key(),
            hash_concat(account_state_hash, output_coins_root).to_vec(),
        )
        .expect("Should be able to create commitment")
    }

    pub fn generate_public_key(&self, index: u32) -> PublicKey {
        // WARNING: LEAKING THE MASTER PUBLIC KEY IS EQUIVALENT TO LEAKING THE PRIVATE KEY!
        Xpub::from_priv(&SECP256K1, &self.private_key)
            .derive_pub(&SECP256K1, &[ChildNumber::Normal { index }])
            .expect("Failed to derive first pubkey")
            .public_key
    }

    pub fn new(private_key: Xpriv) -> Self {
        let mut client_account = ClientAccount {
            address: [0u8; 32],
            num_pubkeys: 0,
            private_key,
        };
        let account = AccountState::new(client_account.generate_public_key(0).serialize().to_vec());
        client_account.address = account.owner;
        client_account
    }
}
