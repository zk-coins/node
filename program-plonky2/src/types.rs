//! Protocol data types for the Plonky2 backend.
//!
//! Ports `AccountState`, `Coin`, `CoinTemplate`, and `ProofData` from
//! `program/src/lib.rs` (SP1/SHA256) to a canonical field-element layout
//! hashed with Poseidon-Goldilocks. The byte-oriented SHA256 layout
//! (`bincode::serialize` then `Sha256::digest`) is replaced with explicit
//! field-element packing so the same hash can be computed cheaply both
//! off-circuit (Rust) and in-circuit (Plonky2 gadget).

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::hash::{hash_bytes, HashDigest};
use crate::F;

pub type Amount = u64;

/// Compressed secp256k1 public key, 33 bytes.
pub type PublicKey = [u8; 33];

/// Address: hash of the initial public key. Derived once at account creation
/// and never mutated; differs from the rotating `AccountState::public_key`.
pub type Address = HashDigest;

/// Asset identifier: Poseidon hash of `(domain_tag || creator_pubkey || name || decimals)`.
pub type AssetId = HashDigest;

/// Minting account address. Currently a placeholder derived from a
/// domain-separated tag — the node will replace this with the actual
/// Poseidon hash of the live minting public key as part of ROADMAP step 7
/// ("Node: replace SP1 with Plonky2"). See SPEC.md §12.1 and divergence
/// D11 in MIGRATION_RESEARCH.md §3.
pub static MINTING_ADDRESS: std::sync::LazyLock<HashDigest> =
    std::sync::LazyLock::new(|| hash_bytes(b"zkcoins:minting-address:placeholder:v1"));

pub static ASSET_GENESIS_DOMAIN_TAG: std::sync::LazyLock<HashDigest> =
    std::sync::LazyLock::new(|| hash_bytes(b"zkcoins:asset-genesis:v1"));

pub static NATIVE_ASSET_ID: std::sync::LazyLock<AssetId> =
    std::sync::LazyLock::new(|| hash_bytes(b"zkcoins:native-asset:v1"));

/// Pack a `u64` into 2 field elements `(lo, hi)` — both 32-bit halves. This
/// guarantees the value is below the Goldilocks modulus regardless of input,
/// and matches a natural 2-limb representation for u64 in-circuit.
fn u64_to_limbs(value: u64) -> [F; 2] {
    [
        F::from_canonical_u32((value & 0xFFFF_FFFF) as u32),
        F::from_canonical_u32((value >> 32) as u32),
    ]
}

/// Pack a 33-byte compressed pubkey into 5 field elements (7 bytes each,
/// little-endian, with the final element holding 5 bytes + 3 zero pads).
/// Below the 56-bit safe ceiling for canonical Goldilocks representation.
pub(crate) fn pubkey_to_limbs(pk: &PublicKey) -> [F; 5] {
    let mut out = [F::ZERO; 5];
    for (i, chunk) in pk.chunks(7).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        out[i] = F::from_canonical_u64(u64::from_le_bytes(buf));
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountState {
    /// `Address = H(initial_public_key_bytes)`. Set once at creation.
    pub owner: Address,
    pub balance: Amount,
    /// Current commitment public key. Rotates each send. Wrapped in
    /// `serde(with = "serde_big_array_local")` because serde's default
    /// derive only handles `[T; N]` for `N ≤ 32`.
    #[serde(with = "BigArray33")]
    pub public_key: PublicKey,
}

/// Tiny helper module supplying the `serialize` / `deserialize`
/// functions that `#[serde(with = "BigArray33")]` looks up. Avoids
/// pulling in the `serde-big-array` dependency for one 33-byte type.
struct BigArray33;

impl BigArray33 {
    pub fn serialize<S: serde::Serializer>(v: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(33)?;
        for b in v.iter() {
            t.serialize_element(b)?;
        }
        t.end()
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = [u8; 33];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("[u8; 33]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 33];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(33, V)
    }
}

impl AccountState {
    /// Create a fresh account from an initial public key. Balance starts at 0;
    /// `owner` is derived as `hash_bytes(initial_public_key)`.
    pub fn new(initial_public_key: PublicKey) -> Self {
        AccountState {
            owner: hash_bytes(&initial_public_key),
            balance: 0,
            public_key: initial_public_key,
        }
    }

    /// Canonical field-element layout: 4 owner + 2 balance + 5 pubkey = 11 F.
    /// Single Poseidon `hash_no_pad` call; matches SPEC §10.3.
    pub fn hash(&self) -> HashDigest {
        let mut elements = Vec::with_capacity(11);
        elements.extend_from_slice(&self.owner.elements);
        elements.extend_from_slice(&u64_to_limbs(self.balance));
        elements.extend_from_slice(&pubkey_to_limbs(&self.public_key));
        PoseidonHash::hash_no_pad(&elements)
    }

    /// Receive a coin into this account. Errors if `coin.recipient != owner`
    /// or if the balance overflows.
    pub fn apply_coin(mut self, coin: &Coin) -> Result<Self, &'static str> {
        if coin.recipient != self.owner {
            return Err("Cannot receive coin: User is not the recipient");
        }
        self.balance = self
            .balance
            .checked_add(coin.amount)
            .ok_or("Receiving coin causes an overflow")?;
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoinTemplate {
    pub recipient: Address,
    pub amount: Amount,
    #[serde(default = "default_native_asset_id")]
    pub asset_id: AssetId,
}

fn default_native_asset_id() -> AssetId {
    *NATIVE_ASSET_ID
}

impl CoinTemplate {
    pub fn new(recipient: Address, amount: Amount, asset_id: AssetId) -> Self {
        CoinTemplate {
            recipient,
            amount,
            asset_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Coin {
    pub identifier: HashDigest,
    pub recipient: Address,
    pub amount: Amount,
    #[serde(default = "default_native_asset_id")]
    pub asset_id: AssetId,
}

impl Coin {
    pub fn new(template: CoinTemplate, identifier: HashDigest) -> Coin {
        Coin {
            recipient: template.recipient,
            amount: template.amount,
            asset_id: template.asset_id,
            identifier,
        }
    }

    pub fn verify_identifier(
        &self,
        account_state_hash: HashDigest,
        coin_index: u32,
    ) -> Result<(), &'static str> {
        if calculate_coin_identifier(account_state_hash, self.asset_id, coin_index)
            == self.identifier
        {
            Ok(())
        } else {
            Err("Incorrect preimages provided.")
        }
    }
}

/// `identifier = H(account_state_hash || asset_id || u32(coin_index))`.
pub fn calculate_coin_identifier(
    account_state_hash: HashDigest,
    asset_id: AssetId,
    coin_index: u32,
) -> HashDigest {
    let mut elements = Vec::with_capacity(9);
    elements.extend_from_slice(&account_state_hash.elements);
    elements.extend_from_slice(&asset_id.elements);
    elements.push(F::from_canonical_u32(coin_index));
    PoseidonHash::hash_no_pad(&elements)
}

pub fn calculate_asset_id(creator_pubkey: &PublicKey, name: &str, decimals: u8) -> AssetId {
    let mut elements = Vec::with_capacity(11);
    elements.extend_from_slice(&ASSET_GENESIS_DOMAIN_TAG.elements);
    elements.extend_from_slice(&pubkey_to_limbs(creator_pubkey));
    for chunk in name.as_bytes().chunks(7) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        elements.push(F::from_canonical_u64(u64::from_le_bytes(buf)));
    }
    elements.push(F::from_canonical_u32(decimals as u32));
    PoseidonHash::hash_no_pad(&elements)
}

/// Public output of the state-transition proof. Field-element-serialised
/// (no bincode) so the in-circuit `commit` and off-circuit reconstruction
/// agree element-for-element.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofData {
    pub account_state_hash: HashDigest,
    pub output_coins_root: HashDigest,
    pub commitment_history_root: HashDigest,
    pub coin_history_root: HashDigest,
    #[serde(default = "default_native_asset_id")]
    pub asset_id: AssetId,
}

impl ProofData {
    pub fn to_field_elements(&self) -> [F; 20] {
        let mut out = [F::ZERO; 20];
        out[0..4].copy_from_slice(&self.account_state_hash.elements);
        out[4..8].copy_from_slice(&self.output_coins_root.elements);
        out[8..12].copy_from_slice(&self.commitment_history_root.elements);
        out[12..16].copy_from_slice(&self.coin_history_root.elements);
        out[16..20].copy_from_slice(&self.asset_id.elements);
        out
    }

    pub fn from_field_elements(elements: &[F; 20]) -> Self {
        let mut chunks = elements.chunks_exact(4);
        let next = |c: &mut std::slice::ChunksExact<F>| {
            let chunk = c.next().unwrap();
            HashOut {
                elements: [chunk[0], chunk[1], chunk[2], chunk[3]],
            }
        };
        ProofData {
            account_state_hash: next(&mut chunks),
            output_coins_root: next(&mut chunks),
            commitment_history_root: next(&mut chunks),
            coin_history_root: next(&mut chunks),
            asset_id: next(&mut chunks),
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pubkey(seed: u8) -> PublicKey {
        let mut pk = [0u8; 33];
        pk[0] = 0x02; // compressed even-y prefix
        for (i, b) in pk.iter_mut().enumerate().skip(1) {
            *b = seed.wrapping_add(i as u8);
        }
        pk
    }

    #[test]
    fn account_state_new_seeds_balance_zero() {
        let s = AccountState::new(dummy_pubkey(1));
        assert_eq!(s.balance, 0);
        assert_eq!(s.owner, hash_bytes(&dummy_pubkey(1)));
        assert_eq!(s.public_key, dummy_pubkey(1));
    }

    #[test]
    fn account_state_hash_is_deterministic_and_collision_resistant() {
        let s1 = AccountState::new(dummy_pubkey(1));
        let s2 = AccountState::new(dummy_pubkey(2));
        assert_eq!(s1.hash(), s1.clone().hash());
        assert_ne!(s1.hash(), s2.hash());

        let mut s3 = s1.clone();
        s3.balance = 1;
        assert_ne!(s1.hash(), s3.hash());

        let mut s4 = s1.clone();
        s4.public_key = dummy_pubkey(99);
        assert_ne!(s1.hash(), s4.hash());
    }

    #[test]
    fn apply_coin_rejects_wrong_recipient() {
        let owner = AccountState::new(dummy_pubkey(1));
        let coin = Coin {
            identifier: hash_bytes(b"x"),
            recipient: hash_bytes(b"someone else"),
            amount: 100,
            asset_id: *NATIVE_ASSET_ID,
        };
        assert!(owner.apply_coin(&coin).is_err());
    }

    #[test]
    fn apply_coin_credits_balance() {
        let owner = AccountState::new(dummy_pubkey(1));
        let coin = Coin {
            identifier: hash_bytes(b"x"),
            recipient: owner.owner,
            amount: 100,
            asset_id: *NATIVE_ASSET_ID,
        };
        let updated = owner.apply_coin(&coin).unwrap();
        assert_eq!(updated.balance, 100);
    }

    #[test]
    fn apply_coin_rejects_overflow() {
        let mut s = AccountState::new(dummy_pubkey(1));
        s.balance = u64::MAX - 5;
        let coin = Coin {
            identifier: hash_bytes(b"x"),
            recipient: s.owner,
            amount: 10,
            asset_id: *NATIVE_ASSET_ID,
        };
        assert!(s.apply_coin(&coin).is_err());
    }

    #[test]
    fn coin_identifier_round_trip() {
        let asth = hash_bytes(b"asth");
        let aid = *NATIVE_ASSET_ID;
        for i in [0u32, 1, 7, 100, u32::MAX] {
            let id = calculate_coin_identifier(asth, aid, i);
            let coin = Coin {
                identifier: id,
                recipient: hash_bytes(b"r"),
                amount: 1,
                asset_id: aid,
            };
            assert!(coin.verify_identifier(asth, i).is_ok());
            if i != u32::MAX {
                assert!(coin.verify_identifier(asth, i + 1).is_err());
            }
        }
    }

    #[test]
    fn proof_data_field_round_trip() {
        let pd = ProofData {
            account_state_hash: hash_bytes(b"asth"),
            output_coins_root: hash_bytes(b"ocr"),
            commitment_history_root: hash_bytes(b"chr"),
            coin_history_root: hash_bytes(b"cohr"),
            asset_id: *NATIVE_ASSET_ID,
        };
        let elts = pd.to_field_elements();
        let recovered = ProofData::from_field_elements(&elts);
        assert_eq!(pd, recovered);
    }

    #[test]
    fn minting_address_is_stable() {
        assert_eq!(*MINTING_ADDRESS, *MINTING_ADDRESS);
        assert_eq!(
            *MINTING_ADDRESS,
            hash_bytes(b"zkcoins:minting-address:placeholder:v1")
        );
    }

    #[test]
    fn coin_template_new_carries_fields() {
        let recipient = hash_bytes(b"r");
        let aid = *NATIVE_ASSET_ID;
        let template = CoinTemplate::new(recipient, 42, aid);
        assert_eq!(template.recipient, recipient);
        assert_eq!(template.amount, 42);
        assert_eq!(template.asset_id, aid);
    }

    #[test]
    fn coin_new_from_template_preserves_recipient_and_amount() {
        let recipient = hash_bytes(b"r");
        let aid = *NATIVE_ASSET_ID;
        let template = CoinTemplate::new(recipient, 17, aid);
        let id = hash_bytes(b"id");
        let coin = Coin::new(template, id);
        assert_eq!(coin.recipient, recipient);
        assert_eq!(coin.amount, 17);
        assert_eq!(coin.identifier, id);
        assert_eq!(coin.asset_id, aid);
    }

    #[test]
    fn calculate_asset_id_is_deterministic_and_collision_resistant() {
        let pk1 = dummy_pubkey(1);
        let pk2 = dummy_pubkey(2);
        let id1 = calculate_asset_id(&pk1, "TestToken", 8);
        let id1b = calculate_asset_id(&pk1, "TestToken", 8);
        assert_eq!(id1, id1b);

        let id2 = calculate_asset_id(&pk2, "TestToken", 8);
        assert_ne!(id1, id2);

        let id3 = calculate_asset_id(&pk1, "OtherToken", 8);
        assert_ne!(id1, id3);

        let id4 = calculate_asset_id(&pk1, "TestToken", 6);
        assert_ne!(id1, id4);
    }

    #[test]
    fn native_asset_id_is_stable() {
        assert_eq!(*NATIVE_ASSET_ID, *NATIVE_ASSET_ID);
        assert_eq!(*NATIVE_ASSET_ID, hash_bytes(b"zkcoins:native-asset:v1"));
    }
}
