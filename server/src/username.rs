use serde::{Deserialize, Serialize};
use shared::Address;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UsernameStore {
    usernames: HashMap<String, Address>,
}

impl UsernameStore {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(any(feature = "usernames", test))]
    pub fn claim(&mut self, username: &str, address: Address) -> Result<(), &'static str> {
        let normalized = username.to_lowercase();

        if normalized.is_empty() || normalized.len() > 64 {
            return Err("Username must be 1-64 characters");
        }
        if !normalized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err("Username may only contain a-z, 0-9, -, _, .");
        }

        if self.usernames.contains_key(&normalized) {
            return Err("Username already taken");
        }

        if self.usernames.values().any(|a| *a == address) {
            return Err("Address already has a username");
        }

        self.usernames.insert(normalized, address);
        Ok(())
    }

    #[cfg(any(feature = "usernames", feature = "lnurl", test))]
    pub fn resolve(&self, username: &str) -> Option<Address> {
        self.usernames.get(&username.to_lowercase()).copied()
    }

    pub fn get_username(&self, address: &Address) -> Option<&str> {
        self.usernames
            .iter()
            .find(|(_, a)| *a == address)
            .map(|(name, _)| name.as_str())
    }

    #[cfg(any(feature = "usernames", test))]
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        // `bincode::serialize` on a HashMap<String, Address> cannot fail in
        // practice; `io::Error::other` is used as a function reference so the
        // error-mapping path does not introduce an uncovered closure.
        let bytes = bincode::serialize(&self.usernames).map_err(std::io::Error::other)?;
        crate::atomic_write(path, &bytes)
    }

    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let usernames: HashMap<String, Address> =
            bincode::deserialize(&bytes).map_err(std::io::Error::other)?;
        Ok(UsernameStore { usernames })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkcoins_program::hash::digest_from_bytes;

    /// Test helper: byte literal → Poseidon `HashDigest = HashOut<F>`.
    /// Stage 7 Plonky2 migration replaced the SP1-era `Address = [u8; 32]`
    /// with `HashOut<F>`; tests that previously used `[N; 32]` literals
    /// now go through `digest_from_bytes`.
    fn addr(seed: u8) -> Address {
        digest_from_bytes(&[seed; 32])
    }

    #[test]
    fn claim_and_resolve() {
        let mut store = UsernameStore::new();
        let address = addr(1);

        store.claim("Alice", address).unwrap();
        assert_eq!(store.resolve("alice"), Some(address));
        assert_eq!(store.resolve("Alice"), Some(address));
        assert_eq!(store.get_username(&address), Some("alice"));
    }

    #[test]
    fn duplicate_username_rejected() {
        let mut store = UsernameStore::new();
        store.claim("alice", addr(1)).unwrap();
        assert!(store.claim("alice", addr(2)).is_err());
    }

    #[test]
    fn duplicate_address_rejected() {
        let mut store = UsernameStore::new();
        let address = addr(1);
        store.claim("alice", address).unwrap();
        assert!(store.claim("bob", address).is_err());
    }

    #[test]
    fn invalid_username_rejected() {
        let mut store = UsernameStore::new();
        assert!(store.claim("", addr(1)).is_err());
        assert!(store.claim("hello world", addr(2)).is_err());
        assert!(store.claim("hello@world", addr(3)).is_err());
        assert!(store.claim(&"a".repeat(65), addr(4)).is_err());
    }

    #[test]
    fn valid_usernames_accepted() {
        let mut store = UsernameStore::new();
        store.claim("alice", addr(1)).unwrap();
        store.claim("bob-99", addr(2)).unwrap();
        store.claim("carol_x", addr(3)).unwrap();
        store.claim("dave.btc", addr(4)).unwrap();
    }

    #[test]
    fn save_and_load_roundtrip() {
        let path = "/tmp/zkcoins-test-usernames.bin";
        let mut store = UsernameStore::new();
        store.claim("alice", addr(1)).unwrap();
        store.claim("bob", addr(2)).unwrap();

        store.save_to_file(path).unwrap();
        let loaded = UsernameStore::load_from_file(path).unwrap();

        assert_eq!(loaded.resolve("alice"), Some(addr(1)));
        assert_eq!(loaded.resolve("bob"), Some(addr(2)));
        assert_eq!(loaded.get_username(&addr(1)), Some("alice"));
        assert_eq!(loaded.resolve("nonexistent"), None);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn resolve_is_case_insensitive() {
        let mut store = UsernameStore::new();
        let address = addr(5);
        store.claim("Alice", address).unwrap();

        // Resolve with different casings
        assert_eq!(store.resolve("alice"), Some(address));
        assert_eq!(store.resolve("ALICE"), Some(address));
        assert_eq!(store.resolve("Alice"), Some(address));
        assert_eq!(store.resolve("aLiCe"), Some(address));
    }

    #[test]
    fn get_username_returns_none_for_unknown() {
        let store = UsernameStore::new();
        let unknown_address = addr(99);
        assert_eq!(store.get_username(&unknown_address), None);
    }
}
