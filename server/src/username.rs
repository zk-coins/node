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

    pub fn resolve(&self, username: &str) -> Option<Address> {
        self.usernames.get(&username.to_lowercase()).copied()
    }

    pub fn get_username(&self, address: &Address) -> Option<&str> {
        self.usernames
            .iter()
            .find(|(_, a)| *a == address)
            .map(|(name, _)| name.as_str())
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let bytes = bincode::serialize(&self.usernames)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        crate::atomic_write(path, &bytes)
    }

    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let usernames: HashMap<String, Address> = bincode::deserialize(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(UsernameStore { usernames })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_and_resolve() {
        let mut store = UsernameStore::new();
        let address = [1u8; 32];

        store.claim("Alice", address).unwrap();
        assert_eq!(store.resolve("alice"), Some(address));
        assert_eq!(store.resolve("Alice"), Some(address));
        assert_eq!(store.get_username(&address), Some("alice"));
    }

    #[test]
    fn duplicate_username_rejected() {
        let mut store = UsernameStore::new();
        store.claim("alice", [1u8; 32]).unwrap();
        assert!(store.claim("alice", [2u8; 32]).is_err());
    }

    #[test]
    fn duplicate_address_rejected() {
        let mut store = UsernameStore::new();
        let address = [1u8; 32];
        store.claim("alice", address).unwrap();
        assert!(store.claim("bob", address).is_err());
    }

    #[test]
    fn invalid_username_rejected() {
        let mut store = UsernameStore::new();
        assert!(store.claim("", [1u8; 32]).is_err());
        assert!(store.claim("hello world", [2u8; 32]).is_err());
        assert!(store.claim("hello@world", [3u8; 32]).is_err());
        assert!(store.claim(&"a".repeat(65), [4u8; 32]).is_err());
    }

    #[test]
    fn valid_usernames_accepted() {
        let mut store = UsernameStore::new();
        store.claim("alice", [1u8; 32]).unwrap();
        store.claim("bob-99", [2u8; 32]).unwrap();
        store.claim("carol_x", [3u8; 32]).unwrap();
        store.claim("dave.btc", [4u8; 32]).unwrap();
    }
}
