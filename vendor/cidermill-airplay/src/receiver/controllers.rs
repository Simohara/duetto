//! The controllers (senders) a receiver has paired with by PIN: who may pair-verify.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// A paired controller: its HAP identifier and long-term Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PairedController {
    /// The identifier the sender sent at pair-setup (usually a UUID's text).
    pub id: Vec<u8>,
    /// Its Ed25519 public key.
    pub public_key: [u8; 32],
}

impl PairedController {
    /// A controller.
    #[must_use]
    pub fn new(id: impl Into<Vec<u8>>, public_key: [u8; 32]) -> Self {
        Self {
            id: id.into(),
            public_key,
        }
    }
}

/// Where a receiver keeps its paired controllers. Shared by every connection; persist it to keep
/// pairings across restarts. A removal takes effect at the controller's next pair-verify.
pub trait ControllerStore: Send + Sync {
    /// The public key of a paired controller.
    fn get(&self, id: &[u8]) -> Option<[u8; 32]>;
    /// Stores a controller a PIN pair-setup just paired, replacing any key it had. An error fails
    /// the pairing: the controller is told it did not pair.
    fn add(&self, controller: PairedController) -> crate::Result<()>;
    /// Forgets a controller; `true` if it was paired.
    fn remove(&self, id: &[u8]) -> crate::Result<bool>;
    /// Every paired controller.
    fn list(&self) -> Vec<PairedController>;
}

/// A [`ControllerStore`] in memory, ordered by identifier.
#[derive(Debug, Default)]
pub struct MemoryControllerStore(Mutex<BTreeMap<Vec<u8>, [u8; 32]>>);

impl MemoryControllerStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store holding `controllers` (paired in an earlier run).
    #[must_use]
    pub fn with_controllers(controllers: impl IntoIterator<Item = PairedController>) -> Self {
        Self(Mutex::new(
            controllers
                .into_iter()
                .map(|c| (c.id, c.public_key))
                .collect(),
        ))
    }

    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<Vec<u8>, [u8; 32]>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ControllerStore for MemoryControllerStore {
    fn get(&self, id: &[u8]) -> Option<[u8; 32]> {
        self.map().get(id).copied()
    }

    fn add(&self, controller: PairedController) -> crate::Result<()> {
        self.map().insert(controller.id, controller.public_key);
        Ok(())
    }

    fn remove(&self, id: &[u8]) -> crate::Result<bool> {
        Ok(self.map().remove(id).is_some())
    }

    fn list(&self) -> Vec<PairedController> {
        self.map()
            .iter()
            .map(|(id, key)| PairedController::new(id.clone(), *key))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_store_adds_lists_and_removes() {
        let store = MemoryControllerStore::with_controllers([PairedController::new("b", [2; 32])]);
        store.add(PairedController::new("a", [1; 32])).unwrap();
        store.add(PairedController::new("b", [3; 32])).unwrap();
        assert_eq!(
            store.get(b"b"),
            Some([3; 32]),
            "a repeat pairing replaces the key"
        );
        assert_eq!(
            store.list(),
            vec![
                PairedController::new("a", [1; 32]),
                PairedController::new("b", [3; 32])
            ]
        );
        assert!(store.remove(b"a").unwrap());
        assert!(!store.remove(b"a").unwrap());
        assert_eq!(store.get(b"a"), None);
        assert_eq!(store.list().len(), 1);
    }
}
