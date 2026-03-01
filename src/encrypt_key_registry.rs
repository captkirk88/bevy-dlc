//! Registry for encrypt keys and DLC asset paths. This tracks which encrypt key is
//! associated with which DLC id, and which asset paths are associated with which DLC id
//! so that they can be reloaded when the DLC is unlocked.

use std::sync::LazyLock;

use crate::EncryptionKey;
use dashmap::DashMap;

use secure_gate::ExposeSecret;

#[derive(Default)]
struct DlcRegistration {
    key: Option<EncryptionKey>,
    path: Option<String>,
}

static REGISTRY: LazyLock<DashMap<String, DlcRegistration>> = LazyLock::new(|| DashMap::new());

/// Insert or replace the encrypt key for `dlc_id`.
pub fn insert(dlc_id: &str, key: EncryptionKey) {
    let mut entry = REGISTRY.entry(dlc_id.to_owned()).or_default();
    entry.key = Some(key);
}

/// Remove the encrypt key for `dlc_id`.
#[allow(unused)]
pub fn remove(dlc_id: &str) {
    REGISTRY.remove(dlc_id);
}

/// Result of a lookup in the registry.
pub struct DlcEntry {
    pub key: EncryptionKey,
    pub path: Option<String>,
}

/// Return an owned [EncryptionKey] (cloned) if present.
/// The clone is performed within the secure closure to minimize exposure time.
pub fn get(dlc_id: &str) -> Option<EncryptionKey> {
    REGISTRY.get(dlc_id).and_then(|v| {
        v.key.as_ref().map(|k| {
            k.with_secret(|b| {
                // Clone directly into a new EncryptionKey wrapper to ensure it's zeroized
                EncryptionKey::new(*b)
            })
        })
    })
}

/// Return both the key and the registered path for a given `dlc_id`.
pub fn get_full(dlc_id: &str) -> Option<DlcEntry> {
    REGISTRY.get(dlc_id).and_then(|v| {
        v.key.as_ref().map(|k| DlcEntry {
            key: k.with_secret(|b| EncryptionKey::new(*b)),
            path: v.path.clone(),
        })
    })
}

/// Register an asset path for a given `dlc_id`. Each DLC ID can only have
/// ONE associated pack file. This enforces the design constraint that each
/// DLC release is shipped as a single .dlcpack.
pub fn register_asset_path(dlc_id: &str, path: &str) {
    REGISTRY
        .entry(dlc_id.to_owned())
        .and_modify(|e| e.path = Some(path.to_owned()))
        .or_insert(DlcRegistration {
            key: None,
            path: Some(path.to_owned()),
        });
}

/// Helper for systems to see all registered DLC IDs.
pub fn iter_ids() -> impl Iterator<Item = String> {
    REGISTRY.iter().map(|r| r.key().clone())
}

/// Return the registered asset path for a given `dlc_id`. This is used by the asset loader to determine if a DLC pack file has already been registered for a given DLC ID, which allows it to avoid registering/loading the same pack multiple times. Returns Some(path) if a path is registered, None otherwise.
#[allow(unused)]
pub fn asset_path_for(dlc_id: &str) -> Option<String> {
    REGISTRY
        .get(dlc_id)
        .and_then(|v| v.path.as_ref().map(|p| p.clone()))
}

/// Check if the registry already has a record of the given `dlc_id` and `path`. This is used by the asset loader to determine if a DLC pack file has already been registered for a given DLC ID, which allows it to avoid registering/loading the same pack multiple times. Returns true if the registry has a matching record, false otherwise.
pub(crate) fn has(dlc_id: &str, path: &str) -> bool {
    if let Some(reg) = REGISTRY.get(dlc_id) {
        reg.path.as_deref() == Some(path)
    } else {
        false
    }
}

/// Check if a DLC id is already registered with a different path, which indicates a conflict (for example, two different .dlcpack files claiming the same DLC id). This is used by the asset loader to detect and reject conflicting DLC packs. Returns true if there is a conflict, false otherwise.
#[cfg(test)]
#[allow(unused)]
pub(crate) fn check(dlc_id: &str, path: &str) -> bool {
    if let Some(reg) = REGISTRY.get(dlc_id) {
        // Conflict if the registered path is different from the incoming path
        reg.path.as_deref().map_or(false, |p| p != path)
    } else {
        false
    }
}

#[cfg(test)]
/// Utility for tests/demo: clear the registry.
pub(crate) fn clear_all() {
    REGISTRY.clear();
}
