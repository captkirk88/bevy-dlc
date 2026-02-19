//! Registry for encrypt keys and DLC asset paths. This is used by `DlcManager` to
//! track which encrypt key is associated with which DLC id, and which asset paths are associated with which DLC id (so that they can be reloaded when the DLC is unlocked).

use crate::EncryptionKey;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use secure_gate::ExposeSecret;

static KEY_REGISTRY: Lazy<DashMap<String, EncryptionKey>> = Lazy::new(|| DashMap::new());
// Each DLC ID can only have ONE associated pack file path.
static PATH_REGISTRY: Lazy<DashMap<String, String>> = Lazy::new(|| DashMap::new());

/// Insert or replace the encrypt key for `dlc_id`.
pub(crate) fn insert(dlc_id: &str, key: EncryptionKey) {
    KEY_REGISTRY.insert(dlc_id.to_owned(), key);
}

/// Remove the encrypt key for `dlc_id`.
#[allow(unused)]
pub(crate) fn remove(dlc_id: &str) {
    KEY_REGISTRY.remove(dlc_id);
    PATH_REGISTRY.remove(dlc_id);
}

/// Return an owned `ContentKey` (cloned) if present.
/// The clone is performed within the secure closure to minimize exposure time.
pub(crate) fn get(dlc_id: &str) -> Option<EncryptionKey> {
    KEY_REGISTRY.get(dlc_id).map(|v| {
        v.value().with_secret(|b| {
            // Clone directly into a new EncryptionKey wrapper to ensure it's zeroized
            EncryptionKey::from(b.to_vec())
        })
    })
}

/// Register an asset path for a given `dlc_id`. Each DLC ID can only have
/// ONE associated pack file. This enforces the design constraint that each
/// DLC release is shipped as a single .dlcpack.
/// Calling this with a different path for the same DlcId will replace the
/// previous entry (which should not happen if the asset loader's conflict check is working).
pub(crate) fn register_asset_path(dlc_id: &str, path: &str) {
    PATH_REGISTRY.insert(dlc_id.to_owned(), path.to_owned());
}

/// Return the registered asset path for the DLC id as a Vec (0 or 1 element).
/// Returns empty vec if the DLC id has not been registered.
#[allow(unused)]
pub(crate) fn asset_paths_for(dlc_id: &str) -> Vec<String> {
    PATH_REGISTRY
        .get(dlc_id)
        .map(|v| vec![v.value().clone()])
        .unwrap_or_default()
}

/// Check if a specific path is already registered for a given DLC id.
pub(crate) fn path_exists_for(dlc_id: &str, path: &str) -> bool {
    if let Some(registered_path) = PATH_REGISTRY.get(dlc_id) {
        registered_path.value() == path
    } else {
        false
    }
}

/// Check if a DLC id is already registered with a different path, which indicates a conflict (for example, two different .dlcpack files claiming the same DLC id). This is used by the asset loader to detect and reject conflicting DLC packs. Returns true if there is a conflict, false otherwise.
#[allow(unused)]
pub(crate) fn check(dlc_id: &str, path: &str) -> bool {
    if let Some(registered_path) = PATH_REGISTRY.get(dlc_id) {
        // Conflict if the registered path is different from the incoming path
        registered_path.value() != path
    } else {
        false
    }
}

#[cfg(test)]
/// Utility for tests/demo: clear the registry.
pub(crate) fn clear_all() {
    KEY_REGISTRY.clear();
    PATH_REGISTRY.clear();
}
