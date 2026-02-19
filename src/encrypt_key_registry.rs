//! Registry for encrypt keys and DLC asset paths. This is used by `DlcManager` to
//! track which encrypt key is associated with which DLC id, and which asset paths are associated with which DLC id (so that they can be reloaded when the DLC is unlocked).

use dashmap::DashMap;
use once_cell::sync::Lazy;
use crate::EncryptionKey;
use secure_gate::ExposeSecret;

static KEY_REGISTRY: Lazy<DashMap<String, EncryptionKey>> = Lazy::new(|| DashMap::new());
static PATH_REGISTRY: Lazy<DashMap<String, Vec<String>>> = Lazy::new(|| DashMap::new());

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

/// Register an asset path for a given `dlc_id`. The path is stored so that
/// callers (for example `DlcManager` or a reload system) can trigger
/// `AssetServer::reload` on the paths associated with a DLC when it becomes
/// unlocked.
pub(crate) fn register_asset_path(dlc_id: &str, path: &str) {
    PATH_REGISTRY
        .entry(dlc_id.to_owned())
        .or_default()
        .push(path.to_owned());
}

/// Return a list of registered asset paths for the DLC id (clone).
#[allow(unused)]
pub(crate) fn asset_paths_for(dlc_id: &str) -> Vec<String> {
    PATH_REGISTRY
        .get(dlc_id)
        .map(|v| v.value().clone())
        .unwrap_or_default()
}

/// Utility for tests/demo: clear the registry.
pub(crate) fn clear_all() {
    KEY_REGISTRY.clear();
    PATH_REGISTRY.clear();
}
