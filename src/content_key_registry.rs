use dashmap::DashMap;
use once_cell::sync::Lazy;

/// Global registry mapping DLC id -> symmetric content-key bytes and
/// tracking asset paths associated with each DLC id (used for reload-on-unlock).
/// Minimal API consumed by the asset loaders and `DlcManager`.

static KEY_REGISTRY: Lazy<DashMap<String, Vec<u8>>> = Lazy::new(|| DashMap::new());
static PATH_REGISTRY: Lazy<DashMap<String, Vec<String>>> = Lazy::new(|| DashMap::new());

/// Insert or replace the content key for `dlc_id`.
pub(crate) fn insert(dlc_id: &str, key: Vec<u8>) {
    KEY_REGISTRY.insert(dlc_id.to_owned(), key);
}

/// Remove the content key for `dlc_id`.
#[allow(unused)]
pub(crate) fn remove(dlc_id: &str) {
    KEY_REGISTRY.remove(dlc_id);
    PATH_REGISTRY.remove(dlc_id);
}

/// Return a clone of the content key bytes if present.
pub(crate) fn get(dlc_id: &str) -> Option<Vec<u8>> {
    KEY_REGISTRY.get(dlc_id).map(|v| v.value().clone())
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
pub(crate) fn asset_paths_for(dlc_id: &str) -> Vec<String> {
    PATH_REGISTRY
        .get(dlc_id)
        .map(|v| v.value().clone())
        .unwrap_or_default()
}

/// Utility for tests/demo: clear the registry.
#[cfg(test)]
pub(crate) fn clear_all() {
    KEY_REGISTRY.clear();
    PATH_REGISTRY.clear();
}
