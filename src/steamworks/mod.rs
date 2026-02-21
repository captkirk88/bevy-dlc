use bevy::asset::io::{AssetReader, AssetReaderError, PathStream, Reader};
use bevy::prelude::*;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "steam")]
use bevy_steamworks::Client;
#[cfg(feature = "steam")]
use steamworks::AppId;

/// Global mapping of Steam IDs (Workshop PublishedFileId or DLC AppId) to their installation folders.
static STEAM_PATHS: Lazy<DashMap<u64, PathBuf>> = Lazy::new(|| DashMap::new());

/// Register a local path for a Steam ID (AppId or WorkshopPublishedFileId).
/// This is used internally by the discovery system but can also be used for
/// testing or manual integration.
pub fn register_steam_path(id: u64, path: impl Into<PathBuf>) {
    STEAM_PATHS.insert(id, path.into());
}

/// Settings for Steam DLC integration.
#[derive(Resource, Default)]
pub struct SteamDlcSettings {
    /// List of official DLC AppIds to check for installation.
    pub dlc_app_ids: Vec<u32>,
}

/// Plugin that integrates Steam DLC and Workshop with bevy-dlc.
pub struct SteamDlcPlugin;

impl Plugin for SteamDlcPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<SteamDlcSettings>();

        #[cfg(feature = "steam")]
        {
            app.register_asset_source(
                "steam",
                bevy::asset::io::AssetSourceBuilder::new(|| Box::new(SteamAssetReader)),
            );

            app.add_systems(Update, discover_steam_dlcs);
        }
    }
}

/// A reader that resolves paths from Steam (DLCs or Workshop).
/// Format: `steam://<id>/path/to/asset.ext`
pub struct SteamAssetReader;

impl AssetReader for SteamAssetReader {
    async fn read<'a>(&'a self, path: &'a Path) -> Result<impl Reader + 'a, AssetReaderError> {
        let path = path.to_owned();
        let (root, sub_path) = resolve_steam_path(&path)?;
        let full_path = root.join(sub_path);
        let bytes = tokio::fs::read(&full_path)
            .await
            .map_err(|e| AssetReaderError::Io(Arc::new(e)))?;
        Ok(bevy::asset::io::VecReader::new(bytes))
    }

    async fn read_meta<'a>(&'a self, path: &'a Path) -> Result<impl Reader + 'a, AssetReaderError> {
        let path = path.to_owned();

        let (root, sub_path) = resolve_steam_path(&path)?;
        let mut full_path = root.join(sub_path);

        let mut ext = full_path.extension().unwrap_or_default().to_os_string();
        ext.push(".meta");
        full_path.set_extension(ext);

        let bytes = tokio::fs::read(&full_path)
            .await
            .map_err(|e| AssetReaderError::Io(Arc::new(e)))?;
        Ok(bevy::asset::io::VecReader::new(bytes))
    }

    async fn read_directory<'a>(
        &'a self,
        path: &'a Path,
    ) -> Result<Box<PathStream>, AssetReaderError> {
        let path = path.to_owned();

        let (root, sub_path) = resolve_steam_path(&path)?;
        let full_path = root.join(sub_path);
        let mut entries = tokio::fs::read_dir(full_path)
            .await
            .map_err(|e| AssetReaderError::Io(Arc::new(e)))?;
        let mut paths = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AssetReaderError::Io(Arc::new(e)))?
        {
            paths.push(entry.path());
        }
        let stream = futures_lite::stream::iter(paths);
        let boxed: Box<PathStream> = Box::new(stream);
        Ok(boxed)
    }

    async fn is_directory<'a>(&'a self, path: &'a Path) -> Result<bool, AssetReaderError> {
        let path = path.to_owned();

        let (root, sub_path) = resolve_steam_path(&path)?;
        let full_path = root.join(sub_path);
        Ok(full_path.is_dir())
    }

    fn read_meta_bytes<'a>(
        &'a self,
        path: &'a Path,
    ) -> impl bevy::tasks::ConditionalSendFuture<Output = std::result::Result<Vec<u8>, AssetReaderError>>
    {
        async {
            let mut meta_reader = self.read_meta(path).await?;
            let mut meta_bytes = Vec::new();
            meta_reader.read_to_end(&mut meta_bytes).await?;
            Ok(meta_bytes)
        }
    }
}

fn resolve_steam_path(path: &Path) -> Result<(PathBuf, PathBuf), AssetReaderError> {
    let path_str = path.to_string_lossy();
    let mut parts = path_str.splitn(2, |c| c == '/' || c == '\\');

    let id_str = parts
        .next()
        .ok_or_else(|| AssetReaderError::NotFound(path.to_owned()))?;

    let sub_path = parts.next().unwrap_or("");

    let id: u64 = id_str
        .parse()
        .map_err(|_| AssetReaderError::NotFound(path.to_owned()))?;

    if let Some(folder) = STEAM_PATHS.get(&id) {
        Ok((folder.clone(), PathBuf::from(sub_path)))
    } else {
        Err(AssetReaderError::NotFound(path.to_owned()))
    }
}

/// System that scans official Steam DLCs and loads .dlcpack files.
#[cfg(feature = "steam")]
fn discover_steam_dlcs(
    client: Option<Res<Client>>,
    settings: Res<SteamDlcSettings>,
    asset_server: Res<AssetServer>,
    mut last_check: Local<f32>,
    time: Res<Time>,
) {
    if time.elapsed_secs() - *last_check < 60.0 {
        return;
    }
    *last_check = time.elapsed_secs();

    let Some(client) = client else { return };

    for &dlc_id_raw in &settings.dlc_app_ids {
        let dlc_app_id = AppId(dlc_id_raw);
        if client.apps().is_dlc_installed(dlc_app_id) {
            let folder = client.apps().app_install_dir(dlc_app_id);
            if !folder.is_empty() {
                let folder_path = PathBuf::from(folder);
                STEAM_PATHS.insert(dlc_id_raw as u64, folder_path.clone());
                scan_and_load_packs(&folder_path, dlc_id_raw as u64, &asset_server);
            }
        }
    }
}

fn scan_and_load_packs(folder: &Path, id: u64, asset_server: &AssetServer) {
    if let Ok(entries) = std::fs::read_dir(folder) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "dlcpack") {
                let filename = path.file_name().unwrap().to_string_lossy();
                let asset_path = format!("steam://{}/{}", id, filename);
                let _handle: Handle<crate::DlcPack> = asset_server.load(asset_path);
            }
        }
    }
}
