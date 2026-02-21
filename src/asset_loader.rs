use bevy::asset::io::Reader;
use bevy::asset::{
    Asset, AssetLoader, AssetPath, ErasedLoadedAsset, Handle, LoadContext, LoadedUntypedAsset,
};
use bevy::ecs::reflect::AppTypeRegistry;
use bevy::prelude::*;
use bevy::reflect::TypePath;
use rayon::prelude::*;
use std::io;
use std::sync::Arc;
use thiserror::Error;

use crate::DlcId;

/// Fuzzy match for type paths, normalizing by trimming leading "::" to handle absolute vs relative paths.
/// Also handles crate name differences by allowing suffix matches.
pub(crate) fn fuzzy_type_path_match<'a>(stored: &'a str, expected: &'a str) -> bool {
    let s = stored.trim_start_matches("::");
    let e = expected.trim_start_matches("::");

    if s == e {
        return true;
    }

    // Allow suffix matching to handle differences in crate names (e.g. "my_crate::MyType" vs "MyType")
    // or when one path is more specific than the other.
    if e.ends_with(s) && e.as_bytes().get(e.len() - s.len() - 1) == Some(&b':') {
        return true;
    }

    if s.ends_with(e) && s.as_bytes().get(s.len() - e.len() - 1) == Some(&b':') {
        return true;
    }

    false
}

/// Attempts to downcast an `ErasedLoadedAsset` to `A` and, if successful,
/// registers it as a labeled sub-asset in `load_context`.
///
/// Returns `true` when the asset was successfully registered.
pub trait ErasedSubAssetRegistrar: Send + Sync + 'static {
    fn try_register(
        &self,
        label: String,
        erased: ErasedLoadedAsset,
        load_context: &mut LoadContext<'_>,
    ) -> Result<(), ErasedLoadedAsset>;

    /// Return the `TypePath` of the asset type this registrar handles.
    fn asset_type_path(&self) -> &'static str;

    /// Attempt to load the asset directly using its static type, bypassing
    /// extension dispatch. This is used when a `type_path` is provided by
    /// the container.
    fn load_direct<'a>(
        &'a self,
        label: String,
        fake_path: String,
        reader: &'a mut dyn Reader,
        load_context: &'a mut LoadContext<'_>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DlcLoaderError>> + Send + 'a>>;
}

/// Concrete implementation for asset type `A`.
pub struct TypedSubAssetRegistrar<A: Asset>(std::marker::PhantomData<A>);

impl<A: Asset> Default for TypedSubAssetRegistrar<A> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<A: Asset> ErasedSubAssetRegistrar for TypedSubAssetRegistrar<A> {
    fn try_register(
        &self,
        label: String,
        erased: ErasedLoadedAsset,
        load_context: &mut LoadContext<'_>,
    ) -> Result<(), ErasedLoadedAsset> {
        match erased.downcast::<A>() {
            Ok(loaded) => {
                load_context.add_loaded_labeled_asset(label, loaded);
                Ok(())
            }
            Err(back) => Err(back),
        }
    }

    fn asset_type_path(&self) -> &'static str {
        A::type_path()
    }

    fn load_direct<'a>(
        &'a self,
        label: String,
        fake_path: String,
        reader: &'a mut dyn Reader,
        load_context: &'a mut LoadContext<'_>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DlcLoaderError>> + Send + 'a>>
    {
        Box::pin(async move {
            match load_context
                .loader()
                .with_static_type()
                .immediate()
                .with_reader(reader)
                .load::<A>(fake_path)
                .await
            {
                Ok(loaded) => {
                    load_context.add_loaded_labeled_asset(label, loaded);
                    Ok(())
                }
                Err(e) => Err(DlcLoaderError::DecryptionFailed(e.to_string())),
            }
        })
    }
}

/// Represents a single encrypted file inside a `.dlcpack` container, along with its metadata (DLC ID, original extension, optional type path). The ciphertext is not decrypted at this stage; decryption is performed on demand by `DlcPackEntry::decrypt_bytes` using the global encrypt key registry.
#[derive(Clone, Debug)]
pub struct EncryptedAsset {
    pub dlc_id: String,
    pub original_extension: String,
    /// Optional serialized type identifier (e.g. `bevy::image::Image`)
    pub type_path: Option<String>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Parse the binary encrypted-asset container `.dlcpack`.
///
/// Returns metadata (dlc id, original extension, optional `type_path`) plus
/// the ciphertext — no decryption is performed here.
///
/// Format: magic(4) | version(1) | dlc_len(u16) | dlc_id | ext_len(u8) | ext | type_len(u16) | type_path | nonce(12) | ciphertext
pub fn parse_encrypted(bytes: &[u8]) -> Result<EncryptedAsset, io::Error> {
    if bytes.len() < 4 + 1 + 2 + 1 + 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted file too small",
        ));
    }
    if &bytes[0..4] != b"BDLC" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid encrypted asset magic",
        ));
    }
    let version = bytes[4];
    let mut offset = 5usize;

    let dlc_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    if offset + dlc_len > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid dlc id length",
        ));
    }
    let dlc_id = String::from_utf8(bytes[offset..offset + dlc_len].to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    offset += dlc_len;

    let ext_len = bytes[offset] as usize;
    offset += 1;
    let original_extension = if ext_len == 0 {
        "".to_string()
    } else {
        let s = String::from_utf8(bytes[offset..offset + ext_len].to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        offset += ext_len;
        s
    };

    // version 1+ stores a serialized type identifier (u16 length + utf8 bytes)
    let type_path = if version >= 1 {
        if offset + 2 > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing type_path length",
            ));
        }
        let tlen = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if tlen == 0 {
            None
        } else {
            if offset + tlen > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid type_path length",
                ));
            }
            let s = String::from_utf8(bytes[offset..offset + tlen].to_vec())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            offset += tlen;
            Some(s)
        }
    } else {
        None
    };

    if offset + 12 > bytes.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing nonce"));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[offset..offset + 12]);
    offset += 12;
    let ciphertext = bytes[offset..].to_vec();

    Ok(EncryptedAsset {
        dlc_id,
        original_extension,
        type_path,
        nonce,
        ciphertext,
    })
}

/// A loader for individual encrypted files inside a `.dlcpack`.
#[derive(TypePath)]
pub struct DlcLoader<A: bevy::asset::Asset + 'static> {
    /// Stored for potential future use (e.g., validating type_path matches `A`).
    /// Currently unused because the generic `A` already specifies the target type.
    #[allow(dead_code)]
    type_registry: Arc<AppTypeRegistry>,
    _marker: std::marker::PhantomData<A>,
}

// Provide FromWorld so the loader can be initialized by Bevy's App without
// requiring `A: Default`.
impl<A> bevy::prelude::FromWorld for DlcLoader<A>
where
    A: bevy::asset::Asset + 'static,
{
    fn from_world(world: &mut bevy::prelude::World) -> Self {
        let registry = world.resource::<AppTypeRegistry>().clone();
        DlcLoader {
            type_registry: Arc::new(registry),
            _marker: std::marker::PhantomData,
        }
    }
}

#[derive(TypePath, Clone, Debug)]
pub struct DlcPackEntry {
    /// Relative path inside the pack (as authored when packing)
    path: String,
    /// Optional original extension stored by the pack producer
    original_extension: String,
    /// Optional serialized TypePath
    type_path: Option<String>,
}

impl DlcPackEntry {
    /// Convenience: load this entry's registered path via `AssetServer::load`.
    pub fn load_untyped(
        &self,
        asset_server: &bevy::prelude::AssetServer,
    ) -> Handle<LoadedUntypedAsset> {
        asset_server.load_untyped(&self.path)
    }

    /// Decrypt and return the plaintext bytes for this entry using the
    /// `DlcPack` container that owns it. This consults the global encrypt-key
    /// registry and will return `DlcLoaderError::DlcLocked` when the encrypt
    /// key is not present.
    pub fn decrypt_bytes(&self, pack: &DlcPack) -> Result<Vec<u8>, DlcLoaderError> {
        pack.decrypt_entry_bytes(&self.path)
    }

    pub fn path(&self) -> AssetPath<'_> {
        bevy::asset::AssetPath::parse(&self.path)
    }

    pub fn original_extension(&self) -> &String {
        &self.original_extension
    }

    pub fn type_path(&self) -> Option<&String> {
        self.type_path.as_ref()
    }
}


/// Represents a `.dlcpack` bundle (multiple encrypted entries).
/// The loader retains the encrypted container bytes so entries can be
/// decrypted on demand (e.g. after unlock).
#[derive(Asset, TypePath, Clone, Debug)]
pub struct DlcPack {
    dlc_id: DlcId,
    entries: Vec<DlcPackEntry>,
    /// Original `.dlcpack` container bytes (still encrypted). Kept so
    /// callers can decrypt individual entries on-demand without the pack
    /// loader doing eager decryption.
    container_bytes: Vec<u8>,
}

impl DlcPack {
    /// Return the DLC identifier for this pack.
    pub fn id(&self) -> &DlcId {
        &self.dlc_id
    }

    /// Return a slice of contained entries.
    pub fn entries(&self) -> &[DlcPackEntry] {
        &self.entries
    }

    /// Return the raw `.dlcpack` container bytes retained by the asset.
    pub fn container_bytes(&self) -> &[u8] {
        &self.container_bytes
    }

    /// Find an entry by its registered path
    pub fn find_entry(&self, path: &str) -> Option<&DlcPackEntry> {
        self.entries
            .iter()
            .find(|e| e.path().to_string().ends_with(path) || e.path().path().ends_with(path))
    }

    /// Find all entries that match the specified asset type `A`.
    pub fn find_by_type<A: Asset>(&self) -> Vec<&DlcPackEntry> {
        self.entries
            .iter()
            .filter(|e| match e.type_path() {
                Some(tp) => fuzzy_type_path_match(tp, A::type_path()),
                None => false,
            })
            .collect()
    }

    /// Decrypt an entry (accepts either `name` or `packfile.dlcpack#name`) by
    /// using the retained `container_bytes`. Returns plaintext or `DlcLocked`.
    pub fn decrypt_entry_bytes(
        &self,
        entry_path: &str,
    ) -> Result<Vec<u8>, crate::asset_loader::DlcLoaderError> {
        // Decrypt the pack once (checks global encrypt-key registry) and
        // extract the requested entry.
        let (_dlc_id, items) =
            crate::asset_loader::decrypt_pack_entries(&self.container_bytes).map_err(|e| e)?;

        // accept either "test.png" or "packfile.dlcpack#test.png" by
        // splitting on '#' and using the suffix when present.
        let subpath = match entry_path.rsplit_once('#') {
            Some((_, suffix)) => suffix,
            None => entry_path,
        };

        for (p, _ext, _tp, plaintext) in items.into_iter() {
            if p == subpath {
                return Ok(plaintext);
            }
        }
        Err(crate::asset_loader::DlcLoaderError::InvalidFormat(format!(
            "entry not found in container: {}",
            entry_path
        )))
    }

    pub fn load<A: Asset>(
        &self,
        asset_server: &bevy::prelude::AssetServer,
        entry_path: &str,
    ) -> Option<Handle<A>> {
        let entry = match self.find_entry(entry_path) {
            Some(e) => e,
            None => return None,
        };
        Some(asset_server.load::<A>(entry.path()))
    }
}

/// `AssetLoader` for `.dlcpack` bundles (contains multiple encrypted entries).
///
/// When the encrypt key is available in the registry at load time (i.e. the
/// DLC is already unlocked), each entry is immediately decrypted and registered
/// as a typed labeled sub-asset so `asset_server.load("pack.dlcpack#entry.png")`
/// returns the correct `Handle<T>` for the extension's loader (e.g. `Handle<Image>`
/// for `.png`). No asset type is hardcoded here — the correct type is determined
/// purely by extension dispatch via Bevy's `immediate()` loader, and the result
/// is downcast + registered using the list of `ErasedSubAssetRegistrar`s that
/// `DlcPlugin::build` populates.
///
/// When the encrypt key is *not* yet available the pack is still loaded
/// successfully (entries list is populated from the manifest) but the labeled
/// sub-assets are not added — `reload_assets_on_unlock_system` will reload the
/// pack once the key arrives, and the second load will succeed.
#[derive(TypePath, Default)]
pub struct DlcPackLoader {
    /// Ordered list of per-type registrars. `DlcPlugin::build` pushes one
    /// `TypedSubAssetRegistrar<A>` for every `A` it also registers via
    /// `init_asset_loader::<DlcLoader<A>>()`. The loader tries each in turn
    /// and uses the first successful downcast.
    pub registrars: Vec<Box<dyn ErasedSubAssetRegistrar>>,
    /// Optional shared reference to the `DlcPackRegistrarFactories` resource so
    /// the loader can observe updates to the factory list at runtime without
    /// requiring the asset loader to be re-registered.
    pub(crate) factories: Option<DlcPackRegistrarFactories>,
}

/// Factory trait used to create `ErasedSubAssetRegistrar` instance.
///
/// Implement `TypedRegistrarFactory<T>` for asset types to produce a
/// `TypedSubAssetRegistrar::<T>` at collection time.
pub trait DlcPackRegistrarFactory: Send + Sync + 'static {
    fn type_name(&self) -> &'static str;
    fn create_registrar(&self) -> Box<dyn ErasedSubAssetRegistrar>;
}

/// Generic typed factory that constructs `TypedSubAssetRegistrar::<T>`.
pub struct TypedRegistrarFactory<T: Asset + 'static>(std::marker::PhantomData<T>);

impl<T: Asset + TypePath + 'static> DlcPackRegistrarFactory for TypedRegistrarFactory<T> {
    fn type_name(&self) -> &'static str {
        T::type_path()
    }

    fn create_registrar(&self) -> Box<dyn ErasedSubAssetRegistrar> {
        Box::new(TypedSubAssetRegistrar::<T>::default())
    }
}

impl<T: Asset + 'static> Default for TypedRegistrarFactory<T> {
    fn default() -> Self {
        TypedRegistrarFactory(std::marker::PhantomData)
    }
}

use std::sync::RwLock;

/// Internal factory resource used by `AppExt::register_dlc_type` so user code
/// can request additional pack-registrars without pushing closures.
///
/// The resource wraps an `Arc<RwLock<_>>` so the registered `DlcPackLoader`
/// instance can hold a cheap clone and observe updates made by
/// `register_dlc_type(...)` without needing to re-register the loader.
#[derive(Clone, Resource)]
pub(crate) struct DlcPackRegistrarFactories(pub Arc<RwLock<Vec<Box<dyn DlcPackRegistrarFactory>>>>);

impl Default for DlcPackRegistrarFactories {
    fn default() -> Self {
        DlcPackRegistrarFactories(Arc::new(RwLock::new(Vec::new())))
    }
}

/// Return the default set of pack registrar factories used by `DlcPlugin`.
///
/// Using factory objects avoids closures and makes it trivial to add custom
/// typed factories in user code (box a `TypedRegistrarFactory::<T>`).
pub(crate) fn default_pack_registrar_factories() -> Vec<Box<dyn DlcPackRegistrarFactory>> {
    vec![
        Box::new(TypedRegistrarFactory::<Image>::default()),
        Box::new(TypedRegistrarFactory::<Scene>::default()),
        Box::new(TypedRegistrarFactory::<bevy::mesh::Mesh>::default()),
        Box::new(TypedRegistrarFactory::<Font>::default()),
        Box::new(TypedRegistrarFactory::<AudioSource>::default()),
        Box::new(TypedRegistrarFactory::<ColorMaterial>::default()),
        Box::new(TypedRegistrarFactory::<bevy::pbr::StandardMaterial>::default()),
        Box::new(TypedRegistrarFactory::<bevy::gltf::Gltf>::default()),
        Box::new(TypedRegistrarFactory::<bevy::gltf::GltfMesh>::default()),
        Box::new(TypedRegistrarFactory::<Shader>::default()),
        Box::new(TypedRegistrarFactory::<DynamicScene>::default()),
        Box::new(TypedRegistrarFactory::<AnimationClip>::default()),
        Box::new(TypedRegistrarFactory::<AnimationGraph>::default()),
    ]
}

/// Build the final `registrars` vector by combining factory objects supplied via
/// the `DlcPackRegistrarFactories` resource with the crate's default factories.
pub(crate) fn collect_pack_registrars(
    factories: Option<&DlcPackRegistrarFactories>,
) -> Vec<Box<dyn ErasedSubAssetRegistrar>> {
    use std::collections::HashSet;
    let mut seen: HashSet<&'static str> = HashSet::new();
    let mut out: Vec<Box<dyn ErasedSubAssetRegistrar>> = Vec::new();

    if let Some(f) = factories {
        let inner = f.0.read().unwrap();
        for factory in inner.iter() {
            out.push(factory.create_registrar());
            seen.insert(factory.type_name());
        }
    }

    for factory in default_pack_registrar_factories() {
        if !seen.contains(factory.type_name()) {
            out.push(factory.create_registrar());
            seen.insert(factory.type_name());
        }
    }

    out
}

impl AssetLoader for DlcPackLoader {
    type Asset = DlcPack;
    type Settings = ();
    type Error = DlcLoaderError;

    fn extensions(&self) -> &[&str] {
        &["dlcpack"]
    }

    async fn load(
        &self,
        reader: &mut dyn Reader,
        _settings: &Self::Settings,
        load_context: &mut LoadContext<'_>,
    ) -> Result<Self::Asset, Self::Error> {
        let path_string = load_context.path().path().to_string_lossy().to_string();

        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.map_err(|e| {
            error!(
                "Failed to read DLC pack file at '{}': {}. \
                    \nCheck that the file exists and is readable in your configured asset source.",
                path_string, e
            );
            DlcLoaderError::Io(e)
        })?;

        let (_product, dlc_id, _version, manifest_entries) = crate::parse_encrypted_pack(&bytes)
            .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

        // Check for DLC ID conflicts: reject if a DIFFERENT pack file is being loaded for the same DLC ID.
        // Allow the same pack file to be loaded multiple times (e.g., when accessing labeled sub-assets).
        let existing_paths = crate::encrypt_key_registry::asset_paths_for(&dlc_id);
        if !existing_paths.is_empty() && existing_paths[0] != path_string {
            return Err(DlcLoaderError::DlcIdConflict(
                dlc_id.clone(),
                existing_paths[0].clone(),
                path_string.clone(),
            ));
        }

        // Register this asset path for the dlc id so it can be reloaded on unlock.
        // If the path already exists for this DLC ID, it's idempotent (same pack file).
        if !crate::encrypt_key_registry::path_exists_for(&dlc_id, &path_string) {
            crate::encrypt_key_registry::register_asset_path(&dlc_id, &path_string);
        }

        // Try to decrypt all entries immediately when the encrypt key is present.
        // Offload decryption + archive extraction to Bevy's compute thread pool so
        // we don't block the asset loader threads on heavy CPU work. If the key
        // is missing we still populate the manifest so callers can inspect
        // entries; a reload after unlock will add the typed sub-assets.
        let decrypted_items: Option<Vec<(String, String, Option<String>, Vec<u8>)>> = {
            // clone bytes for the blocking task so we can continue to own the
            // original `bytes` for `container_bytes` later
            let bytes_for_task = bytes.clone();
            let task = bevy::tasks::AsyncComputeTaskPool::get()
                .spawn(async move { decrypt_pack_entries(&bytes_for_task) });

            match task.await {
                Ok((_id, items)) => Some(items),
                Err(DlcLoaderError::DlcLocked(_)) => None,
                Err(e) => return Err(e),
            }
        };

        let mut out_entries = Vec::with_capacity(manifest_entries.len());

        let mut unregistered_labels: Vec<String> = Vec::new();

        // Collect all available registrars once per pack load to avoid heavy
        // overhead from shared resource locking/matching inside the loop.
        let dynamic_regs = self
            .factories
            .as_ref()
            .map(|f| crate::asset_loader::collect_pack_registrars(Some(f)));
        let regs = dynamic_regs.unwrap_or_else(|| collect_pack_registrars(None));

        for (path, enc) in manifest_entries.into_iter() {
            let entry_label = path.replace('\\', "/");

            // Track whether a typed labeled asset was successfully registered
            // for this entry. If `false` after processing, the pack still
            // contains the entry but no labeled asset will be available via
            // `pack.dlcpack#entry` (AssetServer will report it as missing).
            let mut registered_as_labeled = false;

            // Try to load this entry as a typed sub-asset when plaintext is available.
            if let Some(ref items) = decrypted_items {
                if let Some((_, ext, type_path, plaintext)) =
                    items.iter().find(|(p, _, _, _)| p == &path)
                {
                    // Build a fake path with the correct extension so
                    // `load_context.loader()` selects the right concrete loader
                    // by extension (e.g. `.png` → ImageLoader, `.json` → JsonLoader).
                    let stem = std::path::Path::new(&entry_label)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("entry");
                    let fake_path = format!("{}.{}", stem, ext);

                    let mut vec_reader = bevy::asset::io::VecReader::new(plaintext.clone());

                    // 1. Guided load: if `type_path` is present in the container metadata,
                    // attempt to find a matching registrar and load directly using
                    // that type. This bypasses extension-based dispatch entirely.
                    if let Some(tp) = type_path {
                        if let Some(registrar) =
                            regs.iter().find(|r| fuzzy_type_path_match(r.asset_type_path(), tp))
                        {
                            match registrar
                                .load_direct(
                                    entry_label.clone(),
                                    fake_path.clone(),
                                    &mut vec_reader,
                                    load_context,
                                )
                                .await
                            {
                                Ok(()) => {
                                    registered_as_labeled = true;
                                }
                                Err(e) => {
                                    // if static load failed, we still have a chance with
                                    // extension-based dispatch below (rare but possible).
                                    debug!(
                                        "DlcPackLoader: static load for type '{}' failed: {}; falling back to extension dispatch",
                                        tp, e
                                    );
                                }
                            }
                        }
                    }

                    // 2. Extension dispatch: Bevy picks the right loader based on `fake_path`
                    // extension. We then try to match the resulting erased asset against
                    // all known registrars to register it as a labeled sub-asset.
                    if !registered_as_labeled {
                        let mut vec_reader = bevy::asset::io::VecReader::new(plaintext.clone());
                        let result = load_context
                            .loader()
                            .immediate()
                            .with_reader(&mut vec_reader)
                            .with_unknown_type()
                            .load(fake_path.clone())
                            .await;

                        match result {
                            Ok(erased) => {
                                let mut remaining = Some(erased);

                                for registrar in regs.iter() {
                                    let label = entry_label.clone();
                                    let to_register = remaining.take().unwrap();
                                    match registrar.try_register(label, to_register, load_context) {
                                        Ok(()) => {
                                            registered_as_labeled = true;
                                            remaining = None;
                                            break;
                                        }
                                        Err(back) => {
                                            remaining = Some(back);
                                        }
                                    }
                                }

                                if let Some(_) = remaining {
                                    warn!(
                                        "DlcPackLoader: entry '{}' (fake_path='{}') present in container but no registered asset type matched (extension='{}'); the asset will NOT be available as 'pack#{}'. Register a loader with `app.register_dlc_type::<T>()` or supply `type_path` when packing.",
                                        entry_label, fake_path, ext, entry_label
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "DlcPackLoader: failed to load entry '{}' (fake_path='{}', extension='{}'): {}",
                                    entry_label, fake_path, ext, e
                                );
                            }
                        }
                    }
                }
            }

            // Build the labeled registered path for the DlcPackEntry.
            let registered_path = format!("{}#{}", path_string, entry_label);

            if !registered_as_labeled {
                unregistered_labels.push(entry_label.clone());
            }

            out_entries.push(DlcPackEntry {
                path: registered_path,
                original_extension: enc.original_extension,
                type_path: enc.type_path,
            });
        }

        // If any entries were not registered as labeled assets, emit a single
        // summary warning that explains why `AssetServer::load("pack#entry")`
        // will report the labeled asset as missing (see user-facing error).
        if !unregistered_labels.is_empty() {
            warn!(
                "DlcPackLoader: {} {} in '{}' were not registered as labeled assets and will be inaccessible via 'pack#entry': {}. See earlier warnings for details or register the appropriate loader via `app.register_dlc_type::<T>()`.",
                unregistered_labels.len(),
                if unregistered_labels.len() == 1 {
                    "entry"
                } else {
                    "entries"
                },
                path_string,
                unregistered_labels.join(", ")
            );
        }

        Ok(DlcPack {
            dlc_id: DlcId::from(dlc_id),
            entries: out_entries,
            container_bytes: bytes,
        })
    }
}

/// Decrypt entries out of a `.dlcpack` container.
/// Returns `(dlc_id, Vec<(path, original_extension, plaintext)>)`.
pub fn decrypt_pack_entries(
    pack_bytes: &[u8],
) -> Result<(String, Vec<(String, String, Option<String>, Vec<u8>)>), DlcLoaderError> {
    let (_product, dlc_id, version, entries) = crate::parse_encrypted_pack(pack_bytes)
        .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

    // lookup encrypt key in global registry
    let encrypt_key = crate::encrypt_key_registry::get(&dlc_id)
        .ok_or_else(|| DlcLoaderError::DlcLocked(dlc_id.clone()))?;

    // Version 1: each entry encrypted individually — decrypt entries in parallel
    // to improve load latency when a pack contains many small encrypted files.
    if version == 1 {
        use std::sync::Arc;

        // move the EncryptionKey into an Arc so it can be shared across worker
        // threads without cloning the secret bytes.
        let key_for_tasks = Arc::new(encrypt_key);

        // perform per-entry decryption in parallel using Rayon
        let results: Vec<Result<(String, String, Option<String>, Vec<u8>), DlcLoaderError>> =
            entries
                .into_par_iter()
                .map(|(path, enc)| {
                    let plaintext =
                        crate::decrypt_with_key(&*key_for_tasks, &enc.ciphertext, &enc.nonce)
                            .map_err(|e| {
                                let inner_error = e.to_string();
                                let msg = format!(
                                    "dlc='{}' entry='{}' {}",
                                    dlc_id,
                                    path,
                                    if inner_error.is_empty() {
                                        "".to_string()
                                    } else {
                                        inner_error
                                    }
                                );
                                DlcLoaderError::DecryptionFailed(msg)
                            })?;
                    Ok((path, enc.original_extension, enc.type_path, plaintext))
                })
                .collect();

        // propagate any error or collect plaintexts
        let mut out = Vec::with_capacity(results.len());
        for r in results {
            match r {
                Ok(v) => out.push(v),
                Err(e) => return Err(e),
            }
        }
        return Ok((dlc_id, out));
    }

    // Version >= 2: single encrypted gzip archive + plaintext manifest
    if entries.is_empty() {
        return Ok((dlc_id, Vec::new()));
    }

    // all entries reference the same encrypted archive (nonce + ciphertext)
    let archive_nonce = entries[0].1.nonce;
    let archive_ciphertext = &entries[0].1.ciphertext;

    // decrypt the entire archive once
    let archive_plain = crate::decrypt_with_key(&encrypt_key, archive_ciphertext, &archive_nonce)
        .map_err(|e| {
        // report which DLC failed; include an example entry for context
        let example_entry = &entries[0].0;
        let msg = format!(
            "dlc='{}' entry='{}' {}",
            dlc_id,
            example_entry,
            e.to_string()
        );

        DlcLoaderError::DecryptionFailed(msg)
    })?;

    // decompress tar.gz and extract files
    use flate2::read::GzDecoder;
    use std::io::Read;
    use tar::Archive;

    let mut archive = Archive::new(GzDecoder::new(std::io::Cursor::new(archive_plain)));
    let mut extracted: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    for entry in archive.entries().map_err(|e| {
        DlcLoaderError::DecryptionFailed(format!("dlc='{}' archive read failed: {}", dlc_id, e))
    })? {
        let mut file = entry.map_err(|e| {
            DlcLoaderError::DecryptionFailed(format!(
                "dlc='{}' archive entry read failed: {}",
                dlc_id, e
            ))
        })?;
        let path = file.path().map_err(|e| {
            DlcLoaderError::DecryptionFailed(format!("dlc='{}' archive path error: {}", dlc_id, e))
        })?;
        let path_str = path.to_string_lossy().replace("\\", "/");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| {
            DlcLoaderError::DecryptionFailed(format!("dlc='{}' read file failed: {}", dlc_id, e))
        })?;
        extracted.insert(path_str.to_string(), buf);
    }

    // build output list using manifest metadata from `entries`
    let mut out = Vec::with_capacity(entries.len());
    for (path, enc) in entries.into_iter() {
        // normalize manifest path (manifest paths may contain Windows backslashes);
        // extracted archive paths are normalized to forward slashes above.
        let normalized = path.replace("\\", "/");
        match extracted
            .remove(&normalized)
            .or_else(|| extracted.remove(&path))
        {
            Some(bytes) => out.push((path, enc.original_extension, enc.type_path, bytes)),
            None => {
                return Err(DlcLoaderError::DecryptionFailed(format!(
                    "dlc='{}' missing entry in archive: {}",
                    dlc_id, path
                )));
            }
        }
    }

    Ok((dlc_id, out))
}

#[derive(Error, Debug)]
pub enum DlcLoaderError {
    #[error("IO error: {0}")]
    Io(io::Error),
    #[error("DLC locked: encrypt key not found for DLC id: {0}")]
    DlcLocked(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid encrypted asset format: {0}")]
    InvalidFormat(String),
    #[error(
        "DLC ID conflict: a .dlcpack with DLC id '{0}' is already loaded; cannot load another pack with the same DLC id, original: {1}, new: {2}"
    )]
    DlcIdConflict(String, String, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionKey, PackItem};

    #[test]
    fn dlcpack_accessors_work_and_fields_read() {
        let entry = DlcPackEntry {
            path: "a.txt".to_string(),
            original_extension: "txt".to_string(),
            type_path: None,
        };
        let pack = DlcPack {
            dlc_id: DlcId::from("example_dlc"),
            entries: vec![entry.clone()],
            container_bytes: Vec::new(),
        };

        // exercise getters (reads `dlc_id` + `entries` fields)
        assert_eq!(*pack.id(), DlcId::from("example_dlc"));
        assert_eq!(pack.entries().len(), 1);

        // inspect an entry (reads `path`, `original_extension`)
        let found = pack.find_entry("a.txt").expect("entry present");
        assert_eq!(found.path, "a.txt");
        assert_eq!(found.original_extension, "txt");
        assert!(found.type_path.is_none());
    }

    #[test]
    fn decrypt_pack_entries_without_key_returns_locked_error() {
        crate::encrypt_key_registry::clear_all();
        let dlc_id = crate::DlcId::from("locked_dlc");
        let items = vec![
            PackItem::new("a.txt", b"hello".to_vec()),
        ];
        let key = EncryptionKey::from_random(32);
        let dlc_key = crate::DlcKey::generate_random();
        let product = crate::Product::from("test");
        let container =
            crate::pack_encrypted_pack(&dlc_id, &items, &product, &dlc_key, &key).expect("pack");

        let err = decrypt_pack_entries(&container).expect_err("should be locked");
        match err {
            DlcLoaderError::DlcLocked(id) => assert_eq!(id, "locked_dlc"),
            _ => panic!("expected DlcLocked error, got {:?}", err),
        }
    }

    #[test]
    fn decrypt_pack_entries_with_wrong_key_reports_entry_and_dlc() {
        crate::encrypt_key_registry::clear_all();
        let dlc_id = crate::DlcId::from("badkey_dlc");
        let items = vec![
            PackItem::new("b.txt", b"world".to_vec()),
        ];
        let real_key = EncryptionKey::from_random(32);
        let dlc_key = crate::DlcKey::generate_random();
        let product = crate::Product::from("test");
        let container = crate::pack_encrypted_pack(&dlc_id, &items, &product, &dlc_key, &real_key)
            .expect("pack");

        // insert an incorrect key for this DLC
        let wrong_key: [u8; 32] = rand::random();
        crate::encrypt_key_registry::insert(
            &dlc_id.to_string(),
            crate::EncryptionKey::from(wrong_key.to_vec()),
        );

        let err = decrypt_pack_entries(&container).expect_err("should fail decryption");
        match err {
            DlcLoaderError::DecryptionFailed(msg) => {
                assert!(msg.contains("dlc='badkey_dlc'"));
                assert!(msg.contains("entry='b.txt'"));
                // ensure inner cause is propagated (auth failed for wrong key)
                assert!(msg.contains("authentication failed") || msg.contains("incorrect key"));
            }
            _ => panic!("expected DecryptionFailed, got {:?}", err),
        }
    }

    #[test]
    fn dlc_id_conflict_detection() {
        // Verify that loading different packs with the same DLC ID returns a conflict error,
        // but loading the same pack multiple times is allowed.
        crate::encrypt_key_registry::clear_all();

        let dlc_id_str = "conflict_test_dlc";
        let pack_path_1 = "existing_pack.dlcpack";
        let pack_path_2 = "different_pack.dlcpack";

        // Register a dummy path to simulate a pack already being loaded
        crate::encrypt_key_registry::register_asset_path(dlc_id_str, pack_path_1);

        // Verify that the registry shows paths exist (retry briefly to avoid rare parallel-test races caused by tests/common/mod.rs)
        let mut paths = crate::encrypt_key_registry::asset_paths_for(dlc_id_str);
        let mut tries = 0;
        while paths.is_empty() && tries < 100 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            paths = crate::encrypt_key_registry::asset_paths_for(dlc_id_str);
            tries += 1;
        }
        assert!(!paths.is_empty(), "paths should exist after registering");

        // Same path should NOT be detected as a conflict (idempotent)
        let same_path_conflict = crate::encrypt_key_registry::check(dlc_id_str, pack_path_1);
        assert!(
            !same_path_conflict,
            "same pack path should NOT be a conflict"
        );

        // Different path SHOULD be detected as a conflict
        let diff_path_conflict = crate::encrypt_key_registry::check(dlc_id_str, pack_path_2);
        assert!(
            diff_path_conflict,
            "different pack path SHOULD be detected as a conflict"
        );

        crate::encrypt_key_registry::clear_all();
    }
}

impl<A> AssetLoader for DlcLoader<A>
where
    A: bevy::asset::Asset + TypePath + 'static,
{
    type Asset = A;
    type Settings = ();
    type Error = DlcLoaderError;

    fn extensions(&self) -> &[&str] {
        &["dlc", "dlcenc"]
    }

    async fn load(
        &self,
        reader: &mut dyn Reader,
        _settings: &Self::Settings,
        load_context: &mut LoadContext<'_>,
    ) -> Result<Self::Asset, Self::Error> {
        // capture the original requested path (for registry/bookkeeping)
        let path_string = Some(load_context.path().path().to_string_lossy().to_string());

        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| DlcLoaderError::Io(e))?;

        let enc =
            parse_encrypted(&bytes).map_err(|e| DlcLoaderError::DecryptionFailed(e.to_string()))?;

        // register this asset path for the dlc id so it can be reloaded on unlock
        if let Some(p) = &path_string {
            crate::encrypt_key_registry::register_asset_path(&enc.dlc_id, p);
        }

        // lookup encrypt key in global registry (loader-executed outside ECS)
        let encrypt_key = crate::encrypt_key_registry::get(&enc.dlc_id)
            .ok_or_else(|| DlcLoaderError::DlcLocked(enc.dlc_id.clone()))?;

        // decrypt bytes
        let plaintext = crate::decrypt_with_key(&encrypt_key, &enc.ciphertext, &enc.nonce)
            .map_err(|e| {
                let inner_error = e.to_string();
                let msg = format!(
                    "dlc='{}' path='{}' {}",
                    enc.dlc_id,
                    path_string.unwrap_or_else(|| "<unknown>".to_string()),
                    if inner_error.is_empty() {
                        "".to_string()
                    } else {
                        format!("{}", inner_error)
                    }
                );

                DlcLoaderError::DecryptionFailed(msg)
            })?;

        // Choose an extension for the nested load so Bevy can pick a concrete
        // loader if one exists. We keep the extension around so we can retry
        // with it if the straightforward, static-type load fails. Prioritizing
        // a static-type request avoids the need to downcast an erased asset,
        // which is more efficient and sidesteps the edge cases where the
        // extension loader returns a different type.
        let ext = enc.original_extension;

        // Keep plaintext bytes around so we can recreate readers as needed.
        let bytes_clone = plaintext.clone();

        let stem = load_context
            .path()
            .path()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("dlc_decrypted");
        let fake_path = format!("{}.{}", stem, ext);

        // First attempt a direct static-type load. This bypasses extension
        // dispatch entirely and returns a value of `A` if a loader exists for
        // that type. Only if this fails do we fall back to using the extension
        // and performing a downcast.
        {
            let mut static_reader = bevy::asset::io::VecReader::new(bytes_clone.clone());
            if let Ok(loaded) = load_context
                .loader()
                .with_static_type()
                .immediate()
                .with_reader(&mut static_reader)
                .load::<A>(fake_path.clone())
                .await
            {
                return Ok(loaded.take());
            }
        }

        // Static load didn't succeed. Try using the extension to select a loader
        // and then downcast the result to `A`. This mirrors how the normal
        // AssetServer would work when loading a file from disk.
        if !ext.is_empty() {
            let mut ext_reader = bevy::asset::io::VecReader::new(bytes_clone);
            let attempt = load_context
                .loader()
                .immediate()
                .with_reader(&mut ext_reader)
                .with_unknown_type()
                .load(fake_path.clone())
                .await;

            if let Ok(erased) = attempt {
                match erased.downcast::<A>() {
                    Ok(loaded) => return Ok(loaded.take()),
                    Err(_) => return Err(DlcLoaderError::DecryptionFailed(format!(
                        "dlc loader: extension-based load succeeded but downcast to '{}' failed",
                        A::type_path(),
                    ))),
                }
            } else if let Err(e) = attempt {
                return Err(DlcLoaderError::DecryptionFailed(e.to_string()));
            }
        }

        // If we reach here it means neither static nor extension-based loading
        // succeeded; return an appropriate error. The original static attempt
        // already logged a warning, so just surface a generic message.
        Err(DlcLoaderError::DecryptionFailed(format!(
            "dlc loader: unable to load decrypted asset as {}{}",
            A::type_path(), if ext.is_empty() { "" } else { " (extension fallback also failed)" }
        )))
    }
}
