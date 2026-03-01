use bevy::asset::io::Reader;
use bevy::asset::{
    Asset, AssetLoader, AssetPath, ErasedLoadedAsset, Handle, LoadContext, LoadedUntypedAsset,
};
use bevy::ecs::reflect::AppTypeRegistry;
use bevy::prelude::*;
use bevy::reflect::TypePath;
use futures_lite::{AsyncReadExt, AsyncSeekExt};
use std::io;
use std::sync::Arc;
use thiserror::Error;

use crate::{DlcId, PackItem, Product};

use std::io::{Read, Seek, SeekFrom};

/// Adapter that exposes a `std::io::Read + std::io::Seek` view over a
/// `bevy::asset::io::Reader`.  This is used by pack-parsing routines so we can
/// operate on the async reader without copying the entire file into memory.
///
/// The implementation simply blocks on the underlying async methods using
/// [`pollster::block_on`].  Seeking works only when the wrapped reader is
/// seekable; otherwise the `seek()` call returns an error.
pub struct SyncReader<'a> {
    inner: &'a mut dyn bevy::asset::io::Reader,
}

impl<'a> SyncReader<'a> {
    pub fn new(inner: &'a mut dyn bevy::asset::io::Reader) -> Self {
        SyncReader { inner }
    }
}

impl<'a> Read for SyncReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        bevy::tasks::block_on(self.inner.read(buf))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl<'a> Seek for SyncReader<'a> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self.inner.seekable() {
            Ok(seek) => bevy::tasks::block_on(seek.seek(pos))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "reader not seekable",
            )),
        }
    }
}

/// Decompress a gzip‑compressed tar archive from `plaintext` and return a map from
/// internal path -> contents.  Errors are mapped into `DlcLoaderError::DecryptionFailed`
/// because the only callers are the pack loader and entry decrypt which already treat
/// archive failures as decryption problems.
fn decompress_archive(
    plaintext: &[u8],
) -> Result<std::collections::HashMap<String, Vec<u8>>, DlcLoaderError> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    use tar::Archive;

    let mut archive = Archive::new(GzDecoder::new(std::io::Cursor::new(plaintext)));
    let mut map = std::collections::HashMap::new();
    for entry in archive
        .entries()
        .map_err(|e| DlcLoaderError::DecryptionFailed(format!("archive read failed: {}", e)))?
    {
        let mut file = entry.map_err(|e| {
            DlcLoaderError::DecryptionFailed(format!("archive entry read failed: {}", e))
        })?;
        let path = file
            .path()
            .map_err(|e| DlcLoaderError::DecryptionFailed(format!("archive path error: {}", e)))?;
        let path_str = path.to_string_lossy().replace("\\", "/");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| {
            DlcLoaderError::DecryptionFailed(format!("archive file read failed: {}", e))
        })?;
        map.insert(path_str, buf);
    }
    Ok(map)
}

/// Internal helper to decrypt a specific entry from a v4 pack by reading only
/// the required data block from the file.
pub(crate) fn decrypt_pack_entry_block_bytes<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    enc: &EncryptedAsset,
    key: &crate::EncryptionKey,
    full_path: &str,
) -> Result<Vec<u8>, DlcLoaderError> {
    // 1. Re-parse the pack to get the block metadata
    let _original_pos = reader
        .stream_position()
        .map_err(|e| DlcLoaderError::Io(e))?;
    reader
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| DlcLoaderError::Io(e))?;

    let (_prod, _id, _ver, _entries, blocks) = crate::parse_encrypted_pack(&mut *reader)
        .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

    let block = blocks
        .iter()
        .find(|b| b.block_id == enc.block_id)
        .ok_or_else(|| {
            DlcLoaderError::DecryptionFailed(format!("block {} not found in pack", enc.block_id))
        })?;

    // 2. Decrypt only the bytes corresponding to the desired block.  The
    // pack format writes all blocks concatenated after the metadata, and
    // `parse_encrypted_pack` leaves the reader positioned at the start of the
    // ciphertext region.  We still seek explicitly to the recorded offset to
    // be robust and to support callers that may have moved the reader.
    reader
        .seek(std::io::SeekFrom::Start(block.file_offset))
        .map_err(|e| DlcLoaderError::Io(e))?;

    // limit the reader to the block size so `decrypt_with_key` doesn't read
    // past the boundary when multiple blocks exist.
    let mut limited = reader.take(block.encrypted_size as u64);
    let pt_gz = crate::pack_format::decrypt_with_key(&key, &mut limited, &block.nonce)
        .map_err(|e| DlcLoaderError::DecryptionFailed(e.to_string()))?;

    // 3. Decompress and find entry
    let entries = decompress_archive(&pt_gz)?;

    // Extract label from "pack.dlcpack#label"
    let label = match full_path.rsplit_once('#') {
        Some((_, suffix)) => suffix,
        None => full_path,
    }
    .replace("\\", "/");

    entries.get(&label).cloned().ok_or_else(|| {
        DlcLoaderError::DecryptionFailed(format!(
            "entry '{}' not found in decrypted block {}",
            label, enc.block_id
        ))
    })
}

/// Event fired when a DLC pack is successfully loaded.
#[derive(Event, Clone)]
pub struct DlcPackLoaded {
    dlc_id: DlcId,
    pack: DlcPack,
}

impl DlcPackLoaded {
    pub(crate) fn new(dlc_id: DlcId, pack: DlcPack) -> Self {
        DlcPackLoaded { dlc_id, pack }
    }

    /// Return the DLC identifier for the loaded pack.
    pub fn id(&self) -> &DlcId {
        &self.dlc_id
    }

    /// Return a reference to the loaded `DlcPack`. The pack contains metadata about the DLC and provides methods to decrypt and load individual entries.
    pub fn pack(&self) -> &DlcPack {
        &self.pack
    }
}

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
#[derive(Clone, Debug, Asset, TypePath)]
pub struct EncryptedAsset {
    pub dlc_id: String,
    pub original_extension: String,
    /// Optional serialized type identifier (e.g. `bevy::image::Image`)
    pub type_path: Option<String>,
    pub nonce: [u8; 12],
    pub ciphertext: std::sync::Arc<[u8]>,
    // --- v4 format extensions ---
    pub block_id: u32,
    pub block_offset: u32,
    pub size: u32,
}

impl EncryptedAsset {
    /// Decrypt the ciphertext contained in this `EncryptedAsset`, using the
    /// global encryption-key registry to look up the correct key for
    /// `self.dlc_id`.
    pub(crate) fn decrypt_bytes(&self) -> Result<Vec<u8>, DlcLoaderError> {
        // lookup key
        let encrypt_key = crate::encrypt_key_registry::get(&self.dlc_id)
            .ok_or_else(|| DlcLoaderError::DlcLocked(self.dlc_id.clone()))?;

        // decrypt using the pack-format helper
        crate::pack_format::decrypt_with_key(
            &encrypt_key,
            std::io::Cursor::new(&*self.ciphertext),
            &self.nonce,
        )
        .map_err(|e| DlcLoaderError::DecryptionFailed(e.to_string()))
    }
}

/// Parse the binary encrypted-asset format from a byte slice. This is used by the pack loader when parsing the pack metadata, and also by the `DlcLoader` when decrypting individual entries (since the entry metadata is stored in the same format as a standalone encrypted file).
pub fn parse_encrypted(bytes: &[u8]) -> Result<EncryptedAsset, io::Error> {
    // make sure we can read the fixed-size header fields without panicking:
    // version (1 byte) + dlc_len (2 bytes) + ext_len (1 byte) + nonce (12 bytes)
    // the remaining lengths (dlc_id, ext, type_path, ciphertext) are variable
    // and validated later, so this check only guards the very earliest reads.
    if bytes.len() < 1 + 2 + 1 + 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted file too small",
        ));
    }
    let version = bytes[0];
    let mut offset = 1usize;

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
    let ciphertext = bytes[offset..].into();

    Ok(EncryptedAsset {
        dlc_id,
        original_extension,
        type_path,
        nonce,
        ciphertext,
        block_id: 0,
        block_offset: 0,
        size: 0,
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
    /// Encrypted asset metadata and ciphertext
    encrypted: EncryptedAsset,
}

impl DlcPackEntry {
    pub fn new(path: String, encrypted: EncryptedAsset) -> Self {
        DlcPackEntry { path, encrypted }
    }

    /// Convenience: load this entry's registered path via `AssetServer::load`.
    pub fn load_untyped(
        &self,
        asset_server: &bevy::prelude::AssetServer,
    ) -> Handle<LoadedUntypedAsset> {
        asset_server.load_untyped(&self.path)
    }

    /// Check if this entry is declared as type `A` (via the optional `type_path` in the container, which is independent of file extension). This is not used by the loader itself (which relies on extension-based dispatch) but can be used by user code to inspect entries or implement custom loading behavior.
    pub fn is_type<A: Asset>(&self) -> bool {
        match self.encrypted.type_path.as_ref() {
            Some(tp) => fuzzy_type_path_match(tp, A::type_path()),
            None => false,
        }
    }

    /// Decrypt and return the plaintext bytes for this entry.
    /// This consults the global encrypt-key registry and will return
    /// `DlcLoaderError::DlcLocked` when the encrypt key is not present.
    pub(crate) fn decrypt_bytes(&self) -> Result<Vec<u8>, DlcLoaderError> {
        let entry_ek = crate::encrypt_key_registry::get_full(&self.encrypted.dlc_id)
            .ok_or_else(|| DlcLoaderError::DlcLocked(self.encrypted.dlc_id.clone()))?;
        let encrypt_key = entry_ek.key;

        // v4 block‑based decryption only; older formats are no longer supported.
        let path = entry_ek.path.ok_or_else(|| {
            DlcLoaderError::DecryptionFailed(format!(
                "no file path registered for DLC '{}', cannot decrypt",
                self.encrypted.dlc_id
            ))
        })?;

        let mut file = std::fs::File::open(path).map_err(|e| {
            DlcLoaderError::DecryptionFailed(format!("failed to open pack file: {}", e))
        })?;

        crate::asset_loader::decrypt_pack_entry_block_bytes(
            &mut file,
            &self.encrypted,
            &encrypt_key,
            &self.path,
        )
    }

    pub fn path(&self) -> AssetPath<'_> {
        bevy::asset::AssetPath::parse(&self.path)
    }

    pub fn original_extension(&self) -> &String {
        &self.encrypted.original_extension
    }

    pub fn type_path(&self) -> Option<&String> {
        self.encrypted.type_path.as_ref()
    }
}

impl From<(String, EncryptedAsset)> for DlcPackEntry {
    fn from((path, encrypted): (String, EncryptedAsset)) -> Self {
        DlcPackEntry { path, encrypted }
    }
}

impl From<&(String, EncryptedAsset)> for DlcPackEntry {
    fn from((path, encrypted): &(String, EncryptedAsset)) -> Self {
        DlcPackEntry { path: path.clone(), encrypted: encrypted.clone() }
    }
}

/// Represents a `.dlcpack` bundle (multiple encrypted entries).
#[derive(Asset, TypePath, Clone, Debug)]
pub struct DlcPack {
    dlc_id: DlcId,
    product: Product,
    version: u8,
    entries: Vec<DlcPackEntry>,
}

impl DlcPack {
    pub fn new(id: DlcId, product: Product, version: u8, entries: Vec<DlcPackEntry>) -> Self {
        DlcPack {
            dlc_id: id,
            product,
            version,
            entries,
        }
    }

    /// Return the DLC identifier for this pack.
    pub fn id(&self) -> &DlcId {
        &self.dlc_id
    }

    /// Return the product name this pack belongs to.
    pub fn product(&self) -> &str {
        &self.product.0
    }

    /// Return the pack format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Return a slice of contained entries.
    pub fn entries(&self) -> &[DlcPackEntry] {
        &self.entries
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

    /// Decrypt an entry (accepts either `name` or `packfile.dlcpack#name`).
    /// Returns plaintext or `DlcLocked`.
    pub fn decrypt_entry(
        &self,
        entry_path: &str,
    ) -> Result<Vec<u8>, crate::asset_loader::DlcLoaderError> {
        // accept either "test.png" or "packfile.dlcpack#test.png" by
        // checking both relative and absolute paths
        let entry = self.find_entry(entry_path).ok_or_else(|| {
            DlcLoaderError::DecryptionFailed(format!("entry not found: {}", entry_path))
        })?;

        entry.decrypt_bytes()
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

        // Adapt the async `reader` to a synchronous `std::io::Read` so we can
        // drive the existing pack‑parsing logic without buffering the whole file
        // up front.  If the underlying reader is seekable we will also be able
        // rewind it later in order to extract the raw bytes needed for
        // decryption.
        let mut sync_reader = SyncReader::new(reader);

        let (product, dlc_id, version, manifest_entries, _block_metadatas) =
            crate::parse_encrypted_pack(&mut sync_reader)
                .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

        // rewind the reader back to the start so decryption routines can re‑parse the file as needed.  If the reader is not seekable, error.
        sync_reader.seek(SeekFrom::Start(0)).map_err(|_| {
            DlcLoaderError::Io(io::Error::new(
                io::ErrorKind::NotSeekable,
                format!("reader not seekable, cannot load pack '{}'", path_string),
            ))
        })?;

        // Check for DLC ID conflicts: reject if a DIFFERENT pack file is being loaded for the same DLC ID.
        // Allow the same pack file to be loaded multiple times (e.g., when accessing labeled sub-assets).
        let existing_path = crate::encrypt_key_registry::asset_path_for(dlc_id.as_ref());
        if let Some(existing_path) = existing_path {
            return Err(DlcLoaderError::DlcIdConflict(
                dlc_id.to_string(),
                existing_path.clone(),
                path_string.clone(),
            ));
        }

        // Register this asset path for the dlc id so it can be reloaded on unlock.
        // If the path already exists for this DLC ID, it's idempotent (same pack file).
        if !crate::encrypt_key_registry::has(dlc_id.as_ref(), &path_string) {
            crate::encrypt_key_registry::register_asset_path(dlc_id.as_ref(), &path_string);
        }

        // Try to decrypt all entries immediately when the encrypt key is present.
        // Offload decryption + archive extraction to Bevy's compute thread pool so
        // we don't block the asset loader threads on heavy CPU work. If the key
        // is missing we still populate the manifest so callers can inspect
        // entries; a reload after unlock will add the typed sub-assets.
        let decrypted_items = {
            match decrypt_pack_entries(sync_reader) {
                Ok::<(DlcId, Vec<PackItem>), DlcLoaderError>((_id, items)) => Some(items),
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
                if let Some(item) = items.iter().find(|i| i.path() == path) {
                    let ext = item.ext().unwrap_or_default();
                    let type_path = item.type_path();
                    let plaintext = item.plaintext().to_vec();
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
                        if let Some(registrar) = regs
                            .iter()
                            .find(|r| fuzzy_type_path_match(r.asset_type_path(), tp.as_str()))
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
                                        "Static load for type '{}' failed: {}; falling back to extension dispatch",
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
                                        "DLC entry '{}' present in container but no registered asset type matched (extension='{}'); the asset will NOT be available as '{}#{}'. Register a loader with `app.register_dlc_type::<T>()`",
                                        entry_label, ext, path_string, entry_label
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to load entry '{}', extension='{}': {}",
                                    entry_label, ext, e
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
                encrypted: enc,
            });
        }

        // If we actually had plaintext to attempt registration (i.e. the
        // pack was unlocked at load time) then unregistered_labels indicates a
        // genuine failure to match a loader.  When the pack is still locked we
        // intentionally avoid logging anything here because a later reload when
        // the key arrives will perform the real work and emit the warning.
        if decrypted_items.is_some() && !unregistered_labels.is_empty() {
            // provide a concrete example using the first unregistered label so
            // the user can see how to reference it with the pack path.
            let example_label = &unregistered_labels[0];
            let example_full = format!("{}#{}", path_string, example_label);
            warn!(
                "{} {} in '{}' were not registered as labeled assets and will be inaccessible via '{}'. See earlier warnings for details or register the appropriate loader via `app.register_dlc_type::<T>()`.",
                unregistered_labels.len(),
                if unregistered_labels.len() == 1 {
                    "entry"
                } else {
                    "entries"
                },
                path_string,
                example_full,
            );
        }

        Ok(DlcPack::new(
            dlc_id.clone(),
            product,
            version as u8,
            out_entries,
        ))
    }
}

/// Decrypt entries out of a `.dlcpack` container.
/// Returns `(dlc_id, Vec<(path, original_extension, plaintext)>)`.
/// Decrypt entries out of a `.dlcpack` container.
///
/// This no-longer requires keeping the entire file in memory; the caller
/// provides a `Read+Seek` reader.  Only the current v4 hybrid format is
/// supported, earlier versions have been removed along with their legacy
/// semantics.
///
/// Returns `(dlc_id, Vec<(path, original_extension, plaintext)>)`.
pub fn decrypt_pack_entries<R: std::io::Read + std::io::Seek>(
    mut reader: R,
) -> Result<(crate::DlcId, Vec<crate::PackItem>), DlcLoaderError> {
    let (_product, dlc_id, version, entries, block_metadatas) =
        crate::parse_encrypted_pack(&mut reader)
            .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

    // lookup encrypt key in global registry
    let encrypt_key = crate::encrypt_key_registry::get(dlc_id.as_ref())
        .ok_or_else(|| DlcLoaderError::DlcLocked(dlc_id.to_string()))?;

    // only v4 is supported anymore
    if version != 4 {
        return Err(DlcLoaderError::InvalidFormat(format!(
            "unsupported pack version: {}",
            version
        )));
    }

    let mut extracted_all = std::collections::HashMap::new();
    // use reader in a PackReader for convenience
    let mut pr = crate::pack_format::PackReader::new(reader);
    for block in block_metadatas {
        pr.seek(std::io::SeekFrom::Start(block.file_offset))
            .map_err(|e| DlcLoaderError::Io(e))?;
        let pt = pr
            .read_and_decrypt(&encrypt_key, block.encrypted_size as usize, &block.nonce)
            .map_err(|e| {
                let example = entries
                    .iter()
                    .find(|(_, enc)| enc.block_id == block.block_id)
                    .map(|(p, _)| p.as_str())
                    .unwrap_or("unknown");
                DlcLoaderError::DecryptionFailed(format!(
                    "dlc='{}' entry='{}' (block {}) decryption failed: {}",
                    dlc_id, example, block.block_id, e
                ))
            })?;
        let extracted = decompress_archive(&pt)?;
        extracted_all.extend(extracted);
    }

    let mut out = Vec::with_capacity(entries.len());
    for (path, enc) in entries {
        let normalized = path.replace("\\", "/");
        let plaintext = extracted_all
            .remove(&normalized)
            .or_else(|| extracted_all.remove(&path))
            .ok_or_else(|| {
                DlcLoaderError::DecryptionFailed(format!("entry {} not found in any block", path))
            })?;

        let mut item = PackItem::new(path.clone(), plaintext)
            .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;
        if !enc.original_extension.is_empty() {
            item = item
                .with_extension(enc.original_extension)
                .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;
        }
        if let Some(tp) = enc.type_path {
            item = item.with_type_path(tp);
        }
        out.push(item);
    }

    Ok((dlc_id, out))
}

#[derive(Error, Debug)]
pub enum DlcLoaderError {
    /// Used for any IO failure during pack loading (e.g. file not found, read error, etc).
    #[error("IO error: {0}")]
    Io(io::Error),
    /// Used when the encrypt key for the DLC ID is not found in the registry at load time, which means the DLC is still locked and entries cannot be decrypted yet. This is not a fatal error — the pack can still be loaded and inspected.
    #[error("DLC locked: encrypt key not found for DLC id: {0}")]
    DlcLocked(String),
    /// Used for any failure during decryption of an entry or archive, including authentication failures from incorrect keys and any errors from archive extraction or manifest-archive mismatches.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    /// Used when the initial container-level decryption succeeds but the plaintext is malformed (e.g. gzip archive is corrupted, manifest metadata doesn't match archive contents, etc).
    #[error("Invalid encrypted asset format: {0}")]
    InvalidFormat(String),
    /// Used when a DLC ID conflict is detected: a different pack file is already registered for the same DLC ID. This likely indicates a configuration error (e.g. two different `.dlcpack` files with the same internal DLC ID, or the same `.dlcpack` being loaded from two different paths). The error includes both the original and new pack paths for debugging.
    #[error(
        "DLC ID conflict: a .dlcpack with DLC id '{0}' is already loaded; cannot load another pack with the same DLC id, original: {1}, new: {2}"
    )]
    DlcIdConflict(String, String, String),
}

impl From<std::io::Error> for DlcLoaderError {
    fn from(e: std::io::Error) -> Self {
        DlcLoaderError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionKey, PackItem};
    use secure_gate::ExposeSecret;
    use serial_test::serial;

    #[test]
    #[serial]
    fn encrypted_asset_decrypts_with_registry() {
        // pick a DLC id and prepare a static random key material so we can
        // construct two distinct `EncryptionKey` instances that share the same
        // bytes (one goes in the registry, the other is used for encryption).
        let dlc_id = "standalone";
        let key = EncryptionKey::from_random();

        crate::encrypt_key_registry::clear_all();
        crate::encrypt_key_registry::insert(dlc_id, key.with_secret(|k| {
            EncryptionKey::from(*k)
        }));

        // build a small standalone encrypted blob using PackWriter
        let nonce = [0u8; 12];
        let mut ciphertext = Vec::new();
        {
            let mut pw = crate::pack_format::PackWriter::new(&mut ciphertext);
            pw.write_encrypted(&key, &nonce, b"hello").expect("encrypt");
        }

        let ct_len = ciphertext.len() as u32;
        let enc = EncryptedAsset {
            dlc_id: dlc_id.to_string(),
            original_extension: "".to_string(),
            type_path: None,
            nonce,
            ciphertext: ciphertext.into(),
            block_id: 0,
            block_offset: 0,
            size: ct_len,
        };

        let plaintext = enc.decrypt_bytes().expect("decrypt");
        assert_eq!(&plaintext, b"hello");
    }

    #[test]
    #[serial]
    fn dlcpack_accessors_work_and_fields_read() {
        let entry = DlcPackEntry {
            path: "a.txt".to_string(),
            encrypted: EncryptedAsset {
                dlc_id: "example_dlc".to_string(),
                original_extension: "txt".to_string(),
                type_path: None,
                nonce: [0u8; 12],
                ciphertext: vec![].into(),
                block_id: 0,
                block_offset: 0,
                size: 0,
            },
        };
        let pack = DlcPack::new(
            DlcId::from("example_dlc"),
            Product::from("test"),
            4,
            vec![entry.clone()],
        );

        // exercise getters (reads `dlc_id` + `entries` fields)
        assert_eq!(*pack.id(), DlcId::from("example_dlc"));
        assert_eq!(pack.entries().len(), 1);

        // inspect an entry (reads `path`, `original_extension`)
        let found = pack.find_entry("a.txt").expect("entry present");
        assert_eq!(found.path().path(), "a.txt");
        assert_eq!(found.original_extension(), "txt");
        assert!(found.type_path().is_none());
    }

    #[test]
    #[serial]
    fn decrypt_pack_entries_without_key_returns_locked_error() {
        crate::encrypt_key_registry::clear_all();
        let dlc_id = crate::DlcId::from("locked_dlc");
        let items = vec![PackItem::new("a.txt", b"hello".to_vec()).expect("pack item")];
        let key = EncryptionKey::from_random();
        let _dlc_key = crate::DlcKey::generate_random();
        let product = crate::Product::from("test");
        let container = crate::pack_encrypted_pack(&dlc_id, &items, &product, &key).expect("pack");

        let err =
            decrypt_pack_entries(std::io::Cursor::new(container)).expect_err("should be locked");
        match err {
            DlcLoaderError::DlcLocked(id) => assert_eq!(id, "locked_dlc"),
            _ => panic!("expected DlcLocked error, got {:?}", err),
        }
    }

    #[test]
    #[serial]
    fn decrypt_pack_entries_with_wrong_key_reports_entry_and_dlc() {
        crate::encrypt_key_registry::clear_all();
        let dlc_id = crate::DlcId::from("badkey_dlc");
        let items = vec![PackItem::new("b.txt", b"world".to_vec()).expect("pack item")];
        let real_key = EncryptionKey::from_random();
        let _dlc_key = crate::DlcKey::generate_random();
        let product = crate::Product::from("test");
        let container =
            crate::pack_encrypted_pack(&dlc_id, &items, &product, &real_key).expect("pack");

        // insert an incorrect key for this DLC
        let wrong_key: [u8; 32] = rand::random();
        crate::encrypt_key_registry::insert(
            &dlc_id.to_string(),
            crate::EncryptionKey::from(wrong_key),
        );

        let err = decrypt_pack_entries(std::io::Cursor::new(container))
            .expect_err("should fail decryption");
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
    #[serial]
    fn dlc_id_conflict_detection() {
        // Verify conflict detection logic for a DLC ID.  We avoid checking the
        // registered path string directly because other tests may clear the
        // global registry concurrently; instead we rely solely on the `check`
        // helper which works atomically.
        crate::encrypt_key_registry::clear_all();

        let dlc_id_str = "conflict_test_dlc";
        let pack_path_1 = "existing_pack.dlcpack";
        let pack_path_2 = "different_pack.dlcpack";

        crate::encrypt_key_registry::register_asset_path(dlc_id_str, pack_path_1);

        // same path never counts as a conflict
        assert!(
            !crate::encrypt_key_registry::check(dlc_id_str, pack_path_1),
            "same pack path should NOT be a conflict"
        );

        // different path should trigger a conflict. the registry global is
        // shared across parallel test threads and other tests call
        // `clear_all()`, so the entry may be lost mid-check.  loop and
        // re-register until we observe the expected result or give up.
        let mut tries = 0;
        while tries < 100 && !crate::encrypt_key_registry::check(dlc_id_str, pack_path_2) {
            crate::encrypt_key_registry::register_asset_path(dlc_id_str, pack_path_1);
            std::thread::sleep(std::time::Duration::from_millis(5));
            tries += 1;
        }
        assert!(
            crate::encrypt_key_registry::check(dlc_id_str, pack_path_2),
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

        // decrypt using helper on `EncryptedAsset`; this hides the registry
        // lookup and error formatting so the loader remains lean.
        let plaintext = enc.decrypt_bytes().map_err(|e| {
            // augment the error message with the requested path for context
            match e {
                DlcLoaderError::DecryptionFailed(msg) => DlcLoaderError::DecryptionFailed(format!(
                    "dlc='{}' path='{}' {}",
                    enc.dlc_id,
                    path_string.clone().unwrap_or_else(|| "<unknown>".to_string()),
                    msg,
                )),
                other => other,
            }
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
            // rewind original reader and clone again
            let mut ext_reader = bevy::asset::io::VecReader::new(bytes_clone.clone());
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
                    Err(_) => {
                        return Err(DlcLoaderError::DecryptionFailed(format!(
                            "dlc loader: extension-based load succeeded but downcast to '{}' failed",
                            A::type_path(),
                        )));
                    }
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
            A::type_path(),
            if ext.is_empty() {
                ""
            } else {
                " (extension fallback also failed)"
            }
        )))
    }
}
