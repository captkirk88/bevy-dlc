use bevy::asset::io::Reader;
use bevy::asset::{Asset, AssetLoader, AssetPath, ErasedLoadedAsset, Handle, LoadContext, LoadedUntypedAsset};
use bevy::ecs::reflect::AppTypeRegistry;
use std::io;
use std::sync::Arc;
use bevy::reflect::TypePath;
use thiserror::Error;

use crate::DlcId;

// ---------------------------------------------------------------------------
// Trait for inserting an `ErasedLoadedAsset` as a typed labeled sub-asset.
//
// Bevy's public `LoadContext` API only exposes `add_loaded_labeled_asset::<A>`
// which requires a compile-time type. We work around this by implementing this
// trait for every concrete asset type we support and storing boxed instances
// in `DlcPackLoader`. The loader tries each registrar in turn; the first one
// that successfully downcasts the `ErasedLoadedAsset` wins.
// ---------------------------------------------------------------------------

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
}

/// Represents a single encrypted file loaded from a `.dlc` container. The contained bytes are still encrypted and will be decrypted by the `DlcLoader` when the asset is loaded.
#[derive(Clone, Debug)]
pub struct EncryptedAsset {
    pub dlc_id: String,
    pub original_extension: String,
    /// Optional serialized type identifier (e.g. `bevy::image::Image`)
    pub type_path: Option<String>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Parse the binary encrypted-asset container used by `.dlc` and `.dlcpack`.
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

    /// Decrypt an entry (accepts either `name` or `packfile.dlcpack#name`) by
    /// using the retained `container_bytes`. Returns plaintext or `DlcLocked`.
    pub fn decrypt_entry_bytes(
        &self,
        entry_path: &str,
    ) -> Result<Vec<u8>, crate::asset_loader::DlcLoaderError> {
        // Decrypt the pack once (checks global encrypt-key registry) and
        // extract the requested entry.
        let (_dlc_id, items) = crate::asset_loader::decrypt_pack_entries(&self.container_bytes)
            .map_err(|e| e)?;

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
        Err(crate::asset_loader::DlcLoaderError::InvalidFormat(
            format!("entry not found in container: {}", entry_path),
        ))
    }

    pub fn load<A: Asset>(
        &self,
        asset_server: &bevy::prelude::AssetServer,
        entry_path: &str,
    ) -> Option<Handle<A>> {
        let entry = match self
            .find_entry(entry_path) {
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
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| DlcLoaderError::Io(e))?;

        let (dlc_id, _version, manifest_entries) = crate::parse_encrypted_pack(&bytes)
            .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

        // register this asset path for the dlc id so it can be reloaded on unlock
        crate::encrypt_key_registry::register_asset_path(&dlc_id, &path_string);

        // Try to decrypt all entries immediately when the encrypt key is present.
        // If the key is missing we still populate the manifest so callers can
        // inspect entries; a reload after unlock will add the typed sub-assets.
        let decrypted_items: Option<Vec<(String, String, Option<String>, Vec<u8>)>> =
            match decrypt_pack_entries(&bytes) {
                Ok((_id, items)) => Some(items),
                Err(DlcLoaderError::DlcLocked(_)) => None, // not yet unlocked — ok
                Err(e) => return Err(e),
            };

        let mut out_entries = Vec::with_capacity(manifest_entries.len());

        for (path, enc) in manifest_entries.into_iter() {
            let entry_label = path.replace('\\', "/");

            // Try to load this entry as a typed sub-asset when plaintext is available.
            if let Some(ref items) = decrypted_items {
                if let Some((_, ext, _type_path, plaintext)) =
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

                    // Use extension dispatch — Bevy picks the right loader (e.g. ImageLoader
                    // for .png). Returns an ErasedLoadedAsset (type-erased). We then try each
                    // registered TypedSubAssetRegistrar in turn until one successfully downcasts
                    // and registers the asset.
                    let result = load_context
                        .loader()
                        .immediate()
                        .with_reader(&mut vec_reader)
                        .with_unknown_type()
                        .load(fake_path)
                        .await;

                    match result {
                        Ok(erased) => {
                            let mut remaining = Some(erased);
                            for registrar in &self.registrars {
                                match registrar.try_register(
                                    entry_label.clone(),
                                    remaining.take().unwrap(),
                                    load_context,
                                ) {
                                    Ok(()) => { remaining = None; break; }
                                    Err(back) => { remaining = Some(back); }
                                }
                            }
                            if let Some(_) = remaining {
                                bevy::log::warn!(
                                    "DlcPackLoader: no registrar matched type for entry '{}' (extension='{}').",
                                    entry_label,
                                    ext
                                );
                            }
                        }
                        Err(e) => {
                            bevy::log::warn!(
                                "DlcPackLoader: failed to load entry '{}': {}",
                                entry_label,
                                e
                            );
                        }
                    }
                }
            }

            // Build the labeled registered path for the DlcPackEntry.
            let registered_path = format!("{}#{}", path_string, entry_label);

            out_entries.push(DlcPackEntry {
                path: registered_path,
                original_extension: enc.original_extension,
                type_path: enc.type_path,
            });
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
    let (dlc_id, version, entries) = crate::parse_encrypted_pack(pack_bytes)
        .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

    // lookup encrypt key in global registry
    let encrypt_key = crate::encrypt_key_registry::get(&dlc_id)
        .ok_or_else(|| DlcLoaderError::DlcLocked(dlc_id.clone()))?;

    // Version 1: each entry encrypted individually
    if version == 1 {
        let mut out = Vec::with_capacity(entries.len());
        for (path, enc) in entries.into_iter() {
            let plaintext =
                crate::decrypt_with_key(&encrypt_key, &enc.ciphertext, &enc.nonce).map_err(|e| {
                    let inner_error = e.to_string();
                    let msg = format!(
                        "dlc='{}' entry='{}' {}",
                        dlc_id,
                        path,
                        if inner_error.is_empty() { "".to_string() } else { format!("{}", inner_error) }
                    );

                    DlcLoaderError::DecryptionFailed(msg)
                })?;
            out.push((path, enc.original_extension, enc.type_path, plaintext));
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
    let archive_plain =
        crate::decrypt_with_key(&encrypt_key, archive_ciphertext, &archive_nonce).map_err(|e| {
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
        match extracted.remove(&path) {
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
}

#[cfg(test)]
mod tests {
    use crate::EncryptionKey;
use secure_gate::ExposeSecret;

    use super::*;

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
        let items = vec![(
            "a.txt".to_string(),
            Some("txt".to_string()),
            None,
            b"hello".to_vec(),
        )];
        let key = EncryptionKey::from_random(32);
        let container = crate::pack_encrypted_pack(&dlc_id, &items, &key).expect("pack");

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
        let items = vec![(
            "b.txt".to_string(),
            Some("txt".to_string()),
            None,
            b"world".to_vec(),
        )];
        let real_key = EncryptionKey::from_random(32);
        let container = crate::pack_encrypted_pack(&dlc_id, &items, &real_key).expect("pack");

        // insert an incorrect key for this DLC
        let wrong_key: [u8; 32] = rand::random();
        crate::encrypt_key_registry::insert(&dlc_id.to_string(), crate::EncryptionKey::from(wrong_key.to_vec()));

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
    fn integration_load_expansiona_pack_and_decode_image() {
        // generate a dlcpack on-the-fly using a SignedLicense's embedded encrypt_key
        crate::encrypt_key_registry::clear_all();

        use base64::Engine as _;

        let dlc_id = crate::DlcId::from("expansionA");
        let img_bytes = std::fs::read("test_assets/test.png").expect("read test png");
        let items = vec![(
            "test.png".to_string(),
            Some("png".to_string()),
            Some("bevy_image::image::Image".to_string()),
            img_bytes,
        )];

        // create a private key + signed license (private seed == symmetric encrypt_key)
        let private = crate::DlcKey::generate_random();
        let signedlicense = private
            .create_signed_license(&[dlc_id.clone()], crate::Product::from("example"))
            .expect("create signed license");

        // decode the embedded encrypt_key from the token payload and insert it
        let key_bytes = signedlicense.with_secret(|s| {
            let parts: Vec<&str> = s.split('.').collect();
            assert_eq!(parts.len(), 2);
            let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0].as_bytes())
                .expect("payload base64 decode");
            let v: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("json");
            let content_key_b64 = v.get("encrypt_key").expect("encrypt_key present").as_str().expect("str");
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(content_key_b64.as_bytes())
                .expect("encrypt_key decode")
        });
        assert_eq!(key_bytes.len(), 32);

        let encrypt_key = EncryptionKey::from(key_bytes.clone());
        crate::encrypt_key_registry::insert(&dlc_id.to_string(), encrypt_key.with_secret(|b| EncryptionKey::from(b.to_vec())));

        // pack using the same symmetric key and validate decrypt_pack_entries
        let container = crate::pack_encrypted_pack(&dlc_id, &items, &encrypt_key).expect("pack container");
        let (did, _v, entries) = crate::parse_encrypted_pack(&container).expect("parse pack");
        assert_eq!(did, "expansionA");
        assert!(!entries.is_empty());

        let (_dlc, out_items) = crate::asset_loader::decrypt_pack_entries(&container).expect("decrypt_pack_entries");
        let first = out_items.first().expect("entry");
        assert!(first.3.starts_with(b"\x89PNG\r\n\x1a\n"), "decrypted entry is PNG");

        // basic IHDR sanity check (width/height > 0)
        let raw = &first.3;
        let width = u32::from_be_bytes([raw[16], raw[17], raw[18], raw[19]]);
        let height = u32::from_be_bytes([raw[20], raw[21], raw[22], raw[23]]);
        assert!(width > 0 && height > 0);
    }}

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
                    if inner_error.is_empty() { "".to_string() } else { format!("{}", inner_error) }
                );

                DlcLoaderError::DecryptionFailed(msg)
            })?;

        // Choose an extension for the nested load so Bevy selects the correct
        // concrete loader (use container ext or fallback to original path ext).
        let ext = enc.original_extension;

        // Use an in-memory VecReader (no temp files) and ask the nested loader
        // to immediately parse the bytes as the requested asset type `A`.
        let mut vec_reader = bevy::asset::io::VecReader::new(plaintext);

        let stem = load_context
            .path()
            .path()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("dlc_decrypted");
        let fake_path = format!("{}.{}", stem, ext);

        // Prefer selecting the nested loader by *extension* when possible so
        // the original concrete loader (e.g. `TextAssetLoader` for `.json`) is
        // chosen. If we always force selection by asset *type* the
        // `DlcLoader<A>` we registered for `A` can be selected recursively.
        // If we have a meaningful extension prefer selecting the nested
        // loader by *path/extension* (with_unknown_type) so Bevy chooses the
        // concrete loader registered for that file type (avoids recursive
        // selection of `DlcLoader<A>` registered for the asset *type*).
        if ext == "bin" {
            // no helpful extension available — fall back to static-type lookup
            let loaded = load_context
                .loader()
                .with_static_type()
                .immediate()
                .with_reader(&mut vec_reader)
                .load::<A>(fake_path)
                .await
                .map_err(|e| DlcLoaderError::DecryptionFailed(e.to_string()))?;
            Ok(loaded.take())
        } else {
            // select loader by extension (unknown-typed) then downcast to A
            let erased = load_context
                .loader()
                .immediate()
                .with_reader(&mut vec_reader)
                .with_unknown_type()
                .load(fake_path)
                .await
                .map_err(|e| DlcLoaderError::DecryptionFailed(e.to_string()))?;

            // try to downcast the erased-loaded asset into the requested type
            match erased.downcast::<A>() {
                Ok(loaded) => Ok(loaded.take()),
                Err(e) => Err(DlcLoaderError::DecryptionFailed(
                    format!("type mismatch after decryption: expected {}, got {}", std::any::type_name::<A>(), e.asset_type_name())
                )),
            }
        }
    }
}
