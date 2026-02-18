use bevy::asset::io::Reader;
use bevy::asset::{Asset, AssetLoader, Handle, LoadContext};
use bevy::ecs::reflect::AppTypeRegistry;
use std::io;
use std::sync::Arc;
use bevy::reflect::TypePath;
use thiserror::Error;

use crate::DlcId;

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

// --- Generic AssetLoader that decrypts `.dlc` -> `A` using the global registry ---
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
    pub path: String,
    /// Optional original extension stored by the pack producer
    pub original_extension: String,
    /// Optional serialized TypePath
    pub type_path: Option<String>,
}

impl DlcPackEntry {
    /// Convenience: load this entry's registered path via `AssetServer::load`.
    pub fn load<A: bevy::asset::Asset>(
        &self,
        asset_server: &bevy::prelude::AssetServer,
    ) -> Handle<A> {
        asset_server.load::<A>(&self.path)
    }

    /// Decrypt and return the plaintext bytes for this entry using the
    /// `DlcPack` container that owns it. This consults the global content-key
    /// registry and will return `DlcLoaderError::DlcLocked` when the content
    /// key is not present.
    pub fn decrypt_bytes(&self, pack: &DlcPack) -> Result<Vec<u8>, DlcLoaderError> {
        pack.decrypt_entry_bytes(&self.path)
    }

    pub fn path(&self) -> &String {
        &self.path
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

    /// Find an entry by its registered path (the value produced by the
    /// pack loader, e.g. `expansion_A.dlcpack#test.png`).
    pub fn find_entry(&self, path: &str) -> Option<&DlcPackEntry> {
        self.entries.iter().find(|e| e.path().ends_with(path))
    }

    /// Decrypt an entry (accepts either `name` or `packfile.dlcpack#name`) by
    /// using the retained `container_bytes`. Returns plaintext or `DlcLocked`.
    pub fn decrypt_entry_bytes(
        &self,
        entry_path: &str,
    ) -> Result<Vec<u8>, crate::asset_loader::DlcLoaderError> {
        // Decrypt the pack once (checks global content-key registry) and
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
        Some(entry.load(asset_server))
    }
}

/// `AssetLoader` for `.dlcpack` bundles (contains multiple encrypted entries).
#[derive(TypePath, Default)]
pub struct DlcPackLoader;

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
        // capture the original requested path (for registry/bookkeeping)
        let path_string = Some(load_context.path().path().to_string_lossy().to_string());

        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| DlcLoaderError::Io(e))?;

        // parse manifest only — do NOT decrypt archive entries here. The
        // returned `entries` contain `EncryptedAsset` records that reference
        // the encrypted archive (v2) or per-entry ciphertexts (v1).
        let (dlc_id, _version, manifest_entries) = crate::parse_encrypted_pack(&bytes)
            .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

        // register this asset path for the dlc id so it can be reloaded on unlock
        if let Some(p) = &path_string {
            crate::content_key_registry::register_asset_path(&dlc_id, p);
        }

        // convert manifest into `DlcPackEntry` values and register labeled
        // handles (deferred typed-loading by consumers).
        let mut out_entries = Vec::with_capacity(manifest_entries.len());
        for (path, enc) in manifest_entries.into_iter() {
            // normalized entry path (preserve forward-slashes)
            let fake_path = format!("{}", path.replace('\\', "/"));

            // register an untyped label handle so callers can `load("pack#label")`
            let untyped_handle = load_context.get_label_handle::<bevy::asset::LoadedUntypedAsset>(&fake_path);

            // expose the labeled asset immediately so `AssetServer::load("pack#label")`
            // and `AssetServer::load_folder("pack")` work the same as real files.
            load_context.add_labeled_asset(
                fake_path.clone(),
                bevy::asset::LoadedUntypedAsset { handle: untyped_handle.clone().into() },
            );

            // store the *registered* lookup path (pack-file + `#` + entry path)
            let _pack_file = load_context
                .path()
                .path()
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("<dlcpack>");
            let registered_path = untyped_handle.path().ok_or(DlcLoaderError::InvalidFormat(format!(
                "invalid entry path for registration: {}",
                fake_path
            )))?.to_string();

            out_entries.push(DlcPackEntry {
                path: registered_path,
                original_extension: enc.original_extension,
                type_path: enc.type_path,
            });
        }

        let pack = DlcPack {
            dlc_id: DlcId::from(dlc_id),
            entries: out_entries,
            container_bytes: bytes,
        };

        Ok(pack)
    }
}

/// Decrypt entries out of a `.dlcpack` container.
/// Returns `(dlc_id, Vec<(path, original_extension, plaintext)>)`.
pub fn decrypt_pack_entries(
    pack_bytes: &[u8],
) -> Result<(String, Vec<(String, String, Option<String>, Vec<u8>)>), DlcLoaderError> {
    let (dlc_id, version, entries) = crate::parse_encrypted_pack(pack_bytes)
        .map_err(|e| DlcLoaderError::InvalidFormat(e.to_string()))?;

    // lookup content key in global registry
    let content_key = crate::content_key_registry::get(&dlc_id)
        .ok_or_else(|| DlcLoaderError::DlcLocked(dlc_id.clone()))?;

    // Version 1: each entry encrypted individually
    if version == 1 {
        let mut out = Vec::with_capacity(entries.len());
        for (path, enc) in entries.into_iter() {
            let plaintext =
                crate::decrypt_with_key(&content_key, &enc.ciphertext, &enc.nonce).map_err(|e| {
                    let inner_error = e.to_string();
                    DlcLoaderError::DecryptionFailed(format!(
                        "dlc='{}' entry='{}' {}",
                        dlc_id,
                        path,
                        if inner_error.is_empty() {
                            "".to_string()
                        } else {
                            format!("decryption failed: {}", inner_error)
                        }
                    ))
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
        crate::decrypt_with_key(&content_key, archive_ciphertext, &archive_nonce).map_err(|e| {
            // report which DLC failed; include an example entry for context
            let example_entry = &entries[0].0;
            DlcLoaderError::DecryptionFailed(format!(
                "dlc='{}' entry='{}' decryption failed: {}",
                dlc_id,
                example_entry,
                e.to_string()
            ))
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
    #[error("DLC locked: content key not found for DLC id: {0}")]
    DlcLocked(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid encrypted asset format: {0}")]
    InvalidFormat(String),
}

#[cfg(test)]
mod tests {
    use crate::ContentKey;
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
        crate::content_key_registry::clear_all();
        let dlc_id = crate::DlcId::from("locked_dlc");
        let items = vec![(
            "a.txt".to_string(),
            Some("txt".to_string()),
            None,
            b"hello".to_vec(),
        )];
        let key = ContentKey::from_random(32);
        let container = crate::pack_encrypted_pack(&dlc_id, &items, &key).expect("pack");

        let err = decrypt_pack_entries(&container).expect_err("should be locked");
        match err {
            DlcLoaderError::DlcLocked(id) => assert_eq!(id, "locked_dlc"),
            _ => panic!("expected DlcLocked error, got {:?}", err),
        }
    }

    #[test]
    fn decrypt_pack_entries_with_wrong_key_reports_entry_and_dlc() {
        crate::content_key_registry::clear_all();
        let dlc_id = crate::DlcId::from("badkey_dlc");
        let items = vec![(
            "b.txt".to_string(),
            Some("txt".to_string()),
            None,
            b"world".to_vec(),
        )];
        let real_key = ContentKey::from_random(32);
        let container = crate::pack_encrypted_pack(&dlc_id, &items, &real_key).expect("pack");

        // insert an incorrect key for this DLC
        let wrong_key: [u8; 32] = rand::random();
        crate::content_key_registry::insert(&dlc_id.to_string(), crate::ContentKey::from(wrong_key.to_vec()));

        let err = decrypt_pack_entries(&container).expect_err("should fail decryption");
        match err {
            DlcLoaderError::DecryptionFailed(msg) => {
                assert!(msg.contains("dlc='badkey_dlc'"));
                assert!(msg.contains("entry='b.txt'"));
            }
            _ => panic!("expected DecryptionFailed, got {:?}", err),
        }
    }

    #[test]
    fn integration_load_expansiona_pack_and_decode_image() {
        // generate a dlcpack on-the-fly using a SignedLicense's embedded content_key
        crate::content_key_registry::clear_all();

        use base64::Engine as _;

        let dlc_id = crate::DlcId::from("expansionA");
        let img_bytes = std::fs::read("test_assets/test.png").expect("read test png");
        let items = vec![(
            "test.png".to_string(),
            Some("png".to_string()),
            Some("bevy_image::image::Image".to_string()),
            img_bytes,
        )];

        // create a private key + signed license (private seed == symmetric content_key)
        let private = crate::DlcKey::generate_random();
        let signedlicense = private
            .create_signed_license(&[dlc_id.clone()], crate::Product::from("example"))
            .expect("create signed license");

        // decode the embedded content_key from the token payload and insert it
        let key_bytes = signedlicense.with_secret(|s| {
            let parts: Vec<&str> = s.split('.').collect();
            assert_eq!(parts.len(), 2);
            let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0].as_bytes())
                .expect("payload base64 decode");
            let v: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("json");
            let content_key_b64 = v.get("content_key").expect("content_key present").as_str().expect("str");
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(content_key_b64.as_bytes())
                .expect("content_key decode")
        });
        assert_eq!(key_bytes.len(), 32);

        let content_key = ContentKey::from(key_bytes.clone());
        crate::content_key_registry::insert(&dlc_id.to_string(), content_key.with_secret(|b| ContentKey::from(b.to_vec())));

        // pack using the same symmetric key and validate decrypt_pack_entries
        let container = crate::pack_encrypted_pack(&dlc_id, &items, &content_key).expect("pack container");
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
            crate::content_key_registry::register_asset_path(&enc.dlc_id, p);
        }

        // lookup content key in global registry (loader-executed outside ECS)
        let content_key = crate::content_key_registry::get(&enc.dlc_id)
            .ok_or_else(|| DlcLoaderError::DlcLocked(enc.dlc_id.clone()))?;

        // decrypt bytes
        let plaintext = crate::decrypt_with_key(&content_key, &enc.ciphertext, &enc.nonce)
            .map_err(|e| DlcLoaderError::DecryptionFailed(e.to_string()))?;

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
