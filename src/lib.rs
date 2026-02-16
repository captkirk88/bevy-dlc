//! bevy-dlc — DLC gating utilities for Bevy 0.18
//!
//! Preload encrypted assets and unlock them using offline-signed (Ed25519)
//! tokens. See `DlcManager`, `DlcKey`, and `DlcPack` for the runtime API and
//! examples.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bevy::prelude::*;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use secure_gate::{dynamic_alias, fixed_alias};

// secure wrappers for seeds / passphrases used with `DlcKey`
fixed_alias!(pub PrivateKey, 32);
fixed_alias!(pub PublicKey, 32);
// secure wrapper for issued offline-signed signed-license (zeroized on drop)
dynamic_alias!(pub SignedLicense, String);

dynamic_alias!(pub Product, String);

mod asset_loader;
mod content_key_registry;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
pub use asset_loader::{DlcLoader, DlcPack, DlcPackLoader, EncryptedAsset, parse_encrypted};

// ring is used directly for Ed25519 operations — no external signer trait.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(any(test, feature = "example"))]
pub mod example_util;

/// Strongly-typed DLC identifier (string-backed).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(transparent)]
pub struct DlcId(pub String);

// convenience impls
impl From<&str> for DlcId {
    fn from(s: &str) -> Self {
        DlcId(s.to_owned())
    }
}

impl From<String> for DlcId {
    fn from(s: String) -> Self {
        DlcId(s)
    }
}

impl std::fmt::Display for DlcId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

pub mod prelude {
    pub use crate::{
        DlcHandle, DlcId, DlcKey, DlcManager, DlcPlugin, EncryptedAsset, PrivateKey, PublicKey, Product,
        SignedLicense, VerifiedLicense, build_encrypted_container_bytes, dlc_unlocked,
        pack_encrypted_asset, pack_encrypted_pack, parse_encrypted, parse_encrypted_pack,
    };
    pub use base64::Engine as _;
    pub use base64::engine::general_purpose::URL_SAFE_NO_PAD;
}
/// Bevy plugin that inserts a `DlcManager` resource.
///
/// Provide the public key bytes that will be used to verify offline-signed
/// license tokens.
pub struct DlcPlugin {
    pub public_key: PublicKey,
}

impl DlcPlugin {
    /// Create the plugin from raw public-key bytes (Ed25519, 32 bytes).
    pub fn from_public_key_bytes(bytes: &[u8; 32]) -> Result<Self, DlcError> {
        Ok(DlcPlugin { public_key: PublicKey::from_slice(bytes) })
    }

    /// Create the plugin directly from a `DlcKey` (uses the public key bytes).
    pub fn from_dlc_key(dlc_key: &DlcKey) -> Result<Self, DlcError> {
        Self::from_public_key_bytes(&dlc_key.public_key_bytes())
    }
}

/// Client-side wrapper for Ed25519 key operations: verify tokens and (when
/// private) create compact signed tokens.
#[derive(Clone)]
pub enum DlcKey {
    /// Private key (protected seed + public bytes + publickey tag)
    Private {
        /// Protected signing seed (secure wrapper)
        privkey: PrivateKey,
        /// Public key bytes (wrapped)
        pubkey: PublicKey,
    },

    /// Public-only key (public bytes)
    Public {
        /// Public key bytes (wrapped)
        pubkey: PublicKey,
    },
}

impl DlcKey {
    /// Construct a `DlcKey::Private` from a secure `SigningSeed` **and** a
    /// `PublicKey`. Requiring a `PublicKey` at construction time makes the
    /// private-key creation explicit (breaking change) and enables callers to
    /// later prove knowledge of that publickey when creating tokens.
    pub fn from_priv_and_pub(
        privkey: PrivateKey,
        publickey: PublicKey,
    ) -> Result<Self, DlcError> {
        // derive public bytes from the protected seed and validate via
        // `from_seed_and_public_key` so we never sign using only the seed
        let priv_bytes = privkey.expose_secret();
        let kp = Ed25519KeyPair::from_seed_and_public_key(priv_bytes, publickey.expose_secret())
            .map_err(|e| DlcError::CryptoError(format!("invalid seed: {:?}", e)))?;
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(kp.public_key().as_ref());

        // validate construction using both seed + public (preferred API)
        Ed25519KeyPair::from_seed_and_public_key(priv_bytes, &pub_bytes)
            .map_err(|e| DlcError::CryptoError(format!("keypair validation failed: {:?}", e)))?;

        Ok(DlcKey::Private {
            privkey,
            pubkey: PublicKey::from(pub_bytes),
        })
    }

    /// Generate a new `DlcKey::Private` using the OS CSPRNG. Requires a
    /// `PublicKey` (breaking change).
    pub fn generate(publickey: PublicKey) -> Self {
        let seed: PrivateKey = PrivateKey::generate_random();
        Self::from_priv_and_pub(seed, publickey).expect("generate keypair")
    }

    /// Generate a new `DlcKey::Private` with a random seed and derived public key.
    ///
    /// The public key is derived from the generated seed so the keypair is valid.
    pub fn generate_random() -> Self {
        // generate a random seed and derive the matching public key from it
        let privkey: PrivateKey = PrivateKey::generate_random();
        let priv_bytes = privkey.expose_secret();
        // derive public bytes from the seed using ring
        let pair = Ed25519KeyPair::from_seed_unchecked(priv_bytes)
            .expect("derive public key from seed");
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(pair.public_key().as_ref());

        Self::from_priv_and_pub(privkey, PublicKey::from(pub_bytes))
            .unwrap_or_else(|e| panic!("generate_complete failed: {:?}", e))
    }

    /// Return the raw public key bytes (32 bytes) for either variant.
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        match self {
            DlcKey::Private { pubkey: public, .. } => {
                public.expose_secret()
            }
            DlcKey::Public { pubkey: public } => {
                public.expose_secret()
            }
        }
    }

    pub fn get_public_key(&self) -> &PublicKey {
        match self {
            DlcKey::Private { pubkey, .. } => pubkey,
            DlcKey::Public { pubkey: public } => public,
        }
    }

    /// Create a compact offline-signed token that can be verified by this key's public key.
    ///
    /// Returns a `SignedLicense` (zeroized on drop). The license payload includes
    /// the provided DLC ids and optional product binding.
    pub fn create_signed_license<D>(
        &self,
        dlcs: impl IntoIterator<Item = D>,
        product: Option<Product>, // optional product binding (uses `Product` dynamic alias)
        content_key: Option<&[u8]>,
        exp: Option<u64>,
    ) -> Result<SignedLicense, DlcError>
    where
        D: std::fmt::Display,
    {
        let mut payload = serde_json::Map::new();
        payload.insert(
            "dlcs".to_string(),
            serde_json::Value::Array(
                dlcs.into_iter()
                    .map(|s| serde_json::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        if let Some(p) = product {
            payload.insert(
                "product".to_string(),
                serde_json::Value::String(p.expose_secret().to_string()),
            );
        }
        if let Some(key) = content_key {
            payload.insert(
                "content_key".to_string(),
                serde_json::Value::String(URL_SAFE_NO_PAD.encode(key)),
            );
        }
        if let Some(e) = exp {
            payload.insert(
                "exp".to_string(),
                serde_json::Value::Number(serde_json::Number::from(e)),
            );
        }

        let payload_value = serde_json::Value::Object(payload);
        let payload_bytes = serde_json::to_vec(&payload_value)
            .map_err(|e| DlcError::TokenCreationFailed(e.to_string()))?;

        match self {
            DlcKey::Private {
                privkey,
                pubkey,
            } => {

                // build keypair using both seed + public (preferred invariant)
                let pair = Ed25519KeyPair::from_seed_and_public_key(
                    privkey.expose_secret(),
                    pubkey.expose_secret(),
                )
                .map_err(|e| DlcError::CryptoError(format!("keypair: {:?}", e)))?;
                let sig = pair.sign(&payload_bytes);
                Ok(SignedLicense::from(format!(
                    "{}.{}",
                    URL_SAFE_NO_PAD.encode(&payload_bytes),
                    URL_SAFE_NO_PAD.encode(sig.as_ref())
                )))
            }
            DlcKey::Public { .. } => Err(DlcError::PrivateKeyRequired),
        }
    }

    /// Verify a compact signed-license (signature + payload) using this key's public key
    /// and return a typed `VerifiedLicense`. This only checks signature + parsing;
    /// expiry/product/installation checks are performed by `DlcManager::unlock_verified_license`.
    pub fn verify_signed_license(&self, license: &SignedLicense) -> Result<VerifiedLicense, DlcError> {
        let full_token = license.expose_secret();
        let parts: Vec<&str> = full_token.split('.').collect();
        if parts.len() != 2 {
            return Err(DlcError::MalformedToken(
                "expected signed-license with two dot-separated parts".into(),
            ));
        }

        let payload = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| DlcError::MalformedToken(format!("payload base64: {}", e)))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| DlcError::MalformedToken(format!("signature base64: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(DlcError::MalformedToken(
                "signature bytes length must be 64".into(),
            ));
        }

        let public = self.public_key_bytes();
        let public_key = UnparsedPublicKey::new(&ED25519, public);
        public_key
            .verify(&payload, &sig_bytes)
            .map_err(|_| DlcError::SignatureInvalid)?;

        let lic: LicensePayload = serde_json::from_slice(&payload)
            .map_err(|e| DlcError::PayloadInvalid(e.to_string()))?;

        let content_key_bytes = if let Some(b64) = &lic.content_key {
            Some(
                URL_SAFE_NO_PAD
                    .decode(b64)
                    .map_err(|e| DlcError::PayloadInvalid(format!("content_key base64: {}", e)))?,
            )
        } else {
            None
        };

        Ok(VerifiedLicense {
            dlcs: lic.dlcs,
            exp: lic.exp,
            iat: lic.iat,
            nonce: lic.nonce,
            product: lic.product,
            content_key: content_key_bytes,
        })
    }
}

impl Plugin for DlcPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(DlcManager::new())
            .init_asset_loader::<asset_loader::DlcLoader<Image>>()
            .init_asset_loader::<asset_loader::DlcLoader<Scene>>()
            .init_asset_loader::<asset_loader::DlcLoader<bevy::mesh::Mesh>>()
            .init_asset_loader::<asset_loader::DlcLoader<Font>>()
            .init_asset_loader::<asset_loader::DlcLoader<AudioSource>>()
            //.init_resource::<Assets<asset_loader::DlcPack>>()
            .init_asset_loader::<asset_loader::DlcPackLoader>()
            .init_asset::<asset_loader::DlcPack>()
            .add_systems(Update, reload_assets_on_unlock_system);
    }
}

/// Resource that holds unlocked DLC IDs and verifies signed license tokens.
///
/// Security improvements:
/// - DLC ids are `DlcId<K>` (typed identifier) rather than raw strings.
/// - optional `product` and `installation_id` bindings can be set on the
///   manager; if provided the privatekey must include matching fields. This makes
///   copied tokens useless unless they were issued for the same product/
///   installation.
#[derive(Resource, Debug)]
pub struct DlcManager {
    unlocked: HashSet<DlcId>,
    content_keys: HashMap<DlcId, Vec<u8>>,
    product: Option<String>,
}

impl DlcManager {
    /// Create a new, empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Require tokens to include this `product` value (optional).
    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }



    /// Mark a single DLC as unlocked (useful for tests or server-validated flow).
    pub fn unlock(&mut self, dlc_id: DlcId) {
        self.unlocked.insert(dlc_id);
    }

    /// Check whether a DLC is unlocked by `DlcId`.
    pub fn is_unlocked_id<'a>(&self, dlc_id: impl Into<&'a DlcId>) -> bool {
        self.unlocked.contains(dlc_id.into())
    }

    /// Return a list of currently unlocked DLC ids.
    pub fn unlocked_list(&self) -> Vec<DlcId> {
        self.unlocked.iter().cloned().collect()
    }

    /// Get the content (symmetric) key associated with a DLC id, if any.
    pub fn content_key_for_id(&self, dlc_id: &DlcId) -> Option<Vec<u8>> {
        self.content_keys.get(dlc_id).cloned()
    }

    /// Decrypt using a typed `DlcId`.
    pub fn decrypt_asset_if_unlocked_id(
        &self,
        dlc_id: &DlcId,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, DlcError> {
        if !self.is_unlocked_id(dlc_id) {
            return Err(DlcError::DlcLocked(dlc_id.to_string()));
        }
        let key = self
            .content_key_for_id(dlc_id)
            .ok_or_else(|| DlcError::NoContentKey(dlc_id.to_string()))?;
        decrypt_with_key(&key, ciphertext, nonce)
    }
}

impl Default for DlcManager {
    fn default() -> Self {
        Self {
            unlocked: HashSet::new(),
            content_keys: HashMap::new(),
            product: None,
        }
    }
}

impl DlcManager {
    /// Unlock DLC IDs from a previously-verified `VerifiedLicense`.
    ///
    /// Performs expiry/product/installation checks and populates content keys.
    pub fn unlock_verified_license(&mut self, vt: VerifiedLicense) -> Result<Vec<DlcId>, DlcError> {
        // expiry check
        if let Some(exp) = vt.exp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DlcError::Other(e.to_string()))?
                .as_secs();
            if now > exp {
                return Err(DlcError::Expired);
            }
        }

        // product binding (if manager requires a product)
        if let Some(required) = &self.product {
            if vt.product.as_deref() != Some(required.as_str()) {
                return Err(DlcError::TokenProductMismatch);
            }
        }


        let mut unlocked_ids = Vec::new();
        for id in &vt.dlcs {
            let did = DlcId::from(id.clone());
            self.unlocked.insert(did.clone());
            if let Some(ref key_bytes) = vt.content_key {
                self.content_keys.insert(did.clone(), key_bytes.clone());
                // also populate the global registry used by AssetLoader (string-keyed)
                crate::content_key_registry::insert(&did.to_string(), key_bytes.clone());
            }
            unlocked_ids.push(did);
        }

        Ok(unlocked_ids)
    }
}

/// A small wrapper that associates an asset Handle with a DLC id.
/// The asset may be loaded but `get_if_unlocked` returns `None` until the
/// DLC is unlocked via `DlcManager`.
#[derive(Clone, Debug)]
pub struct DlcHandle<T: Asset> {
    pub handle: Handle<T>,
    pub dlc_id: DlcId,
}

impl<T: Asset> DlcHandle<T> {
    pub fn new(handle: Handle<T>, dlc_id: impl Into<DlcId>) -> Self {
        Self {
            handle,
            dlc_id: dlc_id.into(),
        }
    }

    /// Return the contained `Handle<T>` if the DLC is unlocked.
    pub fn get_if_unlocked(&self, dlc: &DlcManager) -> Option<Handle<T>> {
        if dlc.is_unlocked_id(&self.dlc_id) {
            Some(self.handle.clone())
        } else {
            None
        }
    }

    /// Convenience check.
    pub fn is_unlocked(&self, dlc: &DlcManager) -> bool {
        dlc.is_unlocked_id(&self.dlc_id)
    }
}

/// Bevy `run_if` condition generator — use this to make a system run only
/// when a particular DLC is unlocked. Example:
///
/// `add_systems(Update, my_system.run_if(dlc_unlocked("expansion_1")))`
pub fn dlc_unlocked(dlc_id: impl Into<DlcId>) -> impl Fn(Res<DlcManager>) -> bool {
    let id = dlc_id.into();
    move |dlc: Res<DlcManager>| dlc.is_unlocked_id(&id)
}

/// System that reloads any asset paths registered for DLC ids that have just
/// become unlocked. This allows `AssetLoader`s to register paths they are
/// responsible for and have those assets retried automatically after the
/// relevant content key arrives.
fn reload_assets_on_unlock_system(
    dlc: Res<DlcManager>,
    asset_server: Res<AssetServer>,
    mut seen: Local<std::collections::HashSet<String>>,
) {
    for did in dlc.unlocked_list() {
        let id_str = did.to_string();
        if seen.contains(&id_str) {
            continue;
        }
        for path in crate::content_key_registry::asset_paths_for(&id_str) {
            asset_server.reload(path);
        }
        seen.insert(id_str);
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct LicensePayload {
    pub dlcs: Vec<String>,
    /// optional expiry (unix seconds)
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub nonce: Option<String>,
    pub product: Option<String>,
    /// optional base64-encoded symmetric key for content decryption
    pub content_key: Option<String>,
}

/// Typed, verified privatekey returned by `DlcKey::verify_signed_license`.
/// `content_key` is decoded to raw bytes when present.
#[derive(Debug, Clone)]
pub struct VerifiedLicense {
    pub dlcs: Vec<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub nonce: Option<String>,
    pub product: Option<String>,
    pub content_key: Option<Vec<u8>>,
}

// AES-GCM helper used to decrypt shipped assets once the DLC is unlocked.
fn decrypt_with_key(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, DlcError> {
    if key.len() != 32 {
        return Err(DlcError::InvalidContentKey(
            "content key must be 32 bytes (AES-256)".into(),
        ));
    }
    if nonce.len() != 12 {
        return Err(DlcError::InvalidNonce(
            "nonce must be 12 bytes (AES-GCM)".into(),
        ));
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| DlcError::CryptoError(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| DlcError::DecryptionFailed)
}

/// Pack plaintext bytes into the crate's encrypted container format and
/// return the serialized container bytes plus the random nonce used for AES-GCM.
///
/// - `original_extension` is the original file extension (e.g. "png" or
///   "json") and is stored in the container so loaders can prefer the
///   appropriate nested loader.
pub fn pack_encrypted_asset(
    plaintext: &[u8],
    dlc_id: &DlcId,
    original_extension: Option<&str>,
    original_type: Option<&str>,
    key: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), DlcError> {
    if key.len() != 32 {
        return Err(DlcError::InvalidContentKey(
            "content key must be 32 bytes (AES-256)".into(),
        ));
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| DlcError::CryptoError(e.to_string()))?;
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| DlcError::EncryptionFailed("encryption failed".into()))?;

    // version 1
    let version = 1u8;

    let mut out = Vec::new();
    out.extend_from_slice(DLC_ASSET_MAGIC);
    out.push(version);

    let id = dlc_id.to_string();
    let dlc_bytes = id.as_bytes();
    out.extend_from_slice(&(dlc_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(dlc_bytes);

    let ext = original_extension.unwrap_or("");
    out.push(ext.len() as u8);
    out.extend_from_slice(ext.as_bytes());

    // version 1 includes the type field (u16 length + utf8 bytes)
    let t = original_type.unwrap_or("");
    out.extend_from_slice(&(t.len() as u16).to_be_bytes());
    out.extend_from_slice(t.as_bytes());

    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok((out, nonce_bytes))
}

/// Low-level helper that constructs the container bytes from already-encrypted
/// ciphertext (keeps packing logic in one place). Useful when encryption is
/// performed externally.
pub fn build_encrypted_container_bytes(
    dlc_id: &str,
    original_extension: Option<&str>,
    original_type: Option<&str>,
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DLC_ASSET_MAGIC);
    out.push(1u8); // version 1
    let dlc_bytes = dlc_id.as_bytes();
    out.extend_from_slice(&(dlc_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(dlc_bytes);

    let ext = original_extension.unwrap_or("");
    out.push(ext.len() as u8);
    out.extend_from_slice(ext.as_bytes());

    // version 1 includes the type field (u16 length + utf8 bytes)
    let t = original_type.unwrap_or("");
    out.extend_from_slice(&(t.len() as u16).to_be_bytes());
    out.extend_from_slice(t.as_bytes());

    out.extend_from_slice(&nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Pack multiple entries into a single `.dlcpack` container.
/// New format (version 2):
/// `magic(4)='BDLP' | version(1) | dlc_len(u16) | dlc_id |
///    manifest_len(u32) | manifest(json) | nonce(12) | ciphertext_len(u32) | ciphertext`
///
/// - The manifest is a JSON array of objects: { path, original_extension?, type_path? } and is stored in the pack header (plaintext) so the CLI / tools can list entries without decrypting.
/// - The archive is a gzip-compressed tar (`.tar.gz`) of the raw plaintext files (paths preserved) and the entire compressed archive is encrypted as a single AES-GCM ciphertext using `key`.
///
/// Legacy behavior (per-entry encrypted items) is still supported by `parse_encrypted_pack`.
pub fn pack_encrypted_pack(
    dlc_id: &DlcId,
    items: &[(String, Option<String>, Option<String>, Vec<u8>)],
    key: &[u8],
) -> Result<Vec<u8>, DlcError> {
    if key.len() != 32 {
        return Err(DlcError::InvalidContentKey(
            "content key must be 32 bytes (AES-256)".into(),
        ));
    }

    // refuse inputs that already look like BDLC / BDLP containers
    for (path, _ext_opt, _type_opt, plaintext) in items {
        if plaintext.len() >= 4
            && (plaintext.starts_with(DLC_ASSET_MAGIC) || plaintext.starts_with(DLC_PACK_MAGIC))
        {
            return Err(DlcError::Other(format!(
                "cannot pack existing dlc or dlcpack container as an item: {}",
                path
            )));
        }
    }

    // Build a tar.gz archive (in-memory) containing the plaintext files at
    // their requested relative paths.
    use flate2::{Compression, write::GzEncoder};
    use tar::Builder;

    let mut tar_gz: Vec<u8> = Vec::new();
    {
        let enc = GzEncoder::new(&mut tar_gz, Compression::default());
        let mut tar = Builder::new(enc);
        for (path, _ext_opt, _type_opt, plaintext) in items {
            let mut header = tar::Header::new_gnu();
            header.set_size(plaintext.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            // append_data takes a reader; Cursor over the slice is convenient
            tar.append_data(&mut header, path, &mut std::io::Cursor::new(plaintext))
                .map_err(|e| DlcError::Other(e.to_string()))?;
        }
        // finish the tar builder to flush into the gzip encoder
        let enc = tar
            .into_inner()
            .map_err(|e| DlcError::Other(e.to_string()))?;
        // finish the gzip encoder explicitly to ensure all data is written
        let _ = enc.finish().map_err(|e| DlcError::Other(e.to_string()))?;
    }

    // produce AES-GCM ciphertext for the whole compressed archive
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| DlcError::CryptoError(e.to_string()))?;
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, tar_gz.as_slice())
        .map_err(|_| DlcError::EncryptionFailed("encryption failed".into()))?;

    // prepare manifest (JSON) with per-entry metadata so tools can inspect packs
    #[derive(serde::Serialize)]
    struct ManifestEntry<'a> {
        path: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        original_extension: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        type_path: Option<&'a str>,
    }

    let mut manifest: Vec<ManifestEntry<'_>> = Vec::with_capacity(items.len());
    for (path, ext_opt, type_opt, _plaintext) in items {
        manifest.push(ManifestEntry {
            path: path.as_str(),
            original_extension: ext_opt.as_deref(),
            type_path: type_opt.as_deref(),
        });
    }
    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|e| DlcError::Other(e.to_string()))?;

    // serialize BDLP: magic | version(2) | dlc_len(u16) | dlc_id | manifest_len(u32) | manifest | nonce | ciphertext_len(u32) | ciphertext
    let mut out = Vec::new();
    out.extend_from_slice(DLC_PACK_MAGIC);
    out.push(2u8); // version 2 (archive-encrypted)

    let id = dlc_id.to_string();
    let dlc_bytes = id.as_bytes();
    out.extend_from_slice(&(dlc_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(dlc_bytes);

    out.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&manifest_bytes);

    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// .dlc container magic header (4 bytes) used to identify encrypted asset containers.
pub const DLC_ASSET_MAGIC: &[u8; 4] = b"BDLC";
/// .dlcpack container magic header (4 bytes) used to identify encrypted pack containers.
pub const DLC_PACK_MAGIC: &[u8; 4] = b"BDLP";

/// Parse a `.dlcpack` container and return the embedded `dlc_id` and a list
/// of `(path, EncryptedAsset)` pairs. The returned `EncryptedAsset` values
/// will contain the same `dlc_id` for every entry.
pub fn parse_encrypted_pack(
    bytes: &[u8],
) -> Result<
    (
        String,
        usize,
        Vec<(String, crate::asset_loader::EncryptedAsset)>,
    ),
    std::io::Error,
> {
    use std::io::ErrorKind;

    // basic validation and header parsing
    if bytes.len() < 4 + 1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "dlcpack too small",
        ));
    }
    if &bytes[0..4] != DLC_PACK_MAGIC {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "invalid dlcpack magic",
        ));
    }
    let version = bytes[4];
    let mut offset = 5usize;

    let dlc_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    if offset + dlc_len > bytes.len() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "invalid dlc id length",
        ));
    }
    let dlc_id = String::from_utf8(bytes[offset..offset + dlc_len].to_vec())
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
    offset += dlc_len;

    // Versioned parsing: v1 = per-entry encrypted items, v2 = single encrypted gzip archive + plaintext manifest
    if version == 1 {
        // legacy format
        let entry_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if offset + 2 > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "missing path_len",
                ));
            }
            let path_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2;
            if offset + path_len > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid path length",
                ));
            }
            let path = String::from_utf8(bytes[offset..offset + path_len].to_vec())
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
            offset += path_len;

            if offset + 1 > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "missing ext_len",
                ));
            }
            let ext_len = bytes[offset] as usize;
            offset += 1;
            let original_extension = if ext_len == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "missing original extension",
                ));
            } else {
                if offset + ext_len > bytes.len() {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "invalid ext length",
                    ));
                }
                let s = String::from_utf8(bytes[offset..offset + ext_len].to_vec())
                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                offset += ext_len;
                s
            };

            // version 1+ stores an optional serialized type identifier per entry
            let original_type = if version >= 1 {
                if offset + 2 > bytes.len() {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "missing type_path len",
                    ));
                }
                let tlen = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
                offset += 2;
                if tlen == 0 {
                    None
                } else {
                    if offset + tlen > bytes.len() {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "invalid type_path length",
                        ));
                    }
                    let s = String::from_utf8(bytes[offset..offset + tlen].to_vec())
                        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                    offset += tlen;
                    Some(s)
                }
            } else {
                None
            };

            if offset + 12 + 4 > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "truncated entry",
                ));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&bytes[offset..offset + 12]);
            offset += 12;
            let ciphertext_len = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            offset += 4;
            if offset + ciphertext_len > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "truncated ciphertext",
                ));
            }
            let ciphertext = bytes[offset..offset + ciphertext_len].to_vec();
            offset += ciphertext_len;

            let enc = crate::asset_loader::EncryptedAsset {
                dlc_id: dlc_id.clone(),
                original_extension,
                type_path: original_type,
                nonce,
                ciphertext,
            };
            entries.push((path, enc));
        }

        Ok((dlc_id, 1usize, entries))
    } else if version >= 2 {
        // new archive-encrypted format: read manifest (u32 len + JSON), then nonce + ciphertext
        if offset + 4 > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "missing manifest_len",
            ));
        }
        let manifest_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + manifest_len > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "truncated manifest",
            ));
        }
        let manifest_bytes = &bytes[offset..offset + manifest_len];
        offset += manifest_len;
        let manifest: Vec<serde_json::Value> = serde_json::from_slice(manifest_bytes)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        if offset + 12 + 4 > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "truncated archive",
            ));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[offset..offset + 12]);
        offset += 12;
        let ciphertext_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + ciphertext_len > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "truncated ciphertext",
            ));
        }
        let ciphertext = bytes[offset..offset + ciphertext_len].to_vec();

        // Construct per-entry metadata entries that reference the shared ciphertext
        let mut entries = Vec::with_capacity(manifest.len());
        for v in manifest.into_iter() {
            let path = v
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| {
                    std::io::Error::new(ErrorKind::InvalidData, "manifest entry missing path")
                })?
                .to_string();
            let original_extension = v
                .get("original_extension")
                .and_then(|e| e.as_str())
                .unwrap_or("");
            let type_path = v
                .get("type_path")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());

            let enc = crate::asset_loader::EncryptedAsset {
                dlc_id: dlc_id.clone(),
                original_extension: original_extension.to_string(),
                type_path,
                nonce,
                ciphertext: ciphertext.clone(),
            };
            entries.push((path, enc));
        }

        Ok((dlc_id, version as usize, entries))
    } else {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "unsupported dlcpack version",
        ))
    }
}

#[derive(Error, Debug)]
pub enum DlcError {
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("malformed privatekey: {0}")]
    MalformedToken(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("payload parse failed: {0}")]
    PayloadInvalid(String),
    #[error("license expired")]
    Expired,

    // privatekey / crypto specific
    #[error("privatekey creation failed: {0}")]
    TokenCreationFailed(String),
    #[error("private key required for this operation")]
    PrivateKeyRequired,
    #[error("invalid publickey")]
    InvalidPassphrase,
    #[error("crypto error: {0}")]
    CryptoError(String),

    // encryption / decryption
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("")]
    DecryptionFailed,
    #[error("invalid content key: {0}")]
    InvalidContentKey(String),
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    // DLC / content-key state
    #[error("dlc locked: {0}")]
    DlcLocked(String),
    #[error(
        "no content key for dlc: {0} (hint: call DlcManager::unlock_verified_license with a privatekey containing a content_key)"
    )]
    NoContentKey(String),

    // privatekey binding mismatches
    #[error("privatekey product does not match")]
    TokenProductMismatch,

    // fallback
    #[error("{0}")]
    Other(String),
}

/// Usage example (simplified):
///
/// - Ship DLC assets with the main binary and tag them with `DlcHandle`.
/// - Deliver an offline-signed privatekey to the user. When they provide the privatekey
///   the game verifies it with a `DlcKey` and passes the typed result to
///   `DlcManager::unlock_verified_license` to enable access.
///
/// ```ignore
/// use bevy::prelude::*;
/// use bevy_dlc::{DlcPlugin, DlcManager, DlcHandle, DlcKey};
/// fn example() {
///     // at app startup (embed public key in build)
///     let pubkey_bytes = include_bytes!("../public.key");
///     app.add_plugins(DefaultPlugins).add_plugin(DlcPlugin::from_public_key_bytes(pubkey_bytes).unwrap());
///     // elsewhere: register asset on an entity:
///     commands.spawn((DlcHandle::new(texture_handle, "expansion_1"),));
///     // when privatekey is entered / verified:
///     // Warning: Never actually use any unwrap().  Always handle errors.
///     let vk = DlcKey::from_public_key_bytes(pubkey_bytes).unwrap();
///     let verified = vk.verify_signed_license(token_str).unwrap();
///     let mut dlc = world.resource_mut::<DlcManager>();
///     dlc.unlock_verified_license(verified).unwrap();
/// }
/// ```

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_and_unlock_token_roundtrip() {
        // generate a matching keypair for the test
        let key = DlcKey::generate_random();

        let token = key
            .create_signed_license(
                &[String::from("expansion_1")],
                None,
                None,
                None,
            )
            .expect("create privatekey");

        let mut manager = DlcManager::new();
        let vt = key
            .verify_signed_license(&token)
            .expect("verify privatekey");
        let unlocked = manager.unlock_verified_license(vt).expect("should verify");
        assert_eq!(unlocked, vec![DlcId::from("expansion_1")]);
        assert!(manager.is_unlocked_id(&DlcId::from("expansion_1")));
    }

    #[test]
    fn dlc_key_from_protected_seed() {
        // create a matching protected seed + public key pair
        let orig_key = DlcKey::generate_random();
        let protected = match orig_key { DlcKey::Private { ref privkey, .. } => privkey.clone(), _ => unreachable!() };
        let key = DlcKey::from_priv_and_pub(protected, orig_key.get_public_key().clone()).expect("from_seed");

        let privatekey = key
            .create_signed_license(
                &[String::from("expansion_1")],
                None,
                None,
                None,
            )
            .expect("create privatekey");

        let mut manager = DlcManager::new();
        let vt = key.verify_signed_license(&privatekey).expect("verify privatekey");
        let unlocked = manager.unlock_verified_license(vt).expect("verify");
        assert_eq!(unlocked, vec![DlcId::from("expansion_1")]);
    }

    #[test]
    fn dlc_key_generate_and_verify() {
        let key = DlcKey::generate_random();
        let privatekey = key
            .create_signed_license(
                &[String::from("expansion_1")],
                None,
                None,
                None,
            )
            .expect("create privatekey");

        let mut manager = DlcManager::new();
        let vt = key.verify_signed_license(&privatekey).expect("verify privatekey");
        let unlocked = manager.unlock_verified_license(vt).expect("verify");
        assert_eq!(unlocked, vec![DlcId::from("expansion_1")]);
        assert!(manager.is_unlocked_id(&DlcId::from("expansion_1")));
    }

    #[test]
    fn verify_inserts_content_key_into_registry() {
        crate::content_key_registry::clear_all();

        let key = DlcKey::generate_random();
        let sym_key: [u8; 32] = rand::random();
        let privatekey = key
            .create_signed_license(
                &[String::from("expansion_encrypted")],
                None,
                Some(&sym_key),
                None,
            )
            .expect("create privatekey with content_key");

        let mut manager = DlcManager::new();
        let vt = key.verify_signed_license(&privatekey).expect("verify privatekey");
        let _ = manager.unlock_verified_license(vt).expect("verify");

        let stored = crate::content_key_registry::get("expansion_encrypted").expect("key present");
        assert_eq!(stored, sym_key.to_vec());
    }

    #[test]
    fn pack_and_parse_roundtrip() {
        let key: [u8; 32] = rand::random();
        let plaintext = b"hello dlc v2";
        let (container, _nonce) =
            pack_encrypted_asset(plaintext, &DlcId::from("my_dlc"), Some("json"), None, &key)
                .expect("pack");

        let enc = parse_encrypted(&container).expect("parse");
        assert_eq!(enc.dlc_id, "my_dlc");
        assert_eq!(enc.original_extension, "json");
        // type_path is None because None was passed to pack_encrypted_asset
        assert!(enc.type_path.is_none());

        let decrypted = decrypt_with_key(&key, &enc.ciphertext, &enc.nonce).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pack_encrypted_pack_rejects_nested_dlc() {
        let key: [u8; 32] = rand::random();
        let dlc_id = DlcId::from("pack_test");
        let items = vec![("a.txt".to_string(), Some("txt".to_string()), None, {
            let mut v = Vec::new();
            v.extend_from_slice(b"BDLC");
            v.extend_from_slice(b"inner");
            v
        })];
        let res = pack_encrypted_pack(&dlc_id, &items, &key);
        assert!(matches!(res, Err(DlcError::Other(_))));
    }

    #[test]
    fn pack_encrypted_pack_rejects_nested_dlcpack() {
        let key: [u8; 32] = rand::random();
        let dlc_id = DlcId::from("pack_test");
        let items = vec![("b.bin".to_string(), None, None, {
            let mut v = Vec::new();
            v.extend_from_slice(b"BDLP");
            v.extend_from_slice(b"innerpack");
            v
        })];
        let res = pack_encrypted_pack(&dlc_id, &items, &key);
        assert!(matches!(res, Err(DlcError::Other(_))));
    }

    #[test]
    fn dlc_id_serde_roundtrip() {
        let id = DlcId::from("expansion_serde");
        let s = serde_json::to_string(&id).expect("serialize dlc id");
        assert_eq!(s, "\"expansion_serde\"");
        let decoded: DlcId = serde_json::from_str(&s).expect("deserialize dlc id");
        assert_eq!(decoded.to_string(), "expansion_serde");
    }

    #[test]
    fn verify_and_unlock_token_with_dlc_key_param() {
        let key = DlcKey::generate_random();
        let token = key
            .create_signed_license(
                &[String::from("expansion_1")],
                None,
                None,
                None,
            )
            .expect("create privatekey");

        let vt = key.verify_signed_license(&token).expect("verify privatekey");
        let mut manager = DlcManager::new();
        // unlock using the previously-verified privatekey
        let unlocked = manager
            .unlock_verified_license(vt)
            .expect("verify with dlckey");
        assert_eq!(unlocked, vec![DlcId::from("expansion_1")]);
    }
}
