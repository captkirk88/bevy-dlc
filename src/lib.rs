//! bevy-dlc — simple DLC gating for Bevy 0.18
//!
//! Strategy implemented: pre-load DLC assets in the main build and gate their
//! usage with an offline, signed license token (Ed25519). This provides
//! "unlock key"/entitlement-style DLC: assets are present but unusable until
//! the token is verified locally.
//!
//! Security notes: offline-signed licenses are secure if the private key is
//! kept secret and the public key is embedded in the game. They do not allow
//! revocation without an online check — use server validation for revocation.

use bevy::prelude::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub mod prelude {
    pub use crate::{DlcHandle, DlcManager, DlcPlugin};
    pub use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    pub use base64::Engine as _;
    pub use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
}
/// Bevy plugin that inserts a `DlcManager` resource.
///
/// Provide the public key bytes that will be used to verify offline-signed
/// license tokens.
pub struct DlcPlugin {
    pub public_key: VerifyingKey,
}

impl DlcPlugin {
    /// Create the plugin from raw public-key bytes (Ed25519, 32 bytes).
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, DlcError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DlcError::InvalidPublicKey("public key must be 32 bytes".into()))?;
        // ed25519-dalek v2 uses fixed-size byte arrays for keys/signatures
        let pk = VerifyingKey::from_bytes(&arr).map_err(|e| DlcError::InvalidPublicKey(e.to_string()))?;
        Ok(DlcPlugin { public_key: pk })
    }
}

impl Plugin for DlcPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(DlcManager::new(self.public_key.clone()));
    }
}

/// Resource that holds unlocked DLC IDs and verifies signed license tokens.
#[derive(Resource, Debug)]
pub struct DlcManager {
    public_key: VerifyingKey,
    unlocked: HashSet<String>,
}

impl DlcManager {
    /// Construct a manager from an Ed25519 `VerifyingKey`.
    pub fn new(public_key: VerifyingKey) -> Self {
        Self { public_key, unlocked: HashSet::new() }
    }

    /// Verify a compact token and unlock the DLC IDs contained in it.
    ///
    /// Token format: `base64url(payload_json)`.`base64url(signature_bytes)`.
    /// Payload example: { "dlcs": ["expansion_1"], "exp": 1710000000 }
    pub fn verify_and_unlock_token(&mut self, token: &str) -> Result<Vec<String>, DlcError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err(DlcError::MalformedToken(
                "expected token with two dot-separated parts".into(),
            ));
        }

        let payload = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| DlcError::MalformedToken(format!("payload base64: {}", e)))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| DlcError::MalformedToken(format!("signature base64: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(DlcError::MalformedToken("signature bytes length must be 64".into()));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        self.public_key
            .verify(&payload, &signature)
            .map_err(|_| DlcError::SignatureInvalid)?;

        let lic: LicensePayload = serde_json::from_slice(&payload)
            .map_err(|e| DlcError::PayloadInvalid(e.to_string()))?;

        if let Some(exp) = lic.exp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DlcError::Other(e.to_string()))?
                .as_secs();
            if now > exp {
                return Err(DlcError::Expired);
            }
        }

        for id in &lic.dlcs {
            self.unlocked.insert(id.clone());
        }

        Ok(lic.dlcs)
    }

    /// Mark a single DLC as unlocked (useful for tests or server-validated flow).
    pub fn unlock(&mut self, dlc_id: impl Into<String>) {
        self.unlocked.insert(dlc_id.into());
    }

    /// Check whether a DLC is unlocked.
    pub fn is_unlocked(&self, dlc_id: &str) -> bool {
        self.unlocked.contains(dlc_id)
    }

    /// Return a list of currently unlocked DLC ids.
    pub fn unlocked_list(&self) -> Vec<String> {
        self.unlocked.iter().cloned().collect()
    }
}

/// A small wrapper that associates an asset Handle with a DLC id.
/// The asset may be loaded but `get_if_unlocked` returns `None` until the
/// DLC is unlocked via `DlcManager`.
#[derive(Clone, Debug)]
pub struct DlcHandle<T: Asset> {
    pub handle: Handle<T>,
    pub dlc_id: String,
}

impl<T: Asset> DlcHandle<T> {
    pub fn new(handle: Handle<T>, dlc_id: impl Into<String>) -> Self {
        Self { handle, dlc_id: dlc_id.into() }
    }

    /// Return the contained `Handle<T>` if the DLC is unlocked.
    pub fn get_if_unlocked(&self, dlc: &DlcManager) -> Option<Handle<T>> {
        if dlc.is_unlocked(&self.dlc_id) {
            Some(self.handle.clone())
        } else {
            None
        }
    }

    /// Convenience check.
    pub fn is_unlocked(&self, dlc: &DlcManager) -> bool {
        dlc.is_unlocked(&self.dlc_id)
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
}

#[derive(Error, Debug)]
pub enum DlcError {
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("malformed token: {0}")]
    MalformedToken(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("payload parse failed: {0}")]
    PayloadInvalid(String),
    #[error("license expired")]
    Expired,
    #[error("other error: {0}")]
    Other(String),
}



/// Usage example (simplified):
///
/// - Ship DLC assets with the main binary and tag them with `DlcHandle`.
/// - Deliver an offline-signed token to the user. When they provide the token
///   the game calls `DlcManager::verify_and_unlock_token` to enable access.
///
/// ```ignore
/// use bevy::prelude::*;
/// use bevy_dlc::{DlcPlugin, DlcManager, DlcHandle};
/// fn example() {
///     // at app startup (embed public key in build)
///     let pubkey_bytes = include_bytes!("../public.key");
///     app.add_plugins(DefaultPlugins).add_plugin(DlcPlugin::from_public_key_bytes(pubkey_bytes).unwrap());
///     // elsewhere: register asset on an entity:
///     commands.spawn((DlcHandle::new(texture_handle, "expansion_1"),));
///     // when token is entered / verified:
///     let mut dlc = world.resource_mut::<DlcManager>();
///     dlc.verify_and_unlock_token(token_str).unwrap();
/// }
/// ```

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use ed25519_dalek::Signer;

    #[test]
    fn verify_and_unlock_token_roundtrip() {
        // deterministic test key (do NOT use a fixed seed in production)
        let seed = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = VerifyingKey::from(&signing_key);

        let payload = LicensePayload { dlcs: vec!["expansion_1".into()], exp: None, iat: None, nonce: None, product: None };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let sig = signing_key.sign(&payload_bytes);

        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_bytes),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );

        let mut manager = DlcManager::new(verifying_key);
        let unlocked = manager.verify_and_unlock_token(&token).expect("should verify");
        assert_eq!(unlocked, vec!["expansion_1".to_string()]);
        assert!(manager.is_unlocked("expansion_1"));
    }
}
