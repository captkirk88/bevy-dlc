//! This module contains example code for how to use DLC in a Bevy app. It also contains an example privatekey and pubkey for testing purposes. In a real app, you would want to store the privatekey securely (e.g. in an environment variable or a secure vault) and not hardcode it in your source code.

use bevy::{asset::*, prelude::*};

use crate::PrivateKey;

// Private signing seed used by examples/tests. Use this to produce tokens
// programmatically (don't embed private seeds in production code).
pub const EXAMPLE_TOKEN: PrivateKey = PrivateKey::new([
    0x8f, 0x8a, 0x0a, 0xde, 0x87, 0x71, 0x3a, 0x2a, 0x9c, 0x67, 0x18, 0xb2, 0x4c, 0xef, 0xc2, 0x35,
    0x4f, 0xeb, 0xaa, 0x49, 0xae, 0x56, 0xd9, 0xd6, 0xbc, 0xa7, 0x4d, 0xfc, 0xe1, 0x62, 0xd5, 0x4a,
]);

// Corresponding public key (base64url, *without* the `pub.` prefix)
pub const EXAMPLE_PUBKEY: &str = "WMbgRrKylvaZct8uXIEoEGw4UGzgw1zZmnOa6iXE_0M";

#[derive(Debug, Clone, TypePath, Asset)]
pub struct TextAsset(pub String);

#[derive(TypePath, Default)]
pub struct TextAssetLoader;

#[derive(thiserror::Error, Debug)]
pub enum TextAssetLoaderError {
    #[error("io error: {0}")]
    Io(String),
    #[error("utf8 error: {0}")]
    Utf8(String),
}

impl AssetLoader for TextAssetLoader {
    type Asset = TextAsset;
    type Settings = ();
    type Error = TextAssetLoaderError;

    fn extensions(&self) -> &[&str] {
        &["json", "txt"]
    }

    async fn load(
        &self,
        reader: &mut dyn bevy::asset::io::Reader,
        _settings: &Self::Settings,
        _load_context: &mut LoadContext<'_>,
    ) -> Result<Self::Asset, Self::Error> {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| TextAssetLoaderError::Io(e.to_string()))?;
        let s = String::from_utf8(bytes).map_err(|e| TextAssetLoaderError::Utf8(e.to_string()))?;
        Ok(TextAsset(s))
    }
}
