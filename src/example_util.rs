use bevy::{asset::*, prelude::*};

// DO NOT USE ABCD as your choice of secure key. This is just a placeholder for the example.
// create a compile-time encrypted literal and expose a typed wrapper that
// returns `SignedLicense` (zeroized wrapper). Uses the `secure` crate's
// `secure_str_aes!` under the hood via the `secure!` helper macro.
#[cfg(feature = "example")]
secure::secure_str_aes!("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "EXAMPLE_LICENSE", "eyJkbGNzIjpbImV4cGFuc2lvbkEiXSwiZW5jcnlwdF9rZXkiOiIzZ1pRekU5Y1IxQTQ5cFlTZ1FTYkhVMldjTVpNWWdZbVpRS1AxdWFJcnZFIiwicHJvZHVjdCI6ImV4YW1wbGUifQ.vitSR1ZjTT6dzzujTtmHnAE8w-JmBssu7H7Mr43M1luN-fafS3dqQ-g3SFw83PU7kDoXNAL29jaVMoKz_ttsAA");

pub const EXAMPLE_PUBKEY: &str = "Df4bDHFR_Fx0I6QZajTK6IGRRG0sOlsv0qUeNITCn9w";

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
