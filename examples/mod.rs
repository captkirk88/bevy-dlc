use bevy::{asset::{AssetLoader, LoadContext, io::Reader}, prelude::*};

#[derive(Asset, Reflect, serde::Serialize, serde::Deserialize)]
pub struct TextAsset(pub String);

#[derive(Default, Reflect)]
pub struct TextAssetLoader;

impl AssetLoader for TextAssetLoader {
    type Asset = TextAsset;
    type Settings = ();
    type Error = std::io::Error;

    async fn load(
        &self,
        reader: &mut dyn Reader,
        _settings: &(),
        _load_context: &mut LoadContext<'_>,
    ) -> Result<Self::Asset, Self::Error> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await?;
        let s = String::from_utf8(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(TextAsset(s))
    }

    fn extensions(&self) -> &[&str] {
        &["txt", "json"]
    }
}

#[allow(unused)]
fn main() {}