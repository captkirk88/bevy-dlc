use bevy::prelude::*;

// A simple text/string asset used in the examples.  the helper macro generates
// the struct, a loader, and a plugin that registers the loader + DLC type.
bevy_dlc::dlc_simple_asset!(TextAsset, TextAssetLoader, TextAssetPlugin, "txt", "json",);

#[derive(serde::Serialize, serde::Deserialize, Reflect, Clone, Debug)]
pub struct Person {
    pub age: u32,
    pub city: String,
}

#[derive(Asset, Reflect, serde::Serialize, serde::Deserialize)]
pub struct JsonAsset(pub std::collections::HashMap<String, Person>);

#[allow(unused)]
fn main() {}
