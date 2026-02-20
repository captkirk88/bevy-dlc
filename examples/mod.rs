use bevy::prelude::*;

#[derive(Asset, Reflect, serde::Serialize, serde::Deserialize)]
pub struct TextAsset(pub String);

#[allow(unused)]
fn main() {}