//! Example of loading `bevy-common-assets` from a DLC pack with `bevy-dlc`.
//! This example assumes you have already generated a signed license and DLC pack using the CLI tool:
//! ```bash
//! bevy-dlc generate --product example -o keys/
//! ```
//! You will see warnings in the console about missing asset loaders for the DLC pack entries until you register them with their AssetLoader and `app.register_dlc_type::<T>()` (see `startup` system below). This is expected and intentional to demonstrate how the plugin handles unsupported asset types in DLC packs, and to show how you can add support for them.

use bevy::prelude::*;
use bevy_common_assets::json::JsonAssetPlugin;
use bevy_dlc::DlcPack;
use bevy_dlc::prelude::*;

#[path = "../mod.rs"]
mod examples;
use examples::JsonAsset;


fn main() -> AppExit {
    // DO NOT USE ABCD... as your choice of secure key. This is just a placeholder for the example.
    // This is the RECOMMENDED approach:
    // Create cryptographically secure license key that can't be decrypted from your compiled binary (game).
    secure::include_secure_str_aes!(
        "example.slicense",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "example_license"
    );

    let dlc_key =
        DlcKey::public(include_str!("../../example.pubkey")).expect("invalid example pubkey");

    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(DlcPlugin::new(dlc_key, SignedLicense::from(get_example_license())))
        .init_resource::<DlcPacks>()
        .add_plugins(JsonAssetPlugin::<JsonAsset>::new(&["json"]))
        .register_dlc_type::<JsonAsset>()
        .add_systems(Startup, startup)
        .add_systems(Update, display_loaded_text)
        .add_observer(on_dlc_pack_loaded)
        .run()
}

#[derive(Resource,Default)]
struct DlcPacks(Vec<Handle<DlcPack>>);

#[derive(Component)]
struct LoadedJson(Handle<JsonAsset>);

fn startup(asset_server: Res<AssetServer>,mut packs: ResMut<DlcPacks>, mut commands: Commands) {
    packs.0.push(asset_server.load::<DlcPack>("dlcA.dlcpack"));
    commands.spawn(Camera2d);
}

fn on_dlc_pack_loaded(
    event: On<DlcPackLoaded>,
    asset_server: Res<AssetServer>,
    mut commands: Commands,
) {
    let pack = event.pack();
    
    for entry in pack.entries() {
        info!(
            "DLC Pack contains asset: {} of type {}",
            entry.path(),
            entry.type_path().unwrap_or(&"<unknown>".to_string())
        );
    }

    for entry in pack.find_by_type::<Image>() {
        let img: Handle<Image> = asset_server.load(entry.path());
        commands.spawn(Sprite::from_image(img));
    }

    for entry in pack.find_by_type::<JsonAsset>() {
        let json_asset: Handle<JsonAsset> = asset_server.load(entry.path());
        commands.spawn(LoadedJson(json_asset));
    }
}


fn display_loaded_text(
    json_assets: Res<Assets<JsonAsset>>,
    mut commands: Commands,
    query: Query<(Entity, Option<&LoadedJson>)>,
) {
    for (entity, json_loaded) in query.iter() {
        if let Some(loaded) = json_loaded {
            if let Some(json_asset) = json_assets.get(&loaded.0) {
                let count = json_asset.0.len();
                info!("Loaded JsonAsset from DLC with {} entries", count);
                commands.entity(entity).remove::<LoadedJson>().insert((
                    Text::from(format!("JSON: {} people found", count)),
                    TextFont {
                        font_size: 12.0,
                        ..default()
                    },
                    TextColor(Color::LinearRgba(LinearRgba::GREEN)),
                    Node {
                        position_type: PositionType::Absolute,
                        top: Val::Px(25.0),
                        left: Val::Px(15.0),
                        ..default()
                    },
                ));
            }
        }
    }
}
