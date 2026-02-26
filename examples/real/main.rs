//! Example of loading DLC packs with `bevy-dlc`.
//! This example assumes you have already generated a signed license and DLC pack using the CLI tool:
//! ```bash
//! bevy-dlc generate --product example -o keys/
//! ```
//! You will see warnings in the console about missing asset loaders for the DLC pack entries until you register them with their AssetLoader and `app.register_dlc_type::<T>()` (see `startup` system below). This is expected and intentional to demonstrate how the plugin handles unsupported asset types in DLC packs, and to show how you can add support for them.

use bevy::prelude::*;
use bevy_dlc::DlcPack;
use bevy_dlc::prelude::*;

#[path = "../mod.rs"]
mod examples;
use examples::TextAsset;

use crate::examples::TextAssetLoader;

// You must generate `example.slicense` and `example.pubkey` by `bevy-dlc generate example`

fn main() -> AppExit {
    // DO NOT USE ABCD... as your choice of secure key. This is just a placeholder for the example.
    // This is the RECOMMENDED approach:
    // Create cryptographically secure license key that can't be decrypted from your compiled binary (game).
    secure::include_secure_str_aes!(
        "examples/example_keys/example.slicense",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "example_license"
    );
    
    let dlc_key = DlcKey::public(include_str!("../example_keys/example.pubkey"))
        .expect("invalid example pubkey");

    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(DlcPlugin::new(
            dlc_key,
            SignedLicense::from(get_example_license()),
        ))
        .init_asset_loader::<TextAssetLoader>()
        .register_dlc_type::<TextAsset>()
        .init_resource::<DlcPacks>()
        .add_systems(Startup, startup)
        .add_systems(
            Update,
            display_loaded_text.run_if(is_dlc_entry_loaded("dlcA", "test.txt")),
        )
        .add_observer(on_dlc_pack_loaded)
        .run()
}

#[derive(Resource, Default)]
struct DlcPacks(Vec<Handle<DlcPack>>);

#[derive(Component)]
struct DlcAText(Handle<TextAsset>);

#[allow(unused)]
fn startup(asset_server: Res<AssetServer>, mut packs: ResMut<DlcPacks>, mut commands: Commands) {
    packs.0.push(asset_server.load::<DlcPack>("dlcA.dlcpack"));
    commands.spawn(Camera2d);
}

fn on_dlc_pack_loaded(
    event: On<DlcPackLoaded>,
    asset_server: Res<AssetServer>,
    mut commands: Commands,
) {
    let pack = event.pack();

    for entry in pack.find_by_type::<Image>() {
        let img: Handle<Image> = asset_server.load(entry.path());
        commands.spawn(Sprite::from_image(img));
    }

    for entry in pack.find_by_type::<TextAsset>() {
        let text_asset: Handle<TextAsset> = asset_server.load(entry.path());
        commands.spawn(DlcAText(text_asset));
    }
}

fn display_loaded_text(
    text_assets: Res<Assets<TextAsset>>,
    mut commands: Commands,
    query: Query<(Entity, &DlcAText)>,
) {
    for (entity, loaded) in query.iter() {
        match text_assets.get(&loaded.0) {
            Some(text_asset) => {
                info!("Loaded TextAsset from DLC: {}", text_asset.0);
                // prevent re-printing
                commands.entity(entity).remove::<DlcAText>();

                let mut ent = commands.entity(entity);
                ent.insert((
                    Text::from(text_asset.0.clone()),
                    TextFont {
                        font_size: 12.0,
                        ..default()
                    },
                    TextColor(Color::LinearRgba(LinearRgba::BLUE)),
                    Node {
                        position_type: PositionType::Absolute,
                        top: Val::Px(5.0),
                        left: Val::Px(15.0),
                        ..default()
                    },
                ));
            }
            None => {
                debug!("TextAsset not ready yet for handle: {:?}", loaded.0);
                return;
            }
        }
    }
}
