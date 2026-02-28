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
use examples::*;
use bevy_cursor_kit::prelude::*;

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
        .add_plugins(ExamplePlugin::default())
        .add_plugins(DlcPlugin::new(
            dlc_key,
            SignedLicense::from(get_example_license()),
        ))
        .add_plugins(CursorAssetPlugin)
        .register_dlc_type::<StaticCursor>()
        .init_resource::<DlcPacks>()
        .init_resource::<Cursors>()
        .add_systems(Startup, startup)
        .add_systems(
            Update,
            insert_cursor.run_if(is_dlc_entry_loaded("dlcA", "blue.cur")),
        )
        .add_observer(on_dlc_pack_loaded)
        .run()
}

#[derive(Resource, Default)]
struct DlcPacks(Vec<Handle<DlcPack>>);

#[derive(Debug, Resource, Reflect, Default)]
#[reflect(Debug, Resource)]
struct Cursors(Handle<StaticCursor>);

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

    for entry in pack.find_by_type::<StaticCursor>() {
        let cursor: Handle<StaticCursor> = asset_server.load(entry.path());
        commands.insert_resource(Cursors(cursor));
    }
}

fn insert_cursor(
    mut commands: Commands,
    static_cursors: Res<Assets<StaticCursor>>,
    cursors: Res<Cursors>,
    window: Single<Entity, With<Window>>,
    mut setup: Local<bool>,
) {
    if *setup {
        return;
    }

    let Some(c) = static_cursors.get(&cursors.0.clone()) else {
        return;
    };
    
    commands
        .entity(*window)
        .insert(bevy::window::CursorIcon::Custom(
            CustomCursorImageBuilder::from_static_cursor(c, Some(5)).build(),
        ));

    *setup = true;
}
