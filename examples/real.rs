// Example: typical game usage — the game knows the public key and verifies an
// offline-signed license to unlock DLC. This example reads the shipped
// `assets/*.dlc` files and demonstrates usage.

use bevy::prelude::*;
use bevy_dlc::DlcPack;
use bevy_dlc::example_util::*;
use bevy_dlc::prelude::*;

fn main() -> AppExit {
    // Use the public-only DlcKey (matches the `pack` CLI output). The app
    // only needs the public key; the SignedLicense (private token) is
    // supplied separately (for example, printed by `cargo run -- pack`).
    let dlc_key = DlcKey::public(EXAMPLE_PUBKEY).expect("invalid example pubkey");
    let signedlicense = SignedLicense::from(get_EXAMPLE_LICENSE());

    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(DlcPlugin::new(
            Product::from("example"),
            dlc_key,
            signedlicense,
        ))
        // register our simple `TextAsset` + loader and the generic DLC loader
        .init_asset::<TextAsset>()
        .init_asset_loader::<TextAssetLoader>()
        .register_dlc_type::<TextAsset>()
        .add_systems(Startup, startup)
        .add_systems(
            Update,
            show_dlc_content.run_if(dlc_unlocked("expansionA").and(run_once)),
        )
        .run()
}

#[allow(unused)]
#[derive(Component)]
struct LoadedPack(Handle<DlcPack>);

fn startup(asset_server: Res<AssetServer>, mut commands: Commands, dlc_mgr: Res<DlcManager>) {
    let handle = asset_server.load::<DlcPack>("expansionA.dlcpack");

    commands.spawn((Camera2d, LoadedPack(handle)));

    let dlc_id = DlcId::from("expansionA");
    if dlc_mgr.is_unlocked_id(&dlc_id) {
        info!("DLC is already unlocked at startup!");
    } else {
        info!("DLC is locked at startup.");
    }
}

fn show_dlc_content(
    dlc_packs: Res<Assets<DlcPack>>,
    asset_server: Res<AssetServer>,
    mut commands: Commands,
) {
    info!("DLC is unlocked! Showing DLC content...");

    for (_, pack) in dlc_packs.iter() {
        for entry in pack.entries() {
            let img: Handle<Image> = asset_server.load(entry.path());
            info!("Spawning sprite for DLC entry: {}", entry.path());
            commands.spawn(Sprite::from_image(img));
        }
    }
}
