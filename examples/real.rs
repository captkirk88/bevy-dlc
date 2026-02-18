// Example: typical game usage — the game knows the public key and verifies an
// offline-signed privatekey to unlock DLC. This example reads the shipped
// `assets/*.dlc` files and demonstrates AssetServer -> DlcLoader -> loader
// flow using a small `TextAsset` loader.

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
        .add_plugins(DlcPlugin::new(Product::from("example"),dlc_key, signedlicense))
        // register our simple `TextAsset` + loader and the generic DLC loader
        .init_asset::<TextAsset>()
        .init_asset_loader::<TextAssetLoader>()
        .register_dlc_type::<TextAsset>()
        .insert_resource(PackHandleResource::default())
        .add_systems(Startup, startup)
        .add_systems(Update, print_loaded.run_if(run_once))
        .run()
}

#[derive(Resource, Default)]
struct PackHandleResource(Handle<DlcPack>);

fn startup(
    asset_server: Res<AssetServer>,
    mut handle_res: ResMut<PackHandleResource>,
    mut commands: Commands,
) {
    let handle: Handle<DlcPack> = asset_server.load("expansionA.dlcpack");
    handle_res.0 = handle;

    commands.spawn(Camera2d);
}

fn print_loaded(
    _handle_res: ResMut<PackHandleResource>,
    dlc_packs: Res<Assets<DlcPack>>,
    _image_assets: ResMut<Assets<Image>>,
    mut exit: MessageWriter<AppExit>,
    asset_server: Res<AssetServer>,
    dlc: Res<DlcManager>,
    mut commands: Commands,
) -> Result<()> {
    // show any loaded packs (helpful while debugging async loader behavior)
    for (_, pack) in dlc_packs.iter() {
        info!(
            "DlcPack '{}' entries={:?}",
            pack.id(),
            pack.entries()
        );
    }

    let pack = if let Some(pack) = dlc_packs.get(&_handle_res.0) {
        pack
    } else {
        // pack not loaded yet — in a real game you would want to show a loading screen or something
        error!("DlcPack not loaded yet!");
        exit.write(AppExit::from_code(2u8));
        return Ok(());
    };

    if pack.entries().is_empty() {
        error!("DlcPack present but contains no entries!");
        exit.write(AppExit::from_code(3u8));
        return Ok(());
    }

    // check if the DLC is unlocked before using the content
    if dlc.is_unlocked_id(pack.id()) {
        if let Some(first) = pack.entries().first() {
            let img = first.load(&asset_server);
            info!("DLC is unlocked! Loaded asset path: {}", first.path());
            commands.spawn(Sprite::from_image(img));
        } else {
            info!("DLC is unlocked but no entries found in the pack");
        }
    } else {
        info!("pack is present but DLC is not unlocked yet");
    }
    return Ok(());
}
