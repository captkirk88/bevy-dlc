// Example: typical game usage — the game knows the public key and verifies an
// offline-signed privatekey to unlock DLC. This example reads the shipped
// `assets/*.dlc` files and demonstrates AssetServer -> DlcLoader -> loader
// flow using a small `TextAsset` loader.

use bevy::prelude::*;
use bevy_dlc::DlcPack;

// =====================================================================
// EXAMINE "src/example_util.rs" TO SEE HOW TO STORE TOKEN SECURELY
// =====================================================================
use bevy_dlc::example_util::*;
use bevy_dlc::prelude::*;

fn main() -> AppExit {
    // decode the example public key (base64url) and wrap it in `DlcKey`
    // (client-side public-only wrapper). The example privatekey below was issued
    // by the corresponding private key so verification succeeds.
    // construct a `PublicKey` from the base64url constant and validate it
    let _ = PublicKey::from_base64url(EXAMPLE_PUBKEY).expect("invalid pubkey");

    App::new()
        .add_plugins(DefaultPlugins)
        // insert DlcManager from the `DlcKey` (public-only) and keep the
        // `DlcKey` in resources so examples can verify tokens explicitly.
        .insert_resource(DlcManager::new())
        // register our simple `TextAsset` + loader and the generic DLC loader
        .init_asset::<TextAsset>()
        .init_asset_loader::<TextAssetLoader>()
        .init_asset::<DlcPack>()
        .init_asset_loader::<bevy_dlc::DlcPackLoader>()
        .init_asset_loader::<bevy_dlc::DlcLoader<TextAsset>>()
        .insert_resource(PackHandleResource::default())
        .add_systems(Startup, startup)
        .add_systems(Update, print_loaded)
        .run()
}

#[derive(Resource, Default)]
struct PackHandleResource(Handle<DlcPack>);

fn startup(
    asset_server: Res<AssetServer>,
    mut dlc: ResMut<DlcManager>,
    mut handle_res: ResMut<PackHandleResource>,
) {
    // verify privatekey (populates DlcManager content-keys). Recreate the
    // public-only `DlcKey` from the example constant and verify the privatekey
    // using the typed flow (no raw-&str manager API).
    let pubkey = PublicKey::from_base64url(EXAMPLE_PUBKEY).expect("invalid pubkey");
    let pub_dlc_key = DlcKey::Public { pubkey: pubkey.clone() };

    // EXAMPLE_TOKEN is a `SigningSeed` constant — construct a private key
    // using the matching publickey and issue the example privatekey for testing.
    let pass = PublicKey::from_base64url(EXAMPLE_PUBKEY).expect("invalid pubkey");
    let private = DlcKey::from_priv_and_pub(EXAMPLE_TOKEN, pass.clone()).expect("from seed");
    let privatekey = private
        .create_signed_license(&["expansionA"], None, None, None)
        .expect("create privatekey");
    let vt = pub_dlc_key.verify_signed_license(&privatekey).expect("verify privatekey");
    dlc.unlock_verified_license(vt).expect("unlock privatekey");

    // diagnostic: ensure content key was inserted into the manager
    if dlc
        .content_key_for_id(&DlcId::from("expansionA"))
        .is_some()
    {
        bevy::log::info!("startup: content_key present for expansionA (via DlcManager)");
    } else {
        bevy::log::warn!("startup: content_key NOT present for expansionA (via DlcManager)");
    }

    // request the pack load (async) and save handle to a resource so
    // we can check load state reliably from `print_loaded` (don't call
    // `load` every frame — reuse the same handle).
    let handle = asset_server.load::<DlcPack>("expansionA.dlcpack");
    bevy::log::info!(
        "startup: requested load for expansionA.dlcpack: {:?}",
        handle
    );
    handle_res.0 = handle;
}

fn print_loaded(
    _handle_res: ResMut<PackHandleResource>,
    assets: Res<Assets<DlcPack>>,
    _image_assets: ResMut<Assets<Image>>,
    mut exit: MessageWriter<AppExit>,
    asset_server: Res<AssetServer>,
    dlc: Res<DlcManager>,
) {
    // show any loaded packs (helpful while debugging async loader behavior)
    for (id, pack) in assets.iter() {
        bevy::log::info!(
            "DlcPack '{}' loaded: id={} entries={:?}",
            pack.id(),
            id,
            pack.entries()
        );
    }

    let pack = if let Some(pack) = assets.get(&_handle_res.0) {
        pack
    } else {
        bevy::log::error!("DlcPack not loaded yet!");
        exit.write(AppExit::from_code(2u8));
        return;
    };

    if pack.entries().is_empty() {
        bevy::log::error!("DlcPack present but contains no entries!");
        exit.write(AppExit::from_code(3u8));
        return;
    }

    if dlc.is_unlocked_id(&DlcId::from(pack.id())) {
        if let Some(first) = pack.entries().first() {
            let path = first.path().to_owned();
            let img = asset_server.load::<Image>(&path);
            bevy::log::info!("loaded '{}' from pack as Image: {:?}", path, img);
        }
    }
}
