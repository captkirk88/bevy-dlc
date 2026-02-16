use bevy::prelude::*;
use bevy_dlc::DlcKey;
use bevy_dlc::prelude::*;

// =====================================================================
// EXAMINE "src/example_util.rs" TO SEE HOW TO STORE TOKEN SECURELY
// =====================================================================
use bevy_dlc::example_util::*;

// Minimal example that demonstrates how to "tag" a Bevy entity with a
// `DlcHandle` (the handle may reference a preloaded asset) and *conditionally*
// spawn the actual in-game asset only after the offline-signed privatekey is
// verified by `DlcManager`.
//
// Run: `cargo run --example spawn`

fn main() {
    // demo keypair (server would sign tokens in real usage)
    let (dlc_key, _pubkey) = DlcKey::generate_complete();

    // build a compact privatekey that unlocks `expansion_1` and is bound to a
    // product (demonstrates anti-reuse binding)
    let product = Product::from("demo_product".to_string());
    let privatekey = dlc_key
        .create_private_token(
            &["expansion_1"],
            Some(product.clone()),
            None,
            None,
        )
        .unwrap();

    App::new()
        .add_plugins(DefaultPlugins)
        .init_asset::<TextAsset>()
        .init_asset_loader::<TextAssetLoader>()
        // insert the DlcManager bound to the same product as the privatekey
        .insert_resource(
            DlcManager::new().with_product(product.expose_secret()),
        )
        // keep the demo key in a small resource so the example can verify tokens
        .insert_resource(DemoDlcKey(dlc_key.clone()))
        .insert_resource(ExampleToken(privatekey))
        .add_systems(Startup, (setup, apply_example_token))
        // only run the spawn system if the DLC is unlocked (uses `dlc_unlocked`)
        .add_systems(Update, spawn_dlc.run_if(dlc_unlocked("expansion_1")))
        .run();
}

#[derive(Resource)]
struct ExampleToken(PrivateToken);

#[derive(Resource)]
struct DemoDlcKey(DlcKey);

#[derive(Component)]
struct LockedDlc; // marker component — the entity represents locked DLC

// store the DlcHandle as part of a component so it's attached to an entity
#[derive(Component)]
struct AssetTag(DlcHandle<TextAsset>);

fn setup(mut commands: Commands, asset_server: Res<AssetServer>) {
    // pretend the DLC texture is bundled with the game — we "preload" it by
    // creating a handle (file needn't exist for the example to compile):
    let dlc_texture: Handle<TextAsset> = asset_server.load("test.txt");

    // create an entity that represents DLC content in the scene; it is
    // initially locked (has `LockedDlc`) and carries an `AssetTag` which
    // contains the preloaded asset handle wrapped in `DlcHandle`.
    let dlc_handle = DlcHandle::new(dlc_texture, "expansion_1");
    commands.spawn((LockedDlc, AssetTag(dlc_handle)));

    info!("spawned locked DLC entity — content is present but not yet used");
}

fn apply_example_token(
    privatekey: Res<ExampleToken>,
    mut dlc: ResMut<DlcManager>,
    demo_key: Res<DemoDlcKey>,
) {
    match demo_key.0.verify_token(&privatekey.0) {
        Ok(vt) => match dlc.unlock_verified_token(vt) {
            Ok(list) => info!("unlocked DLCs: {:?}", list),
            Err(e) => warn!("failed to unlock privatekey: {e}"),
        },
        Err(e) => warn!("failed to verify privatekey: {e}"),
    }
}

// When the DLC is unlocked we take the preloaded handle from `AssetTag` and
// spawn the real Sprite (demonstrating "unlocking" preloaded content).
fn spawn_dlc(
    dlc: Res<DlcManager>,
    query: Query<(Entity, &AssetTag), With<LockedDlc>>,
    mut commands: Commands,
    text_assets: Res<Assets<TextAsset>>,
) {
    for (entity, tag) in query.iter() {
        if tag.0.is_unlocked(&dlc) {
            // spawn the real asset into the world using the preloaded handle
            commands.spawn(Text::new(
                text_assets
                    .get(&tag.0.handle)
                    .map(|a| a.0.clone())
                    .unwrap_or_else(|| "Failed to load DLC asset".to_string()),
            ));
            // remove the locked marker so we don't respawn repeatedly
            commands.entity(entity).remove::<LockedDlc>();
            info!("spawned unlocked DLC content for '{}'", tag.0.dlc_id);
        }
    }
}
