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
    let dlc_key = DlcKey::generate_random();

    // build a compact privatekey that unlocks `expansion_1` and is bound to a
    // product (demonstrates anti-reuse binding)
    let product = Product::from("demo_product".to_string());
    let signedlicense = dlc_key
        .create_signed_license(&["expansion_1"], product.clone())
        .unwrap();

    App::new()
        .add_plugins(DefaultPlugins)
        .init_asset::<TextAsset>()
        .init_asset_loader::<TextAssetLoader>()
        // insert the DlcManager bound to the same product as the privatekey
        .insert_resource(DlcManager::new(product))
        // keep the demo key in a small resource so the example can verify tokens
        .insert_resource(DemoDlcKey(dlc_key.clone()))
        .insert_resource(ExampleLicense(signedlicense))
        .add_systems(Startup, (setup, apply_example_token))
        // only run the spawn system if the DLC is unlocked (uses `dlc_unlocked`)
        .add_systems(Update, spawn_dlc.run_if(dlc_unlocked("expansion_1")))
        .run();
}

#[derive(Resource)]
struct ExampleLicense(SignedLicense);

#[derive(Resource)]
struct DemoDlcKey(DlcKey);

#[derive(Component)]
struct LockedDlc; // marker component — the entity represents locked DLC

// store the DlcHandle as part of a component so it's attached to an entity
#[derive(Component)]
struct AssetTag(DlcHandle<TextAsset>);

fn setup(mut commands: Commands, asset_server: Res<AssetServer>) {
    commands.spawn(Camera2d);

    // pretend we preloaded the DLC asset (the path is what the DLC pack references)
    let dlc_content: Handle<TextAsset> = asset_server.load("test.txt");

    // create an entity that represents DLC content in the scene; it is
    // initially locked (has `LockedDlc`) and carries an `AssetTag` which
    // contains the preloaded asset handle wrapped in `DlcHandle`.
    let dlc_handle = DlcHandle::new(dlc_content, "expansion_1");
    commands.spawn((LockedDlc, AssetTag(dlc_handle)));

    info!("spawned locked DLC entity — content is present but not yet used");
}

fn apply_example_token(
    privatekey: Res<ExampleLicense>,
    mut dlc: ResMut<DlcManager>,
    demo_key: Res<DemoDlcKey>,
) {
    match demo_key.0.verify_signed_license(&privatekey.0) {
        Ok(vt) => match dlc.unlock_verified_license(vt) {
            Ok(list) => info!(
                "unlocked DLCs: {}",
                list.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Err(e) => warn!("failed to unlock: {e}"),
        },
        Err(e) => warn!("failed to verify: {e}"),
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
            commands.spawn((
                Text::new(
                    text_assets
                        .get(&tag.0.handle)
                        .map(|a| a.0.clone())
                        .unwrap_or_else(|| "Failed to load DLC asset".to_string()),
                ),
                TextFont {
                    font_size: 32.0,
                    ..default()
                },
                Node {
                    position_type: PositionType::Absolute,
                    align_self: AlignSelf::Center,
                    ..default()
                },
            ));
            // remove the locked marker so we don't respawn repeatedly
            commands.entity(entity).remove::<LockedDlc>();
            info!("spawned unlocked DLC content for '{}'", tag.0.dlc_id);
        }
    }
}
