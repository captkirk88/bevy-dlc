use bevy::prelude::*;
use bevy_dlc::prelude::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// Minimal example that demonstrates how to "tag" a Bevy entity with a
// `DlcHandle` (the handle may reference a preloaded asset) and *conditionally*
// spawn the actual in-game asset only after the offline-signed token is
// verified by `DlcManager`.
//
// Run: `cargo run --example dlc_spawn`

fn main() {
    // demo signing key (server would sign tokens in real usage)
    let seed = [1u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
    let pub_bytes = verifying_key.to_bytes();

    // build a compact token that unlocks `expansion_1`
    let payload = serde_json::json!({ "dlcs": ["expansion_1"] });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let sig = signing_key.sign(&payload_bytes);
    let token = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload_bytes),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    );

    App::new()
        .add_plugins(DefaultPlugins)
        // insert the DlcManager directly for this example (equivalent to
        // using `DlcPlugin` in a real app)
        .insert_resource(DlcManager::new(verifying_key))
        .insert_resource(ExampleToken(token))
        .add_systems(Startup,(setup,apply_example_token))
        .add_systems(Update,spawn_dlc_on_unlock)
        .run();
}

#[derive(Resource)]
struct ExampleToken(String);

#[derive(Component)]
struct LockedDlc; // marker component — the entity represents locked DLC

// store the DlcHandle as part of a component so it's attached to an entity
#[derive(Component)]
struct AssetTag(DlcHandle<Image>);

fn setup(mut commands: Commands, asset_server: Res<AssetServer>) {
    // pretend the DLC texture is bundled with the game — we "preload" it by
    // creating a handle (file needn't exist for the example to compile):
    let dlc_texture: Handle<Image> = asset_server.load("textures/dlc_sprite.png");

    // create an entity that represents DLC content in the scene; it is
    // initially locked (has `LockedDlc`) and carries an `AssetTag` which
    // contains the preloaded asset handle wrapped in `DlcHandle`.
    let dlc_handle = DlcHandle::new(dlc_texture, "expansion_1");
    commands.spawn((LockedDlc, AssetTag(dlc_handle)));

    info!("spawned locked DLC entity — content is present but not yet used");
}

fn apply_example_token(token: Res<ExampleToken>, mut dlc: ResMut<DlcManager>) {
    match dlc.verify_and_unlock_token(&token.0) {
        Ok(list) => info!("unlocked DLCs: {:?}", list),
        Err(e) => warn!("failed to verify token: {e}")
    }
}

// When the DLC is unlocked we take the preloaded handle from `AssetTag` and
// spawn the real Sprite (demonstrating "unlocking" preloaded content).
fn spawn_dlc_on_unlock(
    dlc: Res<DlcManager>,
    query: Query<(Entity, &AssetTag), With<LockedDlc>>,
    mut commands: Commands,
) {
    for (entity, tag) in query.iter() {
        if tag.0.is_unlocked(&dlc) {
            // spawn the real asset into the world using the preloaded handle
            commands.spawn(Sprite { image: tag.0.handle.clone(), ..Default::default() });
            // remove the locked marker so we don't respawn repeatedly
            commands.entity(entity).remove::<LockedDlc>();
            info!("spawned unlocked DLC content for '{}'", tag.0.dlc_id);
        }
    }
}
