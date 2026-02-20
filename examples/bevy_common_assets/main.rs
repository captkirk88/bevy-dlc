//! Example of loading `bevy-common-assets` from a DLC pack with `bevy-dlc`.
//! This example assumes you have already generated a signed license and DLC pack using the CLI tool:
//! ```bash
//! bevy-dlc generate --product example -o keys/
//! ```
use bevy::prelude::*;
use bevy_common_assets::json::JsonAssetPlugin;
use bevy_dlc::DlcPack;
use bevy_dlc::prelude::*;

#[path = "../mod.rs"]
mod examples;
use examples::TextAsset;

// You must generate `example.slicense` and `example.pubkey` by `bevy-dlc generate example`

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
    let signedlicense = SignedLicense::from(get_example_license());

    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(DlcPlugin::new(
            dlc_key,
            signedlicense,
        ))
        .add_plugins(JsonAssetPlugin::<TextAsset>::new(&["json"]))
        .register_dlc_type::<TextAsset>()
        .add_systems(Startup, startup)
        .add_systems(Update, show_dlc_content.run_if(is_dlc_loaded("dlcA")))
        .run()
}

#[allow(unused)]
#[derive(Component)]
struct LoadedPack(Handle<DlcPack>);

#[derive(Component)]
struct LoadedText(Handle<TextAsset>);

fn startup(asset_server: Res<AssetServer>, mut commands: Commands) {
    let handle = asset_server.load::<DlcPack>("dlcA.dlcpack");
    commands.spawn((Camera2d, LoadedPack(handle)));
}

fn show_dlc_content(
    dlc_packs: Res<Assets<DlcPack>>,
    asset_server: Res<AssetServer>,
    mut commands: Commands,
    query: Query<(Entity, &LoadedPack)>,
) {
    for (entity, loaded) in query.iter() {
        match dlc_packs.get(&loaded.0) {
            Some(pack) => {
                for entry in pack.find_by_type::<Image>() {
                    let img: Handle<Image> = asset_server.load(entry.path());
                    commands.spawn(Sprite::from_image(img));
                }

                for entry in pack.find_by_type::<TextAsset>() {
                    let text_asset: Handle<TextAsset> = asset_server.load(entry.path());
                    commands.spawn(LoadedText(text_asset));
                }
                // prevent re-running/spawning again
                commands.entity(entity).remove::<LoadedPack>();
            }
            None => {
                debug!("DlcPack asset not ready yet for handle: {:?}", loaded.0);
                return;
            }
        }
    }
}

fn display_loaded_text(
    text_assets: Res<Assets<TextAsset>>,
    mut commands: Commands,
    query: Query<(Entity, &LoadedText)>,
) {
    for (entity, loaded) in query.iter() {
        match text_assets.get(&loaded.0) {
            Some(text_asset) => {
                info!("Loaded TextAsset from DLC: {}", text_asset.0);
                // prevent re-printing
                commands.entity(entity).remove::<LoadedText>();

                let mut ent = commands.entity(entity);
                ent.insert((
                    Text::from(text_asset.0.clone()),
                    Node {
                        position_type: PositionType::Absolute,
                        top: px(5),
                        left: px(15),
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