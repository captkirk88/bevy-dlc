//! Example of loading DLC packs with `bevy-dlc`.
//! This example assumes you have already generated a signed license and DLC pack using the CLI tool:
//! ```bash
//! bevy-dlc generate --product example -o keys/
//! ```
//! You will see warnings in the console about missing asset loaders for the DLC pack entries until you register them with `app.register_dlc_type::<T>()` (see `startup` system below). This is expected and intentional to demonstrate how the plugin handles unsupported asset types in DLC packs, and to show how you can add support for them by registering loaders.
use bevy::prelude::*;
use bevy_dlc::DlcPack;
use bevy_dlc::prelude::*;

// You must generate `example.slicense` and `example.pubkey` by `bevy-dlc generate example`

#[derive(Asset, Reflect)]
struct TextAsset(String);

fn main() -> AppExit {
    // DO NOT USE ABCD... as your choice of secure key. This is just a placeholder for the example.
    // This is the RECOMMENDED approach:
    // Create cryptographically secure license key that can't be decrypted from your compiled binary (game).
    secure::include_secure_str_aes!("example.slicense", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "example_license");

    let dlc_key = DlcKey::public(include_str!("../../example.pubkey")).expect("invalid example pubkey");
    let signedlicense = SignedLicense::from(get_example_license());

    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(DlcPlugin::new(
            Product::from("example"),
            dlc_key,
            signedlicense,
        ))
        .init_asset::<TextAsset>()
        .register_dlc_type::<TextAsset>()
        .add_systems(Startup, startup)
        .add_systems(
            Update,
            show_dlc_content.run_if(is_dlc_loaded("expansionA")),
        )
        .run()
}

#[allow(unused)]
#[derive(Component)]
struct LoadedPack(Handle<DlcPack>);

fn startup(asset_server: Res<AssetServer>, mut commands: Commands) {
    let handle = asset_server.load::<DlcPack>("expansionA.dlcpack");
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
                for entry in pack.entries() {
                    let ext = entry.original_extension().as_str();
                    match ext {
                        "png" | "jpg" | "jpeg" => {
                            info!("Spawning sprite for DLC entry: {}", entry.path());
                            let img: Handle<Image> = asset_server.load(entry.path());
                            commands.spawn(Sprite::from_image(img));
                        }
                        // Showing example of decrypting a text entry from the DLC pack and printing its contents.
                        "txt" => {
                            info!("Text DLC entry found: {}", entry.path());
                            match entry.decrypt_bytes(pack) {
                                Ok(bytes) => match std::str::from_utf8(&bytes) {
                                    Ok(s) => info!("TextAsset contents: {}", s),
                                    Err(_) => info!("TextAsset (binary) {} bytes", bytes.len()),
                                },
                                Err(e) => warn!("failed to decrypt text entry '{}': {:?}", entry.path(), e),
                            }
                        }
                        _ => {
                            // Fallback: we don't know how to visualise this entry in the example — just log it.
                            info!("Skipping unsupported DLC entry (ext={}) {}", ext, entry.path());
                        }
                    }
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
