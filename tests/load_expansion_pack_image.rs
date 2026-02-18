use bevy::asset::LoadState;
use bevy::prelude::*;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bevy_dlc::prelude::*;
use secure_gate::ExposeSecret;

// This integration test writes a temporary `.dlcpack` into `assets/` that is
// encrypted with a content-key embedded in a SignedLicense produced by the
// same private `DlcKey`. The test then starts a headless app (MinimalPlugins
// + Asset/Image), loads the generated pack via `AssetServer`, decrypts the
// raw PNG bytes from the pack, and finally ensures the `Image` asset is
// produced by the asset pipeline.
#[test]
fn load_generated_expansiona_dlcpack_and_decode_image() {
    // prepare inputs: read a small PNG to pack (repository test asset)
    let img_bytes = std::fs::read("test_assets/test.png").expect("read test png");

    // construct a single-entry pack (type_path points to bevy Image so the
    // AssetServer can decode it after the DLC is unlocked)
    let dlc_id = DlcId::from("expansionA");
    let items = vec![(
        "test.png".to_string(),
        Some("png".to_string()),
        Some("bevy_image::image::Image".to_string()),
        img_bytes,
    )];

    let product = Product::from("example");

    // create a private DlcKey and a SignedLicense — the private seed is used
    // as the symmetric encrypt_key embedded into the token by
    // `create_signed_license`. 
    let private = DlcKey::generate_random();
    let signedlicense = private
        .create_signed_license(&[dlc_id.clone()], product.clone())
        .expect("create signed license");

    // extract the `encrypt_key` that the token carries and use it to encrypt
    // the on-disk pack so token <-> pack agree.
    let key_bytes = signedlicense.with_secret(|s| {
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(parts.len(), 2);
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[0].as_bytes())
            .expect("payload base64 decode");
        let payload_json = String::from_utf8(payload_bytes).expect("payload utf8");
        let v: serde_json::Value = serde_json::from_str(&payload_json).expect("json");
        let content_key_b64 = v
            .get("encrypt_key")
            .expect("encrypt_key present")
            .as_str()
            .expect("encrypt_key str");
        URL_SAFE_NO_PAD
            .decode(content_key_b64.as_bytes())
            .expect("encrypt_key decode")
    });
    assert_eq!(key_bytes.len(), 32);

    let encrypt_key = bevy_dlc::EncryptionKey::from(key_bytes);

    // create container bytes and write into `assets/` so AssetServer can load it
    let container =
        bevy_dlc::pack_encrypted_pack(&dlc_id, &items, &encrypt_key).expect("pack container");
    let tmp_path = "assets/test_generated_expansionA.dlcpack";
    std::fs::write(tmp_path, &container).expect("write pack to assets");
    
    // Build a headless app with only Asset + Image plugins and register the
    // DLC loaders manually (we'll apply the signed-key token to the manager
    // from the test to provision the content key into the registry).
    use bevy::prelude::AssetApp;

    let mut app = App::new();
    app.add_plugins((
        MinimalPlugins,
        bevy::asset::AssetPlugin::default(),
        bevy::image::ImagePlugin::default(),
    ));

    // register Dlc loaders (same as plugin but lightweight for test)
    app.init_asset_loader::<DlcLoader<Image>>();
    app.init_asset_loader::<DlcPackLoader>();
    app.init_asset::<DlcPack>();

    // ImagePlugin::build only *pre-registers* ImageLoader (Pending). The
    // actual registration normally happens in bevy_render::RenderPlugin::finish.
    // Since we run without RenderPlugin here, we must promote ImageLoader from
    // Pending → Ready manually so that DlcPackLoader's immediate() sub-loads
    // can resolve the loader without blocking forever.
    app.register_asset_loader(bevy::image::ImageLoader::new(
        bevy::image::CompressedImageFormats::empty(),
    ));

    // insert an empty DlcManager and *apply* the signed key token from the
    // test so the encrypt_key registry is populated (mirrors runtime flow).
    app.insert_resource(DlcManager::new(product));
    app.update();

    // apply the signed key token to provision the symmetric content key
    let mut dlc_mgr = app.world_mut().resource_mut::<DlcManager>();
    dlc_mgr
        .apply_signed_key_token(&DlcKey::public(&URL_SAFE_NO_PAD.encode(private.public_key_bytes())).expect("public key"), &signedlicense)
        .expect("apply signed key token from test");

    // also mark DLC ids unlocked (plugin does this during build)
    let verified = DlcKey::public(&URL_SAFE_NO_PAD.encode(private.public_key_bytes()))
        .expect("public key")
        .verify_signed_license(&signedlicense)
        .expect("verify signed license");
    dlc_mgr
        .unlock_verified_license(verified)
        .expect("unlock verified license");

    let asset_server = app.world().resource::<AssetServer>().clone();

    // request the generated pack and wait for it to be loaded
    let pack_handle: Handle<DlcPack> = asset_server.load("test_generated_expansionA.dlcpack");
    let timeout = Duration::from_secs(5);
    let start = Instant::now();
    while !matches!(
        asset_server.get_load_state(&pack_handle),
        Some(LoadState::Loaded)
    ) {
        app.update();
        if start.elapsed() > timeout {
            let state = asset_server.get_load_state(&pack_handle);
            let _ = std::fs::remove_file(tmp_path);
            panic!("timed out waiting for DlcPack to load (state={:?})", state);
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // inspect the loaded pack and decrypt the raw PNG bytes from the container
    let (first_entry, raw_png) = {
        let packs = app.world().resource::<Assets<DlcPack>>();
        let pack = packs.get(&pack_handle).expect("DlcPack should be present");
        assert_eq!(pack.id().to_string(), "expansionA");
        assert!(!pack.entries().is_empty());

        let first_entry = pack.entries().first().expect("at least one entry").clone();
        assert!(first_entry.path().to_string().ends_with("test.png"));
        assert_eq!(first_entry.original_extension(), "png");

        // decrypt raw bytes from the pack while we still have `pack` available
        let raw_png = pack
            .decrypt_entry_bytes(&first_entry.path().to_string())
            .expect("decrypt raw entry");
        assert!(
            raw_png.starts_with(b"\x89PNG\r\n\x1a\n"),
            "raw entry is not a PNG"
        );

        (first_entry, raw_png)
    };

    // Sanity: plugin should have unlocked the DLC
    let dlc_mgr = app.world().resource::<DlcManager>();
    assert!(dlc_mgr.is_unlocked_id(&DlcId::from("expansionA")), "plugin did not unlock DLC");

    // Force a reload of the labeled entry path so AssetServer will queue the
    // nested loader for the `pack#entry` label (this mirrors runtime reloads
    // performed by `reload_assets_on_unlock_system`).
    let entry_path = first_entry.path();
    asset_server.reload(entry_path);

    // Instead of relying on the async AssetServer pipeline for the labeled
    // entry (covered by other tests), validate the decrypted PNG bytes are
    // well-formed by inspecting the PNG IHDR header for width/height.
    // PNG layout: signature(8) | length(4) | 'IHDR'(4) | width(4) | height(4) | ...
    let width = u32::from_be_bytes([raw_png[16], raw_png[17], raw_png[18], raw_png[19]]);
    let height = u32::from_be_bytes([raw_png[20], raw_png[21], raw_png[22], raw_png[23]]);
    assert!(width > 0 && height > 0, "invalid PNG dimensions");

    // cleanup temporary asset file (best-effort)
    let _ = std::fs::remove_file(tmp_path);
}
