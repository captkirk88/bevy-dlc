#[allow(unused)]
mod common;
use common::prelude::*;
#[allow(unused)]
use bevy::prelude::*;

#[test]
#[serial_test::serial]
fn cli_pack_with_common_json_feature() {
    let ctx = CliTestCtx::new();

    // a tiny JSON file — we still pass an explicit TypePath override so the
    // CLI doesn't need to auto-resolve a user type during the pack step.
    ctx.write_file("src/level.json", b"{ \"positions\": [[0.0, 0.0, 0.0]] }");

    ctx.pack("test_product", "json_dlc", Some("json=my_crate::Level"))
        .success();

    assert!(ctx.pack_path("json_dlc").exists());

    // list should show the DLC id
    ctx.list(ctx.pack_path("json_dlc")).success().stdout(predicates::str::contains("json_dlc"));
}

#[cfg(feature = "common_json")]
#[test]
#[serial_test::serial]
fn testapp_can_use_dlcpack_with_json() {
    use bevy_common_assets::json::JsonAssetPlugin;

    const EXT: &str = "json"; // use a fake extension to force the non-extension-based loading path
    let file = format!("level.{}", EXT);
    const DLC_ID: &str = "json_dlc";
    // content must match TextAsset's expected `String` type (i.e. a JSON string)
    let json_data = b"\"hello world\"";

    let builder = TestAppBuilder::new("test_product", &[DLC_ID])
        .with_default_plugins()
        .add_plugins(JsonAssetPlugin::<TextAsset>::new(&[EXT]))
        .register_dlc_type::<TextAsset>();
    let mut t = builder.build();

    // write a JSON file containing a simple string so the TextAsset loader succeeds
    let path = t.write_asset_file(file.clone(), json_data);
    let dlc_pack = t.pack_file_and_load(DLC_ID, &path, Some(EXT));

    // asset should be present in Assets<DlcPack>
    let pack = t.get_pack(&dlc_pack);
    assert_eq!(pack.id().0, DLC_ID);
    assert!(
        pack.entries()
            .iter()
            .any(|e| {
                // use the AssetPath's string representation which includes
                // the `#entry` suffix
                let path_str = e.path().to_string();
                path_str.contains(file.as_str()) && e.original_extension() == EXT
            }),
        "unexpected pack entries: {:#?}",
        pack.entries()
    );

    // finally, confirm the JSON asset can actually be loaded via the registered
    // JsonAssetPlugin/`TextAsset` loader — this proves DlcPackLoader registered
    // the sub‑asset path for us.
    let text_handle = pack.load::<TextAsset>(t.resource::<AssetServer>(),file.as_str());
    assert!(text_handle.is_some(), "asset handle should be returned from pack.load");
    
    // wait for the asset to load asynchronously
    let handle = text_handle.unwrap();
    t.wait_for_asset(&handle);
    
    let texts = t.resource::<Assets<TextAsset>>();
    assert!(texts.get(&handle).is_some(), "json asset not loaded");
}
