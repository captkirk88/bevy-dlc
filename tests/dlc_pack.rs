mod common;
use common::prelude::*;
use owo_colors::OwoColorize;

#[test]
#[serial_test::serial]
fn dlcpack_runtime_loads_and_decrypts_when_unlocked() {
    use bevy_dlc::DlcPack;

    // TestApp contains a signed license that unlocks `dlcA`
    let mut t = TestAppBuilder::new("test_product", &["dlcA"])
        .with_default_plugins()
        .add_plugins(TextAssetPlugin::default())
        .build();

    // Prepare a single plaintext entry for the pack
    let items = bevy_dlc::pack_items![
        "note.txt" => b"hello dlc".to_vec(),
    ];

    // create + write + load the pack via the helper
    let handle = t.pack_and_load("dlcA", &items);

    // asset should be present in Assets<DlcPack>
    let packs = t.resource::<bevy::prelude::Assets<DlcPack>>();
    let pack = packs.get(&handle).expect("pack loaded");
    assert_eq!(pack.id().0, "dlcA");

    // decrypt the entry using the pack API
    let bytes = pack.decrypt_entry_bytes("note.txt").expect("decrypt");
    assert_eq!(&bytes, b"hello dlc");
}

#[test]
#[serial_test::serial]
fn pack_executable_fails() {

    // use the running binary as a stand-in for a dangerous payload
    let exe = std::env::current_exe().expect("current exe");
    let data = std::fs::read(&exe).expect("read exe");
    let name = exe
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("exe");

    // PackItem::new itself should reject executable payloads, so exercise that
    let err = bevy_dlc::PackItem::new(name, data).expect_err("PackItem::new should refuse executable");
    let msg = err.to_string();
    assert!(
        msg.contains("executable payload"),
        "unexpected error: {}",
        msg
    );

    // no need to call pack_encrypted_pack at all; the item can't even be created.
}

#[test]
#[serial_test::serial]
fn dlcpack_runtime_loads_but_locked_without_key() {
    use bevy_dlc::{DlcId, DlcKey, pack_encrypted_pack};
    use common::app::TestApp;

    // App WITHOUT the matching license/key for `other_dlc` (no unlock)
    let mut t = TestApp::new("test_product", &[]);

    // create a pack signed/encrypted with a different random key (not present in `t`)
    let pack_key = DlcKey::generate_random();
    let product = bevy_dlc::Product::from("test_product");
    let signed = pack_key
        .create_signed_license(&["other_dlc"], product.clone())
        .expect("signed");
    let key_bytes = bevy_dlc::extract_encrypt_key_from_license(&signed).expect("key");
    let enc_key = bevy_dlc::EncryptionKey::from(key_bytes);

    let items = bevy_dlc::pack_items![
        "secret.txt" => b"top secret".to_vec(); ext="txt",
    ];
    let pack_bytes = pack_encrypted_pack(
        &DlcId::from("other_dlc"),
        &items,
        &product,
        &enc_key,
    )
    .expect("pack_encrypted_pack");

    // write the pack into the app's asset folder and load it
    t.write_asset_file("other_dlc.dlcpack", &pack_bytes);
    let handle = t.load_asset_sync::<bevy_dlc::DlcPack>("other_dlc.dlcpack");

    // pack asset is present, but decryption should fail because key isn't in registry
    let packs = t.resource::<bevy::prelude::Assets<bevy_dlc::DlcPack>>();
    let pack = packs.get(&handle).expect("pack loaded");

    let res = pack.decrypt_entry_bytes("secret.txt");
    eprintln!("DlcLocked error (expected): {}", format!("{res:?}").red());
    assert!(res.is_err(), "expected DlcLocked or DecryptionFailed");
}


#[test]
#[serial_test::serial]
fn cli_check_command_finds_license_and_succeeds() {
    // create a temporary CLI test context
    let ctx = CliTestCtx::new();

    // write a trivial asset into the workspace
    ctx.write_file("foo.txt", b"hello from CLI");

    let product = "cli_product";
    let dlc_id = "cli_dlc";

    // to keep the encrypt key consistent, first generate the license files
    // using the CLI helper and then build the pack via the library so it uses
    // the same key that is embedded in the license.
    ctx.generate(product, &[dlc_id], None, false).success();

    // pack a single file (foo.txt) using the library with the derived key
    let items = bevy_dlc::pack_items![
        "foo.txt" => b"hello from CLI".to_vec(); ext="txt"; type="examples::TextAsset",
    ];

    // create + write the pack into the tempdir
    ctx.pack(product,dlc_id, Some(&items)).success();

    // now run the `check` command against the current directory – the CLI
    // should recursively discover `<product>.slicense`/`.pubkey` and succeed.
    ctx.run_args(&["check", ctx.path().to_str().unwrap_or("<unknown>")]).success();
}
