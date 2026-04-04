mod common;
use common::prelude::*;
use owo_colors::OwoColorize;
use secure_gate::RevealSecret;
use serde::Deserialize;

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
    let bytes = pack.decrypt_entry("note.txt").expect("decrypt");
    assert_eq!(&bytes, b"hello dlc");
}

#[test]
#[serial_test::serial]
fn dlcpack_entry_loads_through_asset_pipeline_both_paths() {
    use bevy::prelude::{AssetServer, Assets, Handle};
    use bevy_dlc::{DlcId, DlcPack, Product, pack_encrypted_pack};

    let mut t = TestAppBuilder::new("test_product", &["pipeline_dlc"])
        .with_default_plugins()
        .add_plugins(TextAssetPlugin::default())
        .build();

    let expected = b"hello through pipeline".to_vec();
    let item = bevy_dlc::PackItem::new("note.txt", expected.clone()).expect("pack item");
    let signed_license = t.signed_license();
    let encrypt_key = bevy_dlc::extract_encrypt_key_from_license(&signed_license)
        .expect("extract encrypt key from test license");
    let pack_bytes = pack_encrypted_pack(
        &DlcId::from("pipeline_dlc"),
        &[item],
        &Product::from("test_product"),
        &encrypt_key,
        bevy_dlc::DEFAULT_BLOCK_SIZE,
    )
    .expect("pack with pipeline entry");

    t.write_asset_file("pipeline_dlc.dlcpack", &pack_bytes);

    let direct_handle = t.load_asset_sync::<TextAsset>("pipeline_dlc.dlcpack#note.txt");

    let pack_handle = t.load_asset_sync::<DlcPack>("pipeline_dlc.dlcpack");
    let pack = t.get_pack(&pack_handle).clone();
    let entry = pack.find_entry("note.txt").expect("entry present in loaded pack");

    let asset_server = t.resource::<AssetServer>().clone();
    let found_handle: Handle<TextAsset> = asset_server.load(entry.path());
    t.wait_for_asset(&found_handle, None);

    let text_assets = t.resource::<Assets<TextAsset>>();
    let direct_asset = text_assets
        .get(&direct_handle)
        .expect("directly loaded text asset should be present");
    let found_asset = text_assets
        .get(&found_handle)
        .expect("entry-path loaded text asset should be present");

    assert_eq!(direct_asset.0, "hello through pipeline");
    assert_eq!(found_asset.0, "hello through pipeline");
}

#[derive(Debug, Deserialize, PartialEq)]
struct PackFlags {
    boss: bool,
    stage: u32,
}

#[test]
#[serial_test::serial]
fn dlcpack_exposes_typed_pack_metadata() {
    use bevy_dlc::{DlcId, DlcPack, Product, pack_encrypted_pack_with_metadata};

    let dlc_id = "meta";
    let mut t = TestAppBuilder::new("test_product", &[dlc_id])
        .with_default_plugins()
        .add_plugins(TextAssetPlugin::default())
        .build();

    let items = bevy_dlc::pack_items![
        "note.txt" => b"hello dlc".to_vec(),
    ];
    let metadata = bevy_dlc::PackMetadata::from([
        (
            "chapter".to_string(),
            serde_json::Value::String("intro".to_string()),
        ),
        (
            "flags".to_string(),
            serde_json::json!({ "boss": true, "stage": 2 }),
        ),
    ]);

    let signed_license = t.signed_license();
    let encrypt_key = bevy_dlc::extract_encrypt_key_from_license(&signed_license)
        .expect("extract encrypt key from test license");
    let pack_bytes = pack_encrypted_pack_with_metadata(
        &DlcId::from(dlc_id),
        &items,
        &Product::from("test_product"),
        &metadata,
        &encrypt_key,
        bevy_dlc::DEFAULT_BLOCK_SIZE,
    )
    .expect("pack with metadata");

    t.write_asset_file("meta.dlcpack", &pack_bytes);
    let handle = t.load_asset_sync::<DlcPack>("meta.dlcpack");

    let packs = t.resource::<bevy::prelude::Assets<DlcPack>>();
    let pack = packs.get(&handle).expect("pack loaded");

    assert!(pack.has_metadata("chapter"));
    assert_eq!(pack.metadata_keys().count(), 2);

    let chapter: Option<String> = pack
        .get_metadata("chapter")
        .expect("deserialize chapter metadata");
    assert_eq!(chapter.as_deref(), Some("intro"));

    let flags: Option<PackFlags> = pack
        .get_metadata("flags")
        .expect("deserialize flags metadata");
    assert_eq!(
        flags,
        Some(PackFlags {
            boss: true,
            stage: 2,
        })
    );

    let raw = pack
        .get_metadata_raw("flags")
        .expect("raw metadata should be available explicitly")
        .expect("raw metadata value should exist");
    assert_eq!(raw["stage"], serde_json::Value::from(2));

    let missing: Option<u32> = pack
        .get_metadata("missing")
        .expect("missing metadata should not error");
    assert_eq!(missing, None);
}

#[test]
#[serial_test::serial]
fn pack_executable_fails() {
    // use the running binary as a stand-in for a dangerous payload
    let exe = std::env::current_exe().expect("current exe");
    let data = std::fs::read(&exe).expect("read exe");
    let name = exe.file_name().and_then(|s| s.to_str()).unwrap_or("exe");

    // PackItem::new itself should reject executable payloads, so exercise that
    let err =
        bevy_dlc::PackItem::new(name, data).expect_err("PackItem::new should refuse executable");
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
        bevy_dlc::DEFAULT_BLOCK_SIZE,
    )
    .expect("pack_encrypted_pack");

    // write the pack into the app's asset folder and load it
    t.write_asset_file("other_dlc.dlcpack", &pack_bytes);
    let handle = t.load_asset_sync::<bevy_dlc::DlcPack>("other_dlc.dlcpack");

    // pack asset is present, but decryption should fail because key isn't in registry
    let packs = t.resource::<bevy::prelude::Assets<bevy_dlc::DlcPack>>();
    let pack = packs.get(&handle).expect("pack loaded");

    let res = pack.decrypt_entry("secret.txt");
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
    ctx.pack(product, dlc_id, Some(&items)).success();

    // now run the `check` command against the current directory – the CLI
    // should recursively discover `<product>.slicense`/`.pubkey` and succeed.
    ctx.run_args(&["check", ctx.path().to_str().unwrap_or("<unknown>")])
        .success();
}

#[test]
#[serial_test::serial]
fn cli_pack_accepts_metadata_entries() {
    let ctx = CliTestCtx::new();
    ctx.write_file("foo.txt", b"hello from CLI");

    let product = "cli_product";
    let dlc_id = "cli_meta";

    ctx.generate(product, &[dlc_id], None, false).success();

    ctx.run_args(&[
        "pack",
        product,
        dlc_id,
        "--signed-license",
        &format!("{}.slicense", product),
        "--pubkey",
        &format!("{}.pubkey", product),
        "--types",
        "txt=examples::TextAsset",
        "--metadata",
        "chapter=intro",
        "--metadata",
        r#"flags={"boss":true,"stage":3}"#,
        "--",
        "foo.txt",
    ])
    .success();

    let file = std::fs::File::open(ctx.pack_path(dlc_id)).expect("open generated pack");
    let signed_license = std::fs::read_to_string(ctx.path().join(format!("{}.slicense", product)))
        .expect("read generated license");
    let encrypt_key =
        bevy_dlc::extract_encrypt_key_from_license(&bevy_dlc::SignedLicense::from(signed_license))
            .expect("extract encrypt key from generated license");
    let parsed = bevy_dlc::parse_encrypted_pack_info(file, Some(&encrypt_key))
        .expect("parse generated pack");

    assert_eq!(
        parsed.metadata.get("chapter"),
        Some(&serde_json::Value::String("intro".to_string()))
    );
    assert_eq!(
        parsed.metadata["flags"]["boss"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        parsed.metadata["flags"]["stage"],
        serde_json::Value::from(3)
    );
}

#[test]
#[serial_test::serial]
fn cli_version_reports_pack_version() {
    let ctx = CliTestCtx::new();
    ctx.write_file("foo.txt", b"hello from CLI");

    let product = "cli_product";
    let dlc_id = "cli_version";

    ctx.generate(product, &[dlc_id], None, false).success();

    ctx.run_args(&[
        "pack",
        product,
        dlc_id,
        "--signed-license",
        &format!("{}.slicense", product),
        "--pubkey",
        &format!("{}.pubkey", product),
        "--types",
        "txt=examples::TextAsset",
        "--",
        "foo.txt",
    ])
    .success();

    ctx.run_args(&["version", ctx.pack_path(dlc_id).to_str().expect("pack path")])
        .success()
        .stdout(predicates::str::contains(format!("{} -> {} (pack v5)", ctx.pack_path(dlc_id).display(), dlc_id)));
}

#[test]
#[serial_test::serial]
fn cli_list_shows_metadata_and_entries() {
    let ctx = CliTestCtx::new();
    ctx.write_file("foo.txt", b"hello from CLI");

    let product = "cli_product";
    let dlc_id = "cli_list";

    ctx.generate(product, &[dlc_id], None, false).success();

    ctx.run_args(&[
        "pack",
        product,
        dlc_id,
        "--signed-license",
        &format!("{}.slicense", product),
        "--pubkey",
        &format!("{}.pubkey", product),
        "--types",
        "txt=examples::TextAsset",
        "--metadata",
        "chapter=intro",
        "--",
        "foo.txt",
    ])
    .success();

    ctx.list(ctx.pack_path(dlc_id))
        .success()
        .stdout(predicates::str::contains("metadata:"))
        .stdout(predicates::str::contains("encrypted (DLC key required to inspect)"))
        .stdout(predicates::str::contains("foo.txt"));
}

#[test]
#[serial_test::serial]
fn cli_find_locates_pack_by_dlc_id() {
    let ctx = CliTestCtx::new();
    ctx.write_file("assets/foo.txt", b"hello from CLI");

    let product = "cli_product";
    let dlc_id = "cli_find";

    ctx.generate(product, &[dlc_id], None, false).success();

    ctx.run_args(&[
        "pack",
        product,
        dlc_id,
        "--signed-license",
        &format!("{}.slicense", product),
        "--pubkey",
        &format!("{}.pubkey", product),
        "--types",
        "txt=examples::TextAsset",
        "-o",
        "nested/out",
        "--",
        "assets/foo.txt",
    ])
    .success();

    ctx.run_args(&["find", dlc_id, ctx.path().to_str().expect("temp path")])
        .success()
        .stdout(predicates::str::contains("Found .dlcpack at:"))
        .stdout(predicates::str::contains("cli_find.dlcpack"));
}

#[test]
#[serial_test::serial]
fn cli_aes_key_generates_usable_encryption_key() {
    fn strip_ansi(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '\u{1b}' {
                if matches!(chars.peek(), Some('[')) {
                    chars.next();
                    while let Some(next) = chars.next() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                    continue;
                }
            }
            out.push(ch);
        }

        out
    }

    let ctx = CliTestCtx::new();
    let dlc_id = "aes_cli_roundtrip";
    let product = "aes_product";
    let expected = b"hello from generated AES key".to_vec();

    let output = ctx.run_and_capture(&["aes-key"]);
    assert!(output.status.success(), "aes-key should succeed");
    let stdout = strip_ansi(&String::from_utf8(output.stdout).expect("utf8 stdout"));
    let line = stdout
        .lines()
        .find(|line| line.contains("AES KEY:"))
        .expect("aes key line");
    let key = line
        .split_whitespace()
        .last()
        .expect("printed key token");
    assert_eq!(key.len(), 32, "AES key should be 32 characters");
    assert!(key.is_ascii(), "AES key should contain printable ASCII characters");

    let key_bytes: [u8; 32] = key
        .as_bytes()
        .try_into()
        .expect("32-character AES key should map to 32 bytes");
    let encrypt_key = bevy_dlc::EncryptionKey::new(key_bytes);

    let item = bevy_dlc::PackItem::new("note.txt", expected.clone()).expect("pack item");
    let pack_bytes = bevy_dlc::pack_encrypted_pack(
        &bevy_dlc::DlcId::from(dlc_id),
        &[item],
        &bevy_dlc::Product::from(product),
        &encrypt_key,
        bevy_dlc::DEFAULT_BLOCK_SIZE,
    )
    .expect("pack with CLI-generated AES key");

    let mut t = TestAppBuilder::new(product, &[])
        .with_default_plugins()
        .add_plugins(TextAssetPlugin::default())
        .build();

    bevy_dlc::encrypt_key_registry::remove(dlc_id);
    bevy_dlc::register_encryption_key(
        dlc_id,
        encrypt_key.with_secret(|kb| bevy_dlc::EncryptionKey::new(*kb)),
    );
    t.write_asset_file("aes_cli_roundtrip.dlcpack", &pack_bytes);

    let handle = t.load_asset_sync::<bevy_dlc::DlcPack>("aes_cli_roundtrip.dlcpack");
    let packs = t.resource::<bevy::prelude::Assets<bevy_dlc::DlcPack>>();
    let pack = packs.get(&handle).expect("pack loaded");

    let decrypted = pack.decrypt_entry("note.txt").expect("decrypt packed entry");
    assert_eq!(decrypted, expected);

    bevy_dlc::encrypt_key_registry::remove(dlc_id);
}

#[test]
#[serial_test::serial]
fn cli_pack_accepts_positional_product_value() {
    let ctx = CliTestCtx::new();
    ctx.write_file("foo.txt", b"hello from CLI");

    let product = "cli_product";
    let dlc_id = "cli_positional_product";

    ctx.generate(product, &[dlc_id], None, false).success();

    ctx.run_args(&[
        "pack",
        product,
        dlc_id,
        "--signed-license",
        &format!("{}.slicense", product),
        "--pubkey",
        &format!("{}.pubkey", product),
        "--types",
        "txt=examples::TextAsset",
        "--",
        "foo.txt",
    ])
    .success();

    let file = std::fs::File::open(ctx.pack_path(dlc_id)).expect("open generated pack");
    let (parsed_product, parsed_dlc_id, _version, entries, _blocks) =
        bevy_dlc::parse_encrypted_pack(file).expect("parse generated pack");
    assert_eq!(parsed_product.as_ref(), product);
    assert_eq!(parsed_dlc_id.as_str(), dlc_id);
    assert!(entries.iter().any(|(path, _)| path == "foo.txt"));
}
