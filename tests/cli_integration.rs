#[allow(deprecated)]
use assert_cmd::cargo::cargo_bin;
use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn generate_pack_validate_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let td = TempDir::new()?;
    let prod = "itest";
    let dlc_id = "expansion_itest";

    // create an input directory with one file
    let src_dir = td.path().join("src");
    fs::create_dir_all(&src_dir)?;
    fs::write(src_dir.join("hello.txt"), b"hello dlc")?;

    // 1) generate signed license + pubkey for product in the temp dir
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("generate")
        .arg("--product")
        .arg(prod)
        .arg(dlc_id)
        .assert()
        .success()
        .stdout(predicates::str::contains("Wrote signed license"));

    // ensure files were created
    assert!(td.path().join(format!("{}.slicense", prod)).exists());
    assert!(td.path().join(format!("{}.pubkey", prod)).exists());

    // 2) pack the directory into a .dlcpack using the generated product files
    let out_pack = td.path().join("expansion_itest.dlcpack");
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("pack")
        .arg("--product")
        .arg(prod)
        .arg(src_dir)
        .arg(dlc_id)
        .arg("--pack")
        .arg("--types")
        .arg("txt=bevy_dlc::example_util::TextAsset")
        .arg("-o")
        .arg(&out_pack)
        .assert()
        .success();

    assert!(out_pack.exists());

    // 3) validate the produced pack using the product files (should decrypt)
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("validate")
        .arg("--product")
        .arg(prod)
        .arg(&out_pack)
        .assert()
        .success()
        .stdout(predicates::str::contains("SUCCESS"));

    Ok(())
}

#[test]
fn generate_incremental_dlc_releases_merge_ids() -> Result<(), Box<dyn std::error::Error>> {
    let td = TempDir::new()?;
    let prod = "incremental_test";

    // 1) Generate initial license with first DLC
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("generate")
        .arg("--product")
        .arg(prod)
        .arg("expansion_1")
        .assert()
        .success()
        .stdout(predicates::str::contains("Wrote signed license"))
        .stdout(predicates::str::contains("expansion_1"));

    let license_path = td.path().join(format!("{}.slicense", prod));
    let pubkey_path = td.path().join(format!("{}.pubkey", prod));
    assert!(license_path.exists());
    assert!(pubkey_path.exists());

    let first_license = fs::read_to_string(&license_path)?;
    let first_pubkey = fs::read_to_string(&pubkey_path)?;

    // 2) Generate again with a new DLC ID - should merge with existing license
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("generate")
        .arg("--product")
        .arg(prod)
        .arg("expansion_2")
        .assert()
        .success()
        .stdout(predicates::str::contains("Wrote signed license"))
        .stdout(predicates::str::contains("expansion_1"))
        .stdout(predicates::str::contains("expansion_2"));

    let second_license = fs::read_to_string(&license_path)?;
    let second_pubkey = fs::read_to_string(&pubkey_path)?;

    // License file should be different (new signature), but pubkey should differ
    // due to new random keygen
    assert_ne!(first_license, second_license);
    assert_ne!(first_pubkey, second_pubkey);

    // 3) Generate with both IDs explicitly - should deduplicate
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("generate")
        .arg("--product")
        .arg(prod)
        .arg("expansion_1")
        .arg("expansion_2")
        .arg("expansion_3")
        .assert()
        .success()
        .stdout(predicates::str::contains("Wrote signed license"))
        .stdout(predicates::str::contains("expansion_1"))
        .stdout(predicates::str::contains("expansion_2"))
        .stdout(predicates::str::contains("expansion_3"));

    let third_license = fs::read_to_string(&license_path)?;
    assert_ne!(second_license, third_license);

    Ok(())
}

#[test]
fn generate_write_license_and_pubkey_files() -> Result<(), Box<dyn std::error::Error>> {
    let td = TempDir::new()?;
    let prod = "file_write_test";

    // Generate license and pubkey files
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("generate")
        .arg("--product")
        .arg(prod)
        .arg("test_dlc")
        .assert()
        .success();

    let license_path = td.path().join(format!("{}.slicense", prod));
    let pubkey_path = td.path().join(format!("{}.pubkey", prod));

    // Verify both files exist
    assert!(license_path.exists(), "License file should be created");
    assert!(pubkey_path.exists(), "Public key file should be created");

    // Verify license file is not empty and contains valid token format
    let license_content = fs::read_to_string(&license_path)?;
    assert!(!license_content.is_empty(), "License file should not be empty");
    // Token format is payload.signature with base64url encoding
    let parts: Vec<&str> = license_content.trim().split('.').collect();
    assert_eq!(parts.len(), 2, "License should be in compact token format: payload.signature");

    // Verify pubkey file is not empty and is base64url encoded
    let pubkey_content = fs::read_to_string(&pubkey_path)?;
    assert!(!pubkey_content.is_empty(), "Public key file should not be empty");
    // Base64url should only contain [A-Za-z0-9_-]
    assert!(
        pubkey_content.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c.is_whitespace()),
        "Public key should be base64url encoded"
    );

    Ok(())
}

#[test]
fn generate_validates_output_format() -> Result<(), Box<dyn std::error::Error>> {
    let td = TempDir::new()?;
    let prod = "format_test";

    // Generate with multiple DLC IDs
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("generate")
        .arg("--product")
        .arg(prod)
        .arg("dlc_a")
        .arg("dlc_b")
        .arg("dlc_c")
        .assert()
        .success()
        .stdout(predicates::str::contains(&format!("{}.slicense", prod)))
        .stdout(predicates::str::contains(&format!("{}.pubkey", prod)))
        // Output should list all the DLC IDs
        .stdout(predicates::str::contains("dlc_a"))
        .stdout(predicates::str::contains("dlc_b"))
        .stdout(predicates::str::contains("dlc_c"));

    Ok(())
}