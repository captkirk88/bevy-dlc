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