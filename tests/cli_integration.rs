#[allow(deprecated)]
use assert_cmd::cargo::cargo_bin;
use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// This test runs the `pack` CLI command to create a .dlcpack from a test directory, then runs `list` to verify the pack was created and contains the expected DLC ID.
#[test]
fn pack_unpack_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let td = TempDir::new()?;
    let prod = "test_product";
    let dlc_id = "test_dlc";

    // Create input file
    let src_dir = td.path().join("src");
    fs::create_dir_all(&src_dir)?;
    fs::write(src_dir.join("hello.txt"), b"hello dlc")?;

    // Pack the directory into a .dlcpack (explicit file path)
    let out_pack = td.path().join("test_dlc.dlcpack");
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("pack")
        .arg("--product")
        .arg(prod)
        .arg(dlc_id)
        .arg("--types")
        .arg("txt=some_crate::SomeType")
        .arg("-o")
        .arg(&out_pack)
        .arg("--")
        .arg(&src_dir)
        .assert()
        .success();

    assert!(out_pack.exists());

    // Pack with a no-extension -o value -> treated as directory
    let out_dir_no_ext = td.path().join("out_no_ext");
    assert!(!out_dir_no_ext.exists());
    Command::new(cargo_bin!("bevy-dlc"))
        .current_dir(td.path())
        .arg("pack")
        .arg("--product")
        .arg(prod)
        .arg("other_dlc")
        .arg("--types")
        .arg("txt=some_crate::SomeType")
        .arg("-o")
        .arg(&out_dir_no_ext)
        .arg("--")
        .arg(&src_dir)
        .assert()
        .success();

    let expected = out_dir_no_ext.join("other_dlc.dlcpack");
    assert!(expected.exists());

    // List the pack
    Command::new(cargo_bin!("bevy-dlc"))
        .arg("list")
        .arg(&out_pack)
        .assert()
        .success()
        .stdout(predicates::str::contains(dlc_id));

    Ok(())
}