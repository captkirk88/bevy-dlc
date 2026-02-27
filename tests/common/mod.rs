//! Shared CLI test helpers for `bevy-dlc` integration tests.
//!
//! Provides helpers to run the `bevy-dlc` binary, read/parse generated
//! `.dlcpack` files, and create a `Bevy App` preconfigured with `DlcPlugin`.

pub mod app;

use assert_cmd::{Command, pkg_name};
use bevy::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use bevy_dlc::{EncryptedAsset, parse_encrypted_pack};

#[allow(unused)]
pub mod prelude {
    pub use super::{CliTestCtx, TextAsset, TextAssetLoader, TextAssetPlugin, app::*};
}

/// Lightweight test context to run `bevy-dlc` CLI commands and manage a
/// temporary working directory.
#[derive(Debug)]
pub struct CliTestCtx {
    pub td: TempDir,
}

#[allow(unused)]
impl CliTestCtx {
    /// Create a new temp-dir backed test context
    pub fn new() -> Self {
        CliTestCtx {
            td: TempDir::new().expect("tempdir"),
        }
    }

    /// Path to the temporary directory (kept for convenience)
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        self.td.path()
    }

    /// Write a file (creates parent directories as needed)
    pub fn write_file<P: AsRef<Path>>(&self, rel: P, data: &[u8]) {
        let p = self.td.path().join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        std::fs::write(&p, data).expect("write file");
    }

    /// Create a configured `assert_cmd::Command` pointing at the `bevy-dlc`
    /// binary and using the test tempdir as CWD.
    #[allow(deprecated)]
    fn base_cmd(&self) -> Command {
        // Using `Command::cargo_bin` here is convenient in tests; silence the
        // deprecation warning to keep CI output clean. See assert_cmd docs for
        // alternatives when necessary.
        let mut cmd = Command::cargo_bin(pkg_name!()).expect("find binary");
        cmd.current_dir(self.td.path());
        cmd
    }

    /// Run an arbitrary CLI invocation and return the `Assert` for fluent
    /// assertions.
    pub fn run_args<S: AsRef<str>>(&self, args: &[S]) -> assert_cmd::assert::Assert {
        let mut cmd = self.base_cmd();
        for a in args {
            cmd.arg(a.as_ref());
        }
        cmd.assert()
    }

    /// Run an arbitrary CLI invocation and capture stdout/stderr.
    pub fn run_and_capture<S: AsRef<str>>(&self, args: &[S]) -> std::process::Output {
        let mut cmd = self.base_cmd();
        for a in args {
            cmd.arg(a.as_ref());
        }
        cmd.output().expect("command output")
    }

    /// Run `bevy-dlc pack` against the supplied input path (file or dir).
    /// When `type_override` is `Some` it is appended as `--types <override>`.
    pub fn pack(
        &self,
        product: &str,
        dlc_id: &str,
        type_override: Option<&str>,
    ) -> assert_cmd::assert::Assert {
        let out_pack = self.pack_path(dlc_id);

        let mut cmd = self.base_cmd();
        cmd.arg("pack")
            .arg("--product")
            .arg(product)
            .arg(dlc_id)
            .arg("-o")
            .arg(&out_pack);

        if let Some(t) = type_override {
            cmd.arg("--types").arg(t);
        }

        // pack the whole tempdir by default
        cmd.arg("--").arg(self.td.path());
        cmd.assert()
    }

    /// Pack and return parsed `.dlcpack` metadata using `parse_encrypted_pack`.
    pub fn pack_and_parse(
        &self,
        product: &str,
        dlc_id: &str,
        type_override: Option<&str>,
    ) -> Result<
        (
            bevy_dlc::Product,
            bevy_dlc::DlcId,
            usize,
            Vec<(String, EncryptedAsset)>,
            Vec<bevy_dlc::BlockMetadata>,
        ),
        Box<dyn std::error::Error>,
    > {
        self.pack(product, dlc_id, type_override).success();
        let file = std::fs::File::open(self.pack_path(dlc_id))?;
        let parsed = parse_encrypted_pack(&file)?;
        Ok(parsed)
    }

    /// Run `bevy-dlc list <pack>` and return the assertion handle
    pub fn list<P: AsRef<Path>>(&self, pack: P) -> assert_cmd::assert::Assert {
        let mut cmd = self.base_cmd();
        cmd.arg("list").arg(pack.as_ref());
        cmd.assert()
    }

    /// Run `bevy-dlc generate <product> <dlcs...>`
    pub fn generate(
        &self,
        product: &str,
        dlcs: &[&str],
        out_dir: Option<&Path>,
        force: bool,
    ) -> assert_cmd::assert::Assert {
        let mut cmd = self.base_cmd();
        cmd.arg("generate").arg(product);
        for d in dlcs {
            cmd.arg(d);
        }
        if let Some(o) = out_dir {
            cmd.arg("--out-dir").arg(o);
        }
        if force {
            cmd.arg("--force");
        }
        cmd.assert()
    }

    /// Run `bevy-dlc validate <pack>` with optional product/license/pubkey args
    pub fn validate(
        &self,
        pack: &Path,
        product: Option<&str>,
        signed_license: Option<&str>,
        pubkey: Option<&str>,
    ) -> assert_cmd::assert::Assert {
        let mut cmd = self.base_cmd();
        cmd.arg("validate").arg(pack);
        if let Some(p) = product {
            cmd.arg("--product").arg(p);
        }
        if let Some(s) = signed_license {
            cmd.arg("--signed-license").arg(s);
        }
        if let Some(pk) = pubkey {
            cmd.arg("--pubkey").arg(pk);
        }
        cmd.assert()
    }

    /// Convenience: path to an expected .dlcpack file in the tempdir
    pub fn pack_path(&self, dlc_id: &str) -> PathBuf {
        self.td.path().join(format!("{}.dlcpack", dlc_id))
    }

    /// Assert that the parsed pack contains the given entry path
    pub fn assert_pack_contains_entry(&self, dlc_id: &str, entry_path: &str) {
        let file = std::fs::File::open(self.pack_path(dlc_id)).expect("read pack");
        let (_prod, _did, _v, entries, _blocks) = parse_encrypted_pack(&file).expect("parse pack");
        assert!(
            entries.iter().any(|(p, _)| p == entry_path),
            "entry not found: {}",
            entry_path
        );
    }
}

// the helper macro defined in the crate makes it trivial to declare a
// plain-text asset type along with its loader and plugin.  tests previously
// replicated this boilerplate manually; using the macro keeps things
// concise and also validates that the macro works.

bevy_dlc::dlc_simple_asset!(TextAsset, TextAssetLoader, TextAssetPlugin, "txt",);
