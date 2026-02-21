use std::time::Duration;

use bevy::{app::{Plugins, ScheduleRunnerPlugin}, prelude::*};
use secure_gate::ExposeSecret;
use tempfile::TempDir;

use bevy_dlc::{EncryptionKey, pack_encrypted_pack, prelude::*};

/// Test app builder
pub struct TestAppBuilder {
    product: String,
    dlc_ids: Vec<String>,
    app: App,
    dlc_key: DlcKey,
    temp_dir: TempDir,
}

#[allow(dead_code)]
impl TestAppBuilder {
    pub fn new(product: impl Into<Product>, dlc_ids: &[&str]) -> Self {
        Self {
            temp_dir: TempDir::new().expect("create temp dir for TestAppBuilder"),
            product: product.into().get().clone(),
            dlc_ids: dlc_ids.iter().map(|s| s.to_string()).collect(),
            app: App::new(),
            dlc_key: DlcKey::generate_random(),
        }
    }

    pub fn with_dlc_key(mut self, dlc_key: DlcKey) -> Self {
        self.dlc_key = dlc_key;
        self
    }

    pub fn with_default_plugins(mut self) -> Self {
        self.app.add_plugins(MinimalPlugins.set(ScheduleRunnerPlugin::run_loop(Duration::from_secs_f64(1.0 / 60.0))));
        self.app.add_plugins(bevy::window::WindowPlugin {
            primary_window: None,
            ..default()
        });
        self.app.add_plugins(bevy::log::LogPlugin {
            filter: "warn,bevy_dlc=trace".to_string(),
            ..default()
        });
        let assets_dir = self.temp_dir.path().join("assets");
        std::fs::create_dir_all(&assets_dir).expect("create assets dir");
        self.app.add_plugins(AssetPlugin {
            file_path: assets_dir.to_str().unwrap().to_string(),
            unapproved_path_mode: bevy::asset::UnapprovedPathMode::Allow,
            ..Default::default()
        });
        self
    }

    pub fn add_plugins<M>(mut self, plugins: impl Plugins<M>) -> Self {
        self.app.add_plugins(plugins);
        self
    }

    pub fn add_dlc_id(mut self, dlc_id: &str) -> Self {
        self.dlc_ids.push(dlc_id.to_string());
        self
    }

    /// Register an asset type so the resulting app will support loading the
    /// type from a DLC pack. Mirrors `AppExt::register_dlc_type` used in
    /// runtime tests.
    pub fn register_dlc_type<T: Asset + bevy::reflect::TypePath + 'static>(mut self) -> Self {
        self.app.init_asset::<T>();
        self.app.register_dlc_type::<T>();
        self
    }

    /// Return the configured `App` instance (consume the builder).
    pub fn build(mut self) -> TestApp {
        let signed_license = self
            .dlc_key
            .create_signed_license(
                self.dlc_ids.iter().map(|s| s.as_str()),
                Product::from(self.product.clone()),
            )
            .expect("create signed license");
        let signed_license_for_testapp =
            SignedLicense::from(signed_license.expose_secret().as_str());
        self.app.add_plugins(DlcPlugin::new(
            self.dlc_key.clone(),
            signed_license,
        ));
        let mut app = TestApp {
            app: self.app,
            dlc_key: self.dlc_key,
            product: Product::from(self.product),
            dlc_ids: self.dlc_ids,
            signed_license: signed_license_for_testapp,
            asset_dir: self.temp_dir,
        };
        app.init();
        app
    }
}

/// Test helper that manages a `bevy::App` instance with `DlcPlugin` and provides utility methods
/// for testing DLC pack loading and validation.
#[allow(unused)]
pub struct TestApp {
    pub app: App,
    pub dlc_key: DlcKey,
    pub product: Product,
    pub dlc_ids: Vec<String>,
    /// The signed license supplied at construction — use this when creating
    /// packs so the embedded `encrypt_key` matches the runtime registry.
    signed_license: SignedLicense,
    // isolated asset folder used by AssetServer
    asset_dir: TempDir,
}

#[allow(dead_code)]
impl TestApp {
    /// Create a new test app bound to `product` and containing a signed
    /// license that unlocks `dlc_ids`.
    pub fn new(product: &str, dlc_ids: &[&str]) -> Self {
        let product = Product::from(product);
        let dlc_key = DlcKey::generate_random();

        let app_builder = TestAppBuilder::new(product.clone(), dlc_ids)
            .with_default_plugins()
            .with_dlc_key(dlc_key);

        // build the underlying `bevy::App` and run plugin `build` steps
        let mut app = app_builder.build();
        app.init();
        app
    }

    fn init(&mut self) -> &mut Self {
        let original_cwd = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(self.asset_dir.path()).expect("set cwd to asset_dir");
        self.app.finish();
        self.app.cleanup();
        std::env::set_current_dir(original_cwd).expect("restore cwd");
        self
    }

    /// Re-run one frame of the app so asset registrations / systems run.
    pub fn update(&mut self) {
        self.app.update();
    }

    pub fn product(&self) -> &Product {
        &self.product
    }

    /// Recreate a `SignedLicense` that matches the current TestApp state.
    /// Useful when tests need to pass a token to CLI/validation helpers.
    pub fn signed_license(&self) -> SignedLicense {
        self.dlc_key
            .create_signed_license(
                self.dlc_ids.iter().map(|s| s.as_str()),
                self.product.clone(),
            )
            .expect("create signed license")
    }

    /// Path to the app's temporary asset folder
    pub fn asset_folder_path(&self) -> &std::path::Path {
        self.asset_dir.path()
    }

    /// Write a file into the app's `assets/` folder (creates parents).
    /// Write a file into the app's `assets/` folder (creates parents).
    /// Returns the absolute path that was written so callers can reuse it.
    pub fn write_asset_file<P: AsRef<std::path::Path>>(
        &self,
        rel: P,
        data: &[u8],
    ) -> std::path::PathBuf {
        let p = self.asset_dir.path().join("assets").join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        std::fs::write(&p, data).expect("write asset file");
        p
    }

    /// Write a file into the app's temporary directory but outside the `assets/` folder (creates parents).
    /// Returns the absolute path that was written so callers can reuse it.
    pub fn write_non_asset_file<P: AsRef<std::path::Path>>(
        &self,
        rel: P,
        data: &[u8],
    ) -> std::path::PathBuf {
        let p = self.asset_dir.path().join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        std::fs::write(&p, data).expect("write non-asset file");
        p
    }

    /// Load an asset path via the app's AssetServer and drive the app for a few
    /// frames so loaders can complete. Returns the handle that was requested.
    pub fn load_asset_sync<T: bevy::asset::Asset + 'static + Send + Sync>(
        &mut self,
        path: &str,
    ) -> Handle<T> {
        // temporarily set CWD to the asset_dir so AssetServer resolves correctly
        let original_cwd = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(self.asset_dir.path()).expect("set cwd to asset_dir");

        use std::time::Duration;

        let asset_server = self
            .app
            .world()
            .get_resource::<AssetServer>()
            .expect("asset server")
            .clone();

        // always load by logical path; changing cwd below ensures the asset
        // folder is visible even when the current directory is different.
        let handle: Handle<T> = asset_server.load(path.to_string());

        // poll the app's `Assets<T>` resource until the asset appears (or timeout)
        // increased timeout to reduce flakes on CI / slow machines; longer than
        // original 4 to allow file-watcher latency when running many tests.
        for _ in 0..20 {
            self.app.update();

            // check asset server load state for early failures
            let asset_server = self
                .app
                .world()
                .get_resource::<AssetServer>()
                .expect("asset server")
                .clone();
            if let Some(state) = asset_server.get_load_state(handle.id()).into() {
                use bevy::asset::LoadState;
                match state {
                    LoadState::Failed(e) => {
                        // provide helpful diagnostics on early failures
                        let repo_path = std::env::current_dir()
                            .expect("cwd")
                            .join("assets")
                            .join(path);
                        let temp_path = self.asset_dir.path().join("assets").join(path);
                        let repo_exists = std::fs::metadata(&repo_path).is_ok();
                        let temp_exists = std::fs::metadata(&temp_path).is_ok();
                        let path_ids = asset_server.get_path_ids(path.to_string());
                        panic!(
                            "asset load failed for path={}\nerror: {}\nrepo_exists: {}\ntemp_exists: {}\nasset_server.get_path_ids: {:?}",
                            path, e, repo_exists, temp_exists, path_ids
                        )
                    }
                    _ => {}
                }
            }

            if let Some(assets) = self.app.world().get_resource::<bevy::prelude::Assets<T>>() {
                if assets.get(&handle).is_some() {
                    // try to restore previous cwd; if it fails let tests continue
                    if let Err(e) = std::env::set_current_dir(&original_cwd) {
                        eprintln!("warning: failed to restore cwd: {}", e);
                    }
                    return handle;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        // restore cwd and fail hard — tests should not continue if loader didn't produce the asset
        // collect diagnostics to aid debugging: does the file exist on disk and
        // has AssetServer registered any path ids for the requested path?
        let full_path = self.asset_dir.path().join("assets").join(path);
        let file_exists = std::fs::metadata(&full_path).is_ok();
        let asset_server = self
            .app
            .world()
            .get_resource::<AssetServer>()
            .expect("asset server")
            .clone();
        let path_ids = asset_server.get_path_ids(path.to_string());
        if let Err(e) = std::env::set_current_dir(&original_cwd) {
            eprintln!("warning: failed to restore cwd: {}", e);
        }
        panic!(
            "asset did not load within timeout: {}\nfile_exists: {}\nasset_server.get_path_ids: {:?}",
            path, file_exists, path_ids
        );
    }

    /// Wait for a previously-loaded asset (via `pack.load` or other async load)
    /// to appear in the `Assets<T>` resource. Drives the app for a few frames
    /// until the asset loads or timeout is reached.
    pub fn wait_for_asset<T: bevy::asset::Asset + 'static + Send + Sync>(
        &mut self,
        handle: &Handle<T>,
        timeout: Option<Duration>,
    ) {
        let timeout: Duration = timeout.unwrap_or(Duration::from_secs(2));

        use std::time::Duration;
        let start = std::time::Instant::now();
        // poll the app's `Assets<T>` resource until the asset appears (or timeout)
        while start.elapsed() < timeout {
            self.app.update();

            if let Some(assets) = self.app.world().get_resource::<bevy::prelude::Assets<T>>() {
                if assets.get(handle).is_some() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        panic!(
            "asset did not load within timeout for handle id {:?}",
            handle.id()
        );
    }

    /// Create a `.dlcpack` (using `pack_encrypted_pack`) and write it into
    /// the app's asset folder, then load it and return the `Handle<DlcPack>`.
    /// Helper which packs a single file into a `.dlcpack` and then loads it.
    ///
    /// `source` should be a path previously returned by `write_asset_file`.
    /// `original_ext` is the file extension to record in the pack (e.g. "json").
    pub fn pack_file_and_load<P: AsRef<std::path::Path>>(
        &mut self,
        dlc_id: &str,
        source: P,
        original_ext: Option<&str>,
    ) -> Handle<bevy_dlc::DlcPack> {
        // ensure the app has run one frame so the plugin build step has
        // inserted the current license's encrypt key into the registry. This
        // avoids a race where we generate a new license for the pack after the
        // registry was populated (see regression in full test run).
        self.app.update();

        // read plaintext from the file
        let source_path = source.as_ref();
        let file_bytes = std::fs::read(source_path).expect("read source file");
        let filename = source_path
            .file_name()
            .expect("source has filename")
            .to_string_lossy()
            .to_string();

        let item = PackItem::new(filename.clone(), file_bytes)
            .with_extension(original_ext.unwrap_or_default());
        // derive encryption key and pack same as before
        let signed: SignedLicense = self.signed_license();
        let enc_key = bevy_dlc::extract_encrypt_key_from_license(&signed).expect("encrypt_key in license");

        let pack_bytes = pack_encrypted_pack(
            &DlcId::from(dlc_id.to_string()),
            &[item],
            &self.product,
            &self.dlc_key,
            &enc_key,
        )
        .expect("pack_encrypted_pack");

        let pack_name = format!("{}.dlcpack", dlc_id);
        self.write_asset_file(&pack_name, &pack_bytes);
        self.app.update();
        std::fs::remove_file(source_path).expect("cleanup source file");
        self.load_asset_sync::<bevy_dlc::DlcPack>(&pack_name)
    }

    /// Original helper maintaining previous signature (items list)
    pub fn pack_and_load(
        &mut self,
        dlc_id: &str,
        items: &[PackItem],
    ) -> Handle<bevy_dlc::DlcPack> {
        // derive the encryption key embedded in the signed license
        let signed: SignedLicense = self.signed_license();
        let enc_key: EncryptionKey = bevy_dlc::extract_encrypt_key_from_license(&signed).expect("encrypt_key in license");

        let pack_bytes = pack_encrypted_pack(
            &DlcId::from(dlc_id.to_string()),
            items,
            &self.product,
            &self.dlc_key,
            &enc_key,
        )
        .expect("pack_encrypted_pack");

        let filename = format!("{}.dlcpack", dlc_id);
        self.write_asset_file(&filename, &pack_bytes);

        // give AssetServer one frame to register the new file before loading
        self.app.update();

        self.load_asset_sync::<bevy_dlc::DlcPack>(&filename)
    }

    pub fn resource<T: Resource + 'static>(&self) -> &T {
        self.app
            .world()
            .get_resource::<T>()
            .expect("resource present")
    }

    pub fn resource_mut<T: Resource + 'static>(&mut self) -> Mut<'_, T> {
        self.app
            .world_mut()
            .get_resource_mut::<T>()
            .expect("resource present")
    }

    pub fn get_pack(&self, handle: &Handle<bevy_dlc::DlcPack>) -> &bevy_dlc::DlcPack {
        let packs = self.resource::<Assets<bevy_dlc::DlcPack>>();
        packs.get(handle).expect("pack loaded")
    }
}

// Ensure the temporary directory is closed and cleaned up when the test app
// is dropped. `TempDir` already implements Drop, but calling `close()` gives
// us a chance to observe/ignore any error explicitly and avoids the situation
// where earlier panics or process exit would prevent cleanup.
impl Drop for TestApp {
    fn drop(&mut self) {
        // TempDir::close consumes self, so we can't call it here.  Instead we
        // manually remove the directory if it still exists. This handles the
        // case where the process is terminating abnormally; the OS may still
        // leave the test folder behind, but we try our best.
        let _ = std::fs::remove_dir_all(self.asset_dir.path());
    }
}
