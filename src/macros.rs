//! A collection of helper macros to reduce boilerplate when working with DLC packs
//! and assets. These are primarily convenience utilities used by tests and examples
//! (and available to library users) for quickly defining common patterns.
//!
//! The macros are all exported at the crate root so you can invoke them as
//! `bevy_dlc::pack_items!()`, `bevy_dlc::dlc_register_types!()`, etc.

#[doc(hidden)]
pub fn __decode_embedded_signed_license_aes(encrypted_b64: &str, key: &str) -> crate::SignedLicense {
    use base64::Engine as _;

    let value = base64::prelude::BASE64_STANDARD
        .decode(encrypted_b64.as_bytes())
        .expect("invalid embedded base64 in signed license");
    let cryptor = byte_aes::Aes256Cryptor::try_from(key)
        .expect("invalid AES key for signed license");
    let decoded_data = cryptor
        .decrypt(value)
        .expect("failed to decrypt embedded signed license");

    // String::from_utf8 moves decoded_data without cloning — same heap
    // allocation, now owned by SignedLicense, which zeroes it on drop
    // via dynamic_alias!.
    crate::SignedLicense::from(
        String::from_utf8(decoded_data)
            .expect("embedded signed license is not valid UTF-8"),
    )
}

/// format a byte count into a human-readable string (KB/MB/GB)
///
/// The macro returns a `String`; the formatting matches the previous
/// `human_bytes` helper, using two decimal places of precision for units
/// greater than bytes.
///
/// Example usage (hidden from docs):
/// ```ignore
/// use bevy_dlc::human_bytes;
/// let s = human_bytes!(123456);
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! human_bytes {
    ($bytes:expr) => {{
        let bytes: u64 = $bytes as u64;
        const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit = 0;
        while size >= 1024.0 && unit < UNITS.len() - 1 {
            size /= 1024.0;
            unit += 1;
        }
        if unit == 0 {
            format!("{} {}", size as u64, UNITS[unit])
        } else {
            format!("{:.2} {}", size, UNITS[unit])
        }
    }};
}

/// Builds a `Vec<PackItem>` from a list of entries.  Each entry specifies a
/// path and its raw contents; optional query-style suffixes allow specifying an
/// explicit original extension or a type path as well.
///
/// Examples:
///
/// ```ignore
/// use bevy_dlc::pack_items;
///
/// let items = pack_items![
///     "note.txt" => b"hello",
///     // override the extension that would otherwise be inferred
///     "other" => b"data"; ext="bin",
///     // supply a type path to help the runtime choose a loader (optional)
///     "model" => b"objdata"; type="bevy::gltf::Gltf",
/// ];
/// ```
#[macro_export]
macro_rules! pack_items {
    (
        $(
            $path:expr => $bytes:expr
            $(; ext=$ext:expr)?
            $(; type=$type_path:expr)?
        ),* $(,)?
    ) => {{
        let mut v = Vec::new();
        $(
            let mut item = $crate::PackItem::new($path, $bytes).expect("forbidden extension or invalid dlcpack content");
            $( item = item.with_extension($ext).expect("forbidden extension"); )?
            $( item = item.with_type_path($type_path); )?
            v.push(item);
        )*
        v
    }};
}

/// Calls `App::register_dlc_type::<T>()` for each given type on the provided
/// Bevy `App` instance.
///
/// Useful when registering several DLC-supported asset types in one line:
///
/// ```ignore
/// use bevy::prelude::*;
/// use bevy_dlc::prelude::*;
///
/// let mut app = App::new();
/// // an `AssetPlugin` (or AssetLoaders for the asset types) must be added before registering
/// // asset types; this mirrors real usage inside a Bevy application.
/// app.add_plugins(AssetPlugin::default());
/// // bring the `AppExt` trait into scope so the generated calls resolve
/// dlc_register_types!(app, Image, Mesh);
/// ```
#[macro_export]
macro_rules! dlc_register_types {
    ($app:expr, $($ty:ty),* $(,)?) => {{
        $(
            $app.register_dlc_type::<$ty>();
        )*
    }};
}

/// Defines a simple "text-like" asset type along with a loader and a Bevy
/// plugin for it.  The generated loader reads the file as UTF-8 and stores a
/// `String` in the asset.  The plugin registers the loader and the DLC type.
///
/// This is the same pattern used throughout the repository for example assets
/// (see `examples/mod.rs`) and in the test helpers.  Rather than copy/paste the
/// struct/loader/plugin boilerplate each time, this macro generates it for you.
///
/// The macro takes explicit identifiers for the asset struct, its loader, and
/// the plugin; this avoids any need for identifier concatenation in
/// `macro_rules!`.
///
/// Parameters:
/// * `$name`: identifier for the new asset struct.
/// * `$loader`: identifier for the asset/loader type.
/// * `$plugin`: identifier for the plugin struct.
/// * `$($ext:expr),+`: one or more file extensions the loader will recognise.
///
/// Example:
///
/// ```ignore
/// // demonstration only; we don't actually run a Bevy app inside the doctest
/// use bevy::prelude::AssetApp;
/// use bevy_dlc::dlc_simple_asset;
///
/// dlc_simple_asset!(TextAsset, TextAssetLoader, TextAssetPlugin, "txt", "text");
/// ```
#[macro_export]
macro_rules! dlc_simple_asset {
    ($name:ident, $loader:ident, $plugin:ident, $($ext:expr),+ $(,)?) => {
        #[derive(bevy::asset::Asset, bevy::reflect::Reflect, serde::Serialize, serde::Deserialize)]
        pub struct $name(pub String);

        #[derive(Default, bevy::reflect::Reflect)]
        pub struct $loader;

        impl bevy::asset::AssetLoader for $loader {
            type Asset = $name;
            type Settings = ();
            type Error = std::io::Error;

            async fn load(
                &self,
                reader: &mut dyn bevy::asset::io::Reader,
                _settings: &(),
                _load_context: &mut bevy::asset::LoadContext<'_>,
            ) -> Result<Self::Asset, Self::Error> {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).await?;
                let s = String::from_utf8(bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok($name(s))
            }

            fn extensions(&self) -> &[&str] {
                static EXTS: &[&str] = &[$($ext),+];
                EXTS
            }
        }

        pub struct $plugin;

        impl bevy::prelude::Plugin for $plugin {
            fn build(&self, app: &mut bevy::prelude::App) {
                app.init_asset_loader::<$loader>();
                // call via fully qualified path so the `AppExt` trait need not be
                // imported by the macro user.
                // use `$crate` to refer to the current crate from derived code.  `AppExt`
                // is re-exported at the crate root, so we do not need to touch the
                // private `ext` module here.
                $crate::AppExt::register_dlc_type::<$name>(app);
            }
        }

        impl Default for $plugin {
            fn default() -> Self {
                $plugin
            }
        }
    };
}

/// Includes a secure license token and a public key from files.
///
/// Returns a `(DlcKey, SignedLicense)` tuple.
/// 
/// Example:
/// ```rust,ignore
/// use bevy_dlc::prelude::*;
/// 
/// let (dlc_key, signed_license) = include_dlc_key_and_license_aes!(
///     "examples/example_keys/example.pubkey",
///     "examples/example_keys/example.slicense",
///     "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", // Don't use a key like this in production! This is just an example for testing purposes. The key must be exactly 32 characters for AES-256.
/// );
/// ```
#[macro_export]
macro_rules! include_dlc_key_and_license_aes {
    ($pubkey_path:expr, $license_path:expr, $license_key:expr $(,)?) => {{
        let signed_license = $crate::include_signed_license_aes!($license_path, $license_key);
        let dlc_key = $crate::DlcKey::public(include_str!($pubkey_path))
            .expect("invalid dlc pubkey");
        (dlc_key, signed_license)
    }};
}

