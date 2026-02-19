use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bevy::prelude::*;
use bevy::{asset::AssetServer, log::LogPlugin};


use clap::{Parser, Subcommand};

use bevy_dlc::{
    DLC_PACK_MAGIC, EncryptionKey, pack_encrypted_pack,
    parse_encrypted_pack, prelude::*,
};
use secure_gate::ExposeSecret;

const FORBIDDEN_EXTENSIONS: [&str; 3] = ["dlcpack", "pubkey", "slicense"];

#[derive(Parser)]
#[command(
    author,
    version,
    about = "bevy-dlc helper: pack and unpack .dlcpack containers",
    long_about = "Utility for creating, inspecting and extracting bevy-dlc encrypted containers.\n\nPACK: encrypt assets and emit a .dlcpack bundle and print a symmetric encrypt key.\nVALIDATE: verify a .dlcpack container using a signed license.\nLIST: inspect contents of a .dlcpack container.\nGENERATE: create new signed licenses."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Pack assets into a .dlcpack bundle (writes .dlcpack, prints private key + pub key)",
        long_about = "Encrypts the provided input files into a single bevy-dlc .dlcpack bundle and prints a signed private key and public key. Use --list to preview container metadata without writing files."
    )]
    Pack {
        /// DLC identifier to embed in the container/private key
        #[arg(
            help = "Identifier embedded into the container and private key (e.g. expansion_1)",
            value_name = "DLC_ID"
        )]
        dlc_id: String,
        /// Supply an explicit list of files to include (overrides directory recursion)
        #[arg(value_name = "FILES...", last = true)]
        files: Vec<PathBuf>,
        /// print container metadata instead of writing
        #[arg(
            short,
            long,
            help = "Show the metadata the container would contain and exit; no file or private key will be produced."
        )]
        list: bool,
        /// output path (defaults to <dlc_id>.dlcpack)
        #[arg(
            short,
            long,
            help = "Destination path for the generated .dlcpack (default: <dlc_id>.dlcpack)",
            value_name = "OUT"
        )]
        out: Option<PathBuf>,
        /// Product identifier to embed in the private key
        #[arg(
            short,
            long,
            help = "Product identifier to embed in the signed private key",
            long_help = "Embeds a product identifier in the private key. When the DlcManager has a product binding set, tokens must include a matching product value to be accepted. Use this to restrict tokens to a specific game or application.",
            value_name = "PRODUCT"
        )]
        product: String,

        /// Manual type overrides (ext=TypePath pairs)
        #[arg(
            long = "types",
            help = "Override asset types: ext=TypePath (e.g., json=my_game::LevelData)",
            long_help = "Manually specify TypePath for extensions that Bevy doesn't recognize.\nFormat: --types json=my_game::LevelData --types csv=my_game::CsvData\nThese take precedence over auto-detected types from Bevy's loaders.",
            value_name = "EXT=TYPE",
            num_args = 1..
        )]
        types: Option<Vec<String>>,

        /// Optional public key to use for verifying/printing an externally-supplied license
        #[arg(
            long = "pubkey",
            help = "Optional public key (base64url or file) used to verify a supplied signed license or to print alongside a supplied license",
            value_name = "PUBKEY"
        )]
        pubkey: Option<String>,

        /// Optional pre-generated SignedLicense (compact token). When provided with `--pubkey` the license will be verified.
        #[arg(
            short,
            long = "signed-license",
            help = "Optional SignedLicense token to use instead of generating a new one",
            value_name = "SIGNED_LICENSE"
        )]
        signed_license: Option<String>,
    },

    #[command(
        about = "List contents of a .dlc or .dlcpack (prints entries/metadata)",
        long_about = "Display detailed metadata for a single .dlc file or the entries inside a .dlcpack. If given a directory, lists all .dlc and .dlcpack files inside."
    )]
    List {
        /// path to a .dlc or .dlcpack file (or directory)
        #[arg(
            value_name = "DLC",
            help = "Path to a .dlc or .dlcpack file, or a directory containing .dlc/.dlcpack files (recursive)"
        )]
        dlc: PathBuf,
    },

    /// Validate a `.dlc` or `.dlcpack` against a SignedLicense / public key.
    /// If the license carries an embedded `encrypt_key `, the command will
    /// attempt to decrypt the container and report success or the failure
    /// reason (useful for CI or debugging packaging tokens).
    Validate {
        /// path to a .dlc or .dlcpack file
        #[arg(value_name = "DLC")]
        dlc: PathBuf,
        /// Product name (used to read `<product>.slicense` / `<product>.pubkey` if not supplied)
        #[arg(short, long, value_name = "PRODUCT")]
        product: Option<String>,
        /// Optional SignedLicense token to validate (compact form)
        #[arg(short, long = "signed-license", value_name = "SIGNED_LICENSE")]
        signed_license: Option<String>,
        /// Optional public key (base64url or file) used to verify the signed license
        #[arg(long = "pubkey", value_name = "PUBKEY")]
        pubkey: Option<String>,
    },

    #[command(
        about = "Generate a product .slicense and .pubkey (for testing/CI)",
        long_about = "Create a signed-license token and write <product>.slicense and <product>.pubkey; these files are used as defaults by other commands when present."
    )]
    Generate {
        /// Product name (used for filenames and token product binding)
        #[arg(value_name = "PRODUCT")]
        product: String,
        /// DLC ids to include in the signed license
        #[arg(value_name = "DLCS", num_args = 1..)]
        dlcs: Vec<String>,
        /// Output directory for the generated .slicense and .pubkey files (defaults to current directory)
        #[arg(short, long, value_name = "OUT_DIR")]
        out_dir: Option<PathBuf>,
        /// Overwrite existing files if present
        #[arg(short, long)]
        force: bool,
        /// Optionally emit a random 32-byte AES encrypt key (base64url/hex) (secure create requires an encrypt key, but this is not needed for signature verification or pack listing)
        #[arg(
            long = "emit-encrypt-key",
            help = "Also print a random 32-byte AES encrypt key (base64url) for use with secure crate"
        )]
        emit_encrypt_key: bool,
    },

}

/// Recursively collect files under `dir`. If `ext_filter` is Some(ext), only
/// files matching that extension are returned.
fn collect_files_recursive(
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
    ext_filter: Option<&str>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, out, ext_filter)?;
        } else if path.is_file() {
            match ext_filter {
                Some(filter) => {
                    if path
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case(filter))
                        .unwrap_or(false)
                    {
                        out.push(path);
                    }
                }
                None => out.push(path),
            }
        }
    }
    Ok(())
}

/// Parse manual type overrides from CLI arguments.
///
/// Expects format: `ext=TypePath` (e.g., `json=my_game::LevelData`)
fn parse_type_overrides(overrides: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for entry in overrides {
        if let Some((ext, type_path)) = entry.split_once('=') {
            map.insert(ext.to_ascii_lowercase(), type_path.to_string());
        }
    }
    map
}

/// Print `SignedLicense` and public-key information, and optionally write
/// `<product>.slicense` and `<product>.pubkey` when `write_files` is true and
/// `product` is provided.
///
/// - Prints the compact `SignedLicense` token (format: `payload_base64url.signature_base64url`).
/// - DOES NOT print private seeds or raw symmetric keys; treat the token as
///   sensitive and provision it securely.
fn print_signed_license_and_pubkey(
    signedlicense: &str,
    dlc_key: &DlcKey,
    write_files: bool,
    product: Option<&str>,
) {
    println!("SIGNED LICENSE:\n{}", signedlicense);

    let pubkey_b64 = URL_SAFE_NO_PAD.encode(dlc_key.get_public_key().get());
    println!("PUB KEY: {}", pubkey_b64);

    if write_files {
        if let Some(prod) = product {
            let slicense_path = format!("{}.slicense", prod);
            let pubkey_path = format!("{}.pubkey", prod);
            if let Err(e) = std::fs::write(&slicense_path, signedlicense) {
                eprintln!("failed to write {}: {}", slicense_path, e);
            }
            if let Err(e) = std::fs::write(&pubkey_path, pubkey_b64) {
                eprintln!("failed to write {}: {}", pubkey_path, e);
            }
        } else {
            eprintln!("no product name supplied; skipping file write");
        }
    }
}

/// Resolve TypePath for file paths using Bevy's `AssetServer`.
///
/// This relies on runtime loader registrations; use `--types` to override
/// missing loaders.
async fn resolve_type_paths_from_bevy(
    app: &mut App,
    paths: &[PathBuf],
    overrides: &HashMap<String, String>,
) -> Result<HashMap<PathBuf, String>, Box<dyn std::error::Error>> {
    // collect unique extensions to query
    let mut extensions_to_query: Vec<String> = Vec::new();
    for path in paths {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_ascii_lowercase();
            if !overrides.contains_key(&ext_lower) && !extensions_to_query.contains(&ext_lower) {
                extensions_to_query.push(ext_lower);
            }
        }
    }

    // strict AssetServer-only resolution
    let mut ext_map: HashMap<String, String> = HashMap::new();
    {
        let world = app.world();
        let asset_server_ref = world
            .get_resource::<AssetServer>()
            .ok_or("AssetServer resource not found")?;
        let asset_server = asset_server_ref.clone();

        for ext in &extensions_to_query {
            // run one frame so plugins/systems can perform registrations
            app.update();

            match asset_server.get_asset_loader_with_extension(ext).await {
                Ok(loader) => {
                    let type_name = loader.asset_type_name();
                    ext_map.insert(ext.clone(), type_name.to_string());
                }
                Err(_) => {
                    return Err(format!(
                        "no AssetLoader registered for extension '{}'; either add the plugin that provides the loader or pass --types {}=TypePath",
                        ext, ext
                    ).into());
                }
            }
        }
    }

    // Build final path -> type_path map (manual overrides take precedence)
    let mut result = HashMap::new();
    for path in paths {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_ascii_lowercase();
            if let Some(tp) = overrides.get(&ext_lower) {
                result.insert(path.clone(), tp.clone());
            } else if let Some(tp) = ext_map.get(&ext_lower) {
                result.insert(path.clone(), tp.clone());
            }
        }
    }

    Ok(result)
}

/// Helper: Attempt to decrypt a ciphertext with the provided key and nonce, without any archive parsing or license verification. Used to test whether an embedded encrypt key can successfully decrypt the archive ciphertext.
fn decrypt_with_key_local(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 32 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "encrypt key must be 32 bytes (AES-256)",
        )));
    }
    if nonce.len() != 12 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "nonce must be 12 bytes",
        )));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;
    let nonce = Nonce::from_slice(nonce);
    let pt = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|e| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;
    Ok(pt)
}

/// Helper: Resolve pubkey and signed license from CLI args or defaults files
fn resolve_pubkey_and_license(
    pubkey: Option<String>,
    signed_license: Option<String>,
    product: &str,
) -> (Option<String>, Option<String>) {
    let default_pubkey_file = format!("{}.pubkey", product);
    let default_slicense_file = format!("{}.slicense", product);
    
    let resolved_pubkey = pubkey.or_else(|| {
        if std::path::Path::new(&default_pubkey_file).exists() {
            std::fs::read_to_string(&default_pubkey_file)
                .ok()
                .map(|s| s.trim().to_string())
        } else {
            None
        }
    });
    
    let resolved_license = signed_license.or_else(|| {
        if std::path::Path::new(&default_slicense_file).exists() {
            std::fs::read_to_string(&default_slicense_file)
                .ok()
                .map(|s| s.trim().to_string())
        } else {
            None
        }
    });
    
    (resolved_pubkey, resolved_license)
}

/// Helper: Derive encryption key from signed license or generate new one
fn derive_encrypt_key(signed_license: Option<&str>) -> Result<EncryptionKey, Box<dyn std::error::Error>> {
    Ok(if let Some(lic_str) = signed_license {
        if let Some(key_bytes) = bevy_dlc::extract_encrypt_key_from_license(
            &bevy_dlc::SignedLicense::from(lic_str.to_string()),
        ) {
            if key_bytes.len() != 32 {
                return Err("embedded encrypt key has invalid length".into());
            }
            EncryptionKey::from(key_bytes)
        } else {
            EncryptionKey::from_random(32)
        }
    } else {
        EncryptionKey::from_random(32)
    })
}

/// Helper: Handle license verification/generation and output
fn handle_license_output(
    signed_license: Option<&str>,
    pubkey: Option<&str>,
    product: &str,
    dlc_id_str: &str,
    signer_key: Option<&DlcKey>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(sup_license) = signed_license {
        if let Some(pubkey_str) = pubkey {
            let verifier = DlcKey::public(pubkey_str)
                .map_err(|e| format!("invalid provided pubkey: {:?}", e))?;
            let verified = verifier
                .verify_signed_license(&SignedLicense::from(sup_license.to_string()))
                .map_err(|e| format!("supplied signed-license verification failed: {:?}", e))?;
            if verified.product != product {
                return Err("supplied signed-license product does not match --product".into());
            }
            if !verified.dlcs.iter().any(|d| d == &dlc_id_str) {
                return Err("supplied signed-license does not include the requested DLC id".into());
            }
            println!("SIGNED LICENSE:\n{}", sup_license);
            println!("PUB KEY: {}", pubkey_str);
        } else {
            eprintln!("warning: supplied signed-license not verified (no --pubkey supplied)");
            println!("SIGNED LICENSE:\n{}", sup_license);
        }
    } else {
        // Use the provided signer key (the key that signed the pack) when available
        if let Some(dlc_key) = signer_key {
            let signedlicense = dlc_key.create_signed_license(
                &[DlcId::from(dlc_id_str.to_string())],
                Product::from(product.to_string()),
            )?;
            signedlicense.with_secret(|s| print_signed_license_and_pubkey(s.as_str(), dlc_key, false, Some(product)));
        } else {
            let dlc_key = DlcKey::generate_random();
            let signedlicense = dlc_key.create_signed_license(
                &[DlcId::from(dlc_id_str.to_string())],
                Product::from(product.to_string()),
            )?;
            signedlicense.with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key, true, Some(product)));
        }
    }
    Ok(())
}

/// Helper: Resolve pubkey/license for Validate, with fallback to embedded product
fn resolve_validate_keys(
    pubkey: Option<String>,
    signed_license: Option<String>,
    product: Option<String>,
    embedded_product: Option<String>,
) -> (Option<String>, Option<String>) {
    let resolved_pubkey = pubkey.or_else(|| {
        product
            .as_ref()
            .or_else(|| embedded_product.as_ref())
            .and_then(|p| {
                let path = format!("{}.pubkey", p);
                if std::path::Path::new(&path).exists() {
                    std::fs::read_to_string(&path)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    });

    let resolved_license = signed_license.or_else(|| {
        product
            .as_ref()
            .or_else(|| embedded_product.as_ref())
            .and_then(|p| {
                let path = format!("{}.slicense", p);
                if std::path::Path::new(&path).exists() {
                    std::fs::read_to_string(&path)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    });

    (resolved_pubkey, resolved_license)
}

/// Helper: extract an embedded `encrypt_key` (base64url) from a compact SignedLicense token
/// Returns Ok(Some(key_bytes)) when present, Ok(None) when payload contains no encrypt_key,
/// Err(...) for malformed token / invalid base64 / wrong length.
fn extract_encrypt_key_from_token(
    signed_license: &str,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = signed_license.split('.').collect();
    if parts.len() != 2 {
        return Err("malformed signed-license token".into());
    }
    let payload = URL_SAFE_NO_PAD.decode(parts[0].as_bytes())?;
    let payload_json: serde_json::Value = serde_json::from_slice(&payload)?;
    if let Some(ck_b64) = payload_json.get("encrypt_key").and_then(|v| v.as_str()) {
        let key_bytes = URL_SAFE_NO_PAD.decode(ck_b64.as_bytes())?;
        if key_bytes.len() != 32 {
            return Err("embedded encrypt key has invalid length".into());
        }
        Ok(Some(key_bytes))
    } else {
        Ok(None)
    }
}

// Helper: attempt to decrypt the first archive entry using the provided symmetric key.
// Returns Ok(()) on success; Err(...) on any failure (decryption or archive extraction).
fn test_decrypt_archive_with_key(
    container_bytes: &[u8],
    key_bytes: &[u8],
    signature_verified: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_prod, _did, _v, entries) = parse_encrypted_pack(container_bytes)?;
    if entries.is_empty() {
        println!("container has no entries");
        return Ok(());
    }
    let archive_nonce = entries[0].1.nonce;
    let archive_ciphertext = &entries[0].1.ciphertext;

    match decrypt_with_key_local(key_bytes, archive_ciphertext, &archive_nonce) {
        Ok(plain) => {
            let dec = flate2::read::GzDecoder::new(std::io::Cursor::new(plain));
            let mut ar = tar::Archive::new(dec);
            match ar.entries() {
                Ok(_) => {
                    if signature_verified {
                        println!("SUCCESS: .dlcpack archive decrypts with embedded encrypt key (signature verified)");
                    } else {
                        println!("SUCCESS: .dlcpack archive decrypts with embedded encrypt key (signature NOT verified)");
                    }
                    Ok(())
                }
                Err(e) => Err(format!("DECRYPT FAILURE (archive extract): {}", e).into()),
            }
        }
        Err(e) => Err(format!("DECRYPT FAILURE: {}", e).into()),
    }
}

async fn pack_command(
    app: &mut App,
    dlc_id_str: String,
    files: Vec<PathBuf>,
    list: bool,
    out: Option<PathBuf>,
    product: String,
    types: Option<Vec<String>>,
    pubkey: Option<String>,
    signed_license: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // extracted from main::Commands::Pack
    let (pubkey, signed_license) = resolve_pubkey_and_license(pubkey, signed_license, &product);

    // Collect all input files (from files or directories)
    let mut selected_files: Vec<PathBuf> = Vec::new();
    for entry in &files {
            if FORBIDDEN_EXTENSIONS.iter().any(|ext| {
                entry
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case(ext))
                    .unwrap_or(false)
            }) {
                return Err(format!(
                    "input contains forbidden file extension ({}): {}",
                    FORBIDDEN_EXTENSIONS.join(", "),
                    entry.display()
                )
                .into());
            }
            if entry.is_dir() {
                collect_files_recursive(entry, &mut selected_files, None)?;
            } else if entry.is_file() {
                selected_files.push(entry.clone());
            } else {
                return Err(format!("input path not found: {}", entry.display()).into());
            }
        }

        if selected_files.is_empty() {
            return Err("no files selected for dlcpack".into());
        }

        let type_overrides = types
            .as_ref()
            .map(|t| parse_type_overrides(t))
            .unwrap_or_default();
        let type_path_map =
            resolve_type_paths_from_bevy(app, &selected_files, &type_overrides).await?;

        let mut items: Vec<(String, Option<String>, Option<String>, Vec<u8>)> = Vec::new();
        for file in &selected_files {
            let mut f = File::open(file)?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;

        if bytes.len() >= 4 && &bytes[0..4] == DLC_PACK_MAGIC {
            return Err(format!(
                "refusing to pack '{}' — input appears to be an existing .dlcpack",
                file.display()
            )
            .into());
        }

            let mut rel = file
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file")
                .to_string();
            for base in &files {
                if base.is_dir() && file.starts_with(base) {
                    rel = file
                        .strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .to_string();
                    break;
                }
            }
            let ext = file
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string());
            let type_path = type_path_map.get(file).cloned();
            items.push((rel, ext, type_path, bytes));
        }

        let dlc_id = DlcId::from(dlc_id_str.clone());
        // If the user supplied a signed-license and a pubkey, prefer signing the pack
        // with the private seed embedded in that license so the pack's signature
        // matches the provided `pubkey`/`slicense`. Otherwise generate a new key.
        let dlc_key = if let (Some(sup_license), Some(pk)) = (signed_license.as_deref(), pubkey.as_deref()) {
            if let Some(seed_bytes) = bevy_dlc::extract_encrypt_key_from_license(&SignedLicense::from(sup_license.to_string())) {
                let priv_b64 = URL_SAFE_NO_PAD.encode(&seed_bytes);
                match DlcKey::new(pk, &priv_b64) {
                    Ok(k) => k,
                    Err(_) => DlcKey::generate_random(),
                }
            } else {
                DlcKey::generate_random()
            }
        } else {
            DlcKey::generate_random()
        };
        let encrypt_key = derive_encrypt_key(signed_license.as_deref())?;

        let container = pack_encrypted_pack(
            &dlc_id,
            &items,
            &Product::from(product.clone()),
            &dlc_key,
            &encrypt_key,
        )?;

        handle_license_output(
            signed_license.as_deref(),
            pubkey.as_deref(),
            &product,
            &dlc_id_str,
            Some(&dlc_key),
        )?;

        if list {
            let (_prod, did, _v, ents) = parse_encrypted_pack(&container)?;
            println!("dlc_id: {} entries: {}", did, ents.len());
            for (p, enc) in ents.iter() {
                println!(
                    " - {} (ext={}) ciphertext_len={} nonce={}",
                    p,
                    enc.original_extension,
                    enc.ciphertext.len(),
                    hex::encode(enc.nonce)
                );
            }
        }

        let out_path = if let Some(out_val) = out {
            let path = PathBuf::from(&out_val);
            if path.is_dir() {
                path.join(format!("{}.dlcpack", dlc_id_str))
            } else {
                path
            }
        } else {
            PathBuf::from(format!("{}.dlcpack", dlc_id_str))
        };
        std::fs::write(&out_path, &container)?;
        println!("created dlcpack: {}", out_path.display());
        Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create headless Bevy app to set up asset loaders
    let mut app = App::new();
    app.add_plugins(
        DefaultPlugins
            .set(WindowPlugin {
                primary_window: None,
                ..default()
            })
            .set(LogPlugin {
                level: bevy::log::Level::ERROR,
                ..Default::default()
            }),
    );

    app.finish();
    app.cleanup();

    app.update();

    let cli = Cli::parse();

    match cli.command {
        Commands::Pack {
            dlc_id: dlc_id_str,
            files,
            list,
            out,
            product,
            types,
            pubkey,
            signed_license,
        } => {
            pack_command(
                &mut app,
                dlc_id_str,
                files,
                list,
                out,
                product,
                types,
                pubkey,
                signed_license,
            )
            .await?;
        }

        Commands::List { dlc } => {
            if dlc.is_dir() {
                let mut files = Vec::new();
                collect_files_recursive(&dlc, &mut files, None)?;
                if files.is_empty() {
                    return Err("no .dlcpack files found in directory".into());
                }
                for file in &files {
                    let ext = file.extension().and_then(|s| s.to_str()).unwrap_or("");
                    if ext.eq_ignore_ascii_case("dlcpack") {
                        let bytes = std::fs::read(file)?;
                        let (_prod, did, _v, ents) = parse_encrypted_pack(&bytes)?;
                        println!(
                            "{} -> dlcpack: {} entries: {}",
                            file.display(),
                            did,
                            ents.len()
                        );
                        for (p, enc) in ents.iter() {
                            println!(
                                " - {} (ext={}) ciphertext_len={} nonce={}",
                                p,
                                enc.original_extension,
                                enc.ciphertext.len(),
                                hex::encode(enc.nonce)
                            );
                        }
                    }
                }
                return Ok(());
            }

            // single-file mode
            let bytes = std::fs::read(&dlc)?;
            let (_prod, did, _v, ents) = parse_encrypted_pack(&bytes)?;
            println!("dlcpack: {} entries: {}", did, ents.len());
            for (p, enc) in ents.iter() {
                println!(
                    " - {} (ext={}) ciphertext_len={} nonce={} type={}",
                    p,
                    enc.original_extension,
                    enc.ciphertext.len(),
                    hex::encode(enc.nonce),
                    enc.type_path.clone().unwrap_or("None".to_string())
                );
            }
            return Ok(());
        }

        Commands::Validate {
            dlc,
            product,
            signed_license,
            pubkey,
        } => {
            // read container bytes
            let bytes = std::fs::read(&dlc)?;

            // Parse the .dlcpack and get the embedded product and first dlc_id
            let (prod, dlc_id, _v, _ents) = parse_encrypted_pack(&bytes)?;
            let embedded_product = Some(prod.to_string());

            // resolve pubkey and signed license with fallback to embedded product
            let (supplied_pubkey, supplied_license) = resolve_validate_keys(pubkey, signed_license, product, embedded_product);

            // Verify the embedded signature if pubkey is available
            if let Some(pk) = supplied_pubkey.as_deref() {

                match bevy_dlc::verify_pack_signature(&bytes, pk) {
                    Ok(true) => println!("Pack signature verification: SUCCESS"),
                    Ok(false) => return Err("Pack signature verification: FAILED (invalid signature)".into()),
                    Err(e) => return Err(format!("Pack signature verification: ERROR ({})", e).into()),
                }
            }

            if supplied_license.is_none() {
                return Err("no signed license supplied or found (use --signed-license or --product <name> to pick <product>.slicense)".into());
            }
            let supplied_license = supplied_license.unwrap();


            // when a pubkey is supplied, verify the signed-license and check DLC coverage
            if let Some(pk) = supplied_pubkey.as_deref() {
                let verifier = DlcKey::public(pk).map_err(|e| format!("invalid pubkey: {:?}", e))?;
                let verified = verifier
                    .verify_signed_license(&SignedLicense::from(supplied_license.clone()))
                    .map_err(|e| format!("signed-license verification failed: {:?}", e))?;

                if !verified.dlcs.iter().any(|d| d == &dlc_id) {
                    return Err(format!("license does not include DLC id '{}'", dlc_id).into());
                }
            }

            // extract embedded encrypt_key (common code path)
            match extract_encrypt_key_from_token(&supplied_license) {
                Ok(Some(key_bytes)) => {
                    println!(
                        "Found embedded encrypt_key (base64): {}",
                        URL_SAFE_NO_PAD.encode(&key_bytes)
                    );
                    test_decrypt_archive_with_key(&bytes, &key_bytes, supplied_pubkey.is_some())?;
                }
                Ok(None) => {
                    if supplied_pubkey.is_some() {
                        println!("License verified but does not carry an embedded encrypt key — cannot test decrypt");
                    } else {
                        println!("Token payload does not contain a encrypt key; cannot test decrypt");
                    }
                }
                Err(e) => return Err(e),
            }

            return Ok(());
        }

        Commands::Generate {
            product,
            dlcs,
            out_dir,
            force,
            emit_encrypt_key,
        } => {
            if dlcs.is_empty() {
                return Err("must supply at least one DLC id for Generate".into());
            }

            // create private key + signed license (private key seed becomes embedded encrypt_key)
            let dlc_key = DlcKey::generate_random();
            let signedlicense =
                dlc_key.create_signed_license(&dlcs, Product::from(product.clone()))?;

            // determine output paths (use out_dir when provided)
            let out_dir_path = out_dir
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            if !out_dir_path.exists() {
                std::fs::create_dir_all(&out_dir_path)?;
            }
            let slicense_path = out_dir_path.join(format!("{}.slicense", product));
            let pubkey_path = out_dir_path.join(format!("{}.pubkey", product));

            if !force {
                if slicense_path.exists() || pubkey_path.exists() {
                    return Err(format!(
                        "'{}' or '{}' already exists; use --force to overwrite",
                        slicense_path.display(),
                        pubkey_path.display()
                    )
                    .into());
                }
            }

            // print token + pubkey to stdout and write <product>.slicense / <product>.pubkey
            signedlicense.with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key, true, Some(product.as_str())));

            // optionally emit a random 32-byte AES encrypt key (base64url)
            if emit_encrypt_key {
                let ek = EncryptionKey::from_random(32);
                ek.with_secret(|kb| {
                    println!("ENCRYPT KEY (base64url): {}", URL_SAFE_NO_PAD.encode(kb));
                });
            }

            println!(
                "Wrote {} and {}",
                slicense_path.display(),
                pubkey_path.display()
            );
            return Ok(());
        }
    }

    Ok(())
}
