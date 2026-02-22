use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bevy::prelude::*;
use bevy::{asset::AssetServer, log::LogPlugin};

use clap::{Parser, Subcommand};

use bevy_dlc::{
    DLC_PACK_MAGIC, DLC_PACK_VERSION, EncryptionKey, PackItem, extract_dlc_ids_from_license, pack_encrypted_pack, parse_encrypted_pack, prelude::*
};
use owo_colors::{AnsiColors, OwoColorize};
use secure_gate::ExposeSecret;

const FORBIDDEN_EXTENSIONS: [&str; 3] = ["dlcpack", "pubkey", "slicense"];

mod repl;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "bevy-dlc helper: pack and unpack .dlcpack containers",
    long_about = "Utility for creating, inspecting and extracting bevy-dlc encrypted containers.",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Print version information")]
    Version {
        /// Optional path to a .dlcpack file; when supplied the command will
        /// also report the encrypted-pack version embedded in the file.
        #[arg(value_name = "DLC", help = "Optional .dlcpack path")] 
        dlc: Option<PathBuf>,
    },
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
        /// output path (defaults to <dlc_id>.dlcpack). If the supplied path has no extension it is treated as a directory and the generated file will be written to `<OUT>/<dlc_id>.dlcpack`.
        #[arg(
            short,
            long,
            help = "Destination path for the generated .dlcpack (default: <dlc_id>.dlcpack). If the path has no extension it will be treated as a directory.",
            value_name = "OUT"
        )]
        out: Option<PathBuf>,
        /// Product identifier to embed in the private key
        #[arg(
            short,
            long,
            help = "Product identifier to embed in the signed private key",
            long_help = "Embeds a product identifier in the private key. Tokens must include a matching product value to be accepted. Use this to restrict tokens to a specific game or application.",
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
        about = "List contents of a .dlcpack (prints entries/metadata)",
        long_about = "Display detailed metadata for the entries inside a .dlcpack. If given a directory, lists all .dlcpack files inside."
    )]
    List {
        /// path to a .dlcpack file (or directory)
        #[arg(
            value_name = "DLC",
            help = "Path to a .dlcpack file, or a directory containing .dlcpack files (recursive)"
        )]
        dlc: PathBuf,
    },

    /// Validate a `.dlcpack` against a signed license / public key.
    /// If the license carries an embedded `encrypt_key `, the command will
    /// attempt to decrypt the container and report success or the failure
    /// reason (useful for CI or debugging packaging tokens).
    Validate {
        /// path to a .dlcpack file
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
        about = "Generate a product .slicense and .pubkey.",
        long_about = "Create a signed-license token and write <product>.slicense and <product>.pubkey; these files are used as defaults by other commands when present."
    )]
    Generate {
        /// Product name to bind the license to (also used to name the output files)
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
        /// Optionally emit a random 32-byte AES key (base64url/hex). Use `--aes-key` to print the key.
        #[arg(
            long = "aes-key",
            help = "Print a random 32-byte AES key (base64url) for use with secure crate"
        )]
        aes_key: bool,
    },

    #[command(
        about = "Interactive REPL to edit an existing .dlcpack metadata",
        long_about = "Modify the manifest of an existing .dlcpack (change types, remove entries) without re-encrypting the content. If a key/license is provided, you can also add new files."
    )]
    Edit {
        /// path to a .dlcpack file
        #[arg(value_name = "DLC")]
        dlc: PathBuf,
        /// Optional SignedLicense token to unlock re-encryption (for 'add' command)
        #[arg(short, long = "signed-license", value_name = "SIGNED_LICENSE")]
        signed_license: Option<String>,
        /// Optional public key (base64url or file) used to verify the signed license
        #[arg(long = "pubkey", value_name = "PUBKEY")]
        pubkey: Option<String>,
        /// Optional product name (used to find .slicense/.pubkey defaults)
        #[arg(short, long, value_name = "PRODUCT")]
        product: Option<String>,
    },
    #[command(about = "Find a .dlcpack file with specified DLC id in a directory", long_about = "Search for .dlcpack files in a directory (recursively) for a matching DLC id in their manifest. This is useful for locating files when you only have the DLC id and not the filename.")]
    Find {
        /// DLC id to search for in .dlcpack files
        #[arg(value_name = "DLC_ID")]
        dlc_id: String,
        /// Directory to search for .dlcpack files (recursive)
        #[arg(value_name = "DIR")]
        dir: PathBuf,
        /// Max depth for recursive search (default: 5)
        #[arg(short = 'd', long, default_value_t = 5)]
        max_depth: usize,
    }
}

/// Recursively collect files under `dir`. If `ext_filter` is Some(ext), only
/// files matching that extension are returned.
fn collect_files_recursive(
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
    ext_filter: Option<&str>,
    max_depth: usize,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            // Skip hidden directories and common build/dependency artifacts to avoid searching too much
            if name_str.starts_with('.') {
                continue;
            }
            if max_depth > 0 {
                collect_files_recursive(&path, out, ext_filter, max_depth - 1)?;
            }
        } else if path.is_file() {
            #[cfg(windows)]
            if let Ok(meta) = path.metadata() {
                if meta.file_attributes() & 0x00000002 != 0 {
                    // Skip hidden files
                    continue;
                }
            }

            // Skip hidden files
            if name_str.starts_with('.') {
                continue;
            }
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

/// Print signed license and public-key information, and optionally write
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
    println!("{}:\n{}", "SIGNED LICENSE".green().bold(), signedlicense);

    let pubkey_b64 = URL_SAFE_NO_PAD.encode(dlc_key.get_public_key().get());
    println!("{}: {}", "PUB KEY".blue().bold(), pubkey_b64);

    if write_files {
        if let Some(prod) = product {
            let slicense_path = format!("{}.slicense", prod);
            let pubkey_path = format!("{}.pubkey", prod);
            if let Err(e) = std::fs::write(&slicense_path, signedlicense) {
                print_error(&format!("failed to write {}: {}", slicense_path, e));
            }
            if let Err(e) = std::fs::write(&pubkey_path, pubkey_b64) {
                print_error(&format!("failed to write {}: {}", pubkey_path, e));
            }
        } else {
            print_warning("no product name supplied; skipping file write");
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

fn print_pack_entries(version: usize, ents: &[(String, bevy_dlc::EncryptedAsset)]) {
    if version >= 2 {
        if let Some((_, first_enc)) = ents.first() {
            println!(
                " ciphertext_len={} nonce={}",
                first_enc.ciphertext.len(),
                hex::encode(first_enc.nonce)
            );
        }
        for (p, enc) in ents.iter() {
            println!(
                " - {} (ext={}) type={}",
                p,
                enc.original_extension,
                enc.type_path.clone().unwrap_or("None".to_string())
            );
        }
    } else {
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
    }
}

/// Helper: Resolve pubkey and signed license from CLI args or defaults files
fn resolve_pubkey_and_license(
    pubkey: Option<String>,
    signed_license: Option<String>,
    product: &str,
) -> (Option<String>, Option<String>) {
    // Priority: explicit CLI args → product files in CWD → product files anywhere under CWD (recursive)

    // Helper to search recursively for a product file with given extension
    fn find_product_file_recursive(product: &str, ext: &str) -> Option<String> {
        let file_name = format!("{}.{}", product, ext);
        // check CWD first
        if std::path::Path::new(&file_name).exists() {
            return std::fs::read_to_string(&file_name)
                .ok()
                .map(|s| s.trim().to_string());
        }
        // recurse and look for matching filename
        let mut matches = Vec::new();
        if collect_files_recursive(std::path::Path::new("."), &mut matches, Some(ext), 3).is_ok() {
            for p in matches {
                if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                    if fname.eq_ignore_ascii_case(&file_name) {
                        return std::fs::read_to_string(&p)
                            .ok()
                            .map(|s| s.trim().to_string());
                    }
                }
            }
        }
        None
    }

    let resolved_pubkey = pubkey.or_else(|| find_product_file_recursive(product, "pubkey"));
    let resolved_license =
        signed_license.or_else(|| find_product_file_recursive(product, "slicense"));

    (resolved_pubkey, resolved_license)
}

/// Helper: Derive encryption key from signed license or generate new one
fn derive_encrypt_key(
    signed_license: Option<&str>,
) -> Result<EncryptionKey, Box<dyn std::error::Error>> {
    Ok(if let Some(lic_str) = signed_license {
        if let Some(enc_key) = bevy_dlc::extract_encrypt_key_from_license(
            &bevy_dlc::SignedLicense::from(lic_str.to_string()),
        ) {
            enc_key
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

            // If the dlc_id is not in the license, try to extend it
            let final_license = if !verified.dlcs.iter().any(|d| d == &dlc_id_str) {
                if let Some(dlc_key) = signer_key {
                    // Extend the supplied license with the new dlc_id
                    let extended = dlc_key.extend_signed_license(
                        &SignedLicense::from(sup_license.to_string()),
                        &[DlcId::from(dlc_id_str.to_string())],
                        Product::from(product.to_string()),
                    )?;
                    println!("{}", "note: supplied license did not include requested DLC id, extending it now.".yellow());
                    extended
                } else {
                    return Err("supplied signed-license does not include the requested DLC id (and no private key available to extend it)".into());
                }
            } else {
                SignedLicense::from(sup_license.to_string())
            };

            final_license.with_secret(|s| {
                println!("{}:\n{}", "SIGNED LICENSE".green().bold(), s);
                println!("{}: {}", "PUB KEY".blue().bold(), pubkey_str);
            });
        } else {
            print_warning("supplied signed-license not verified (no --pubkey supplied)");

            // Check if we can extend with the new dlc_id
            let dlc_ids_in_existing =
                extract_dlc_ids_from_license(&SignedLicense::from(sup_license.to_string()));
            let final_license = if !dlc_ids_in_existing.iter().any(|d| d == dlc_id_str) {
                if let Some(dlc_key) = signer_key {
                    // Extend the supplied license with the new dlc_id
                    let extended = dlc_key.extend_signed_license(
                        &SignedLicense::from(sup_license.to_string()),
                        &[DlcId::from(dlc_id_str.to_string())],
                        Product::from(product.to_string()),
                    )?;
                    println!(
                        "{}",
                        "note: existing license did not include requested DLC id, extended with it"
                            .yellow()
                    );
                    extended
                } else {
                    print_warning(&format!(
                        "existing license does not include DLC id '{}' (no private key available to extend)",
                        dlc_id_str
                    ));
                    SignedLicense::from(sup_license.to_string())
                }
            } else {
                SignedLicense::from(sup_license.to_string())
            };

            final_license.with_secret(|s| println!("{}:\n{}", "SIGNED LICENSE:".green().bold(), s));
        }
    } else {
        // Use the provided signer key (the key that signed the pack) when available
        if let Some(dlc_key) = signer_key {
            let signedlicense = dlc_key.create_signed_license(
                &[DlcId::from(dlc_id_str.to_string())],
                Product::from(product.to_string()),
            )?;
            signedlicense.with_secret(|s| {
                print_signed_license_and_pubkey(s.as_str(), dlc_key, false, Some(product))
            });
        } else {
            let dlc_key = DlcKey::generate_random();
            let signedlicense = dlc_key.create_signed_license(
                &[DlcId::from(dlc_id_str.to_string())],
                Product::from(product.to_string()),
            )?;
            signedlicense.with_secret(|s| {
                print_signed_license_and_pubkey(s.as_str(), &dlc_key, true, Some(product))
            });
        }
    }
    Ok(())
}

/// Helper: Resolve pubkey/license for Validate, with fallback to embedded product
fn resolve_keys(
    pubkey: Option<String>,
    signed_license: Option<String>,
    product: Option<String>,
    embedded_product: Option<String>,
) -> (Option<String>, Option<String>) {
    // Priority: explicit args → product/embedded_product files in CWD → recursive search for product files

    fn find_product_file_recursive_opt(name: &str, ext: &str) -> Option<String> {
        let file_name = format!("{}.{}", name, ext);
        if std::path::Path::new(&file_name).exists() {
            return std::fs::read_to_string(&file_name)
                .ok()
                .map(|s| s.trim().to_string());
        }
        let mut matches = Vec::new();
        if collect_files_recursive(std::path::Path::new("."), &mut matches, Some(ext), 3).is_ok() {
            for p in matches {
                if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                    if fname.eq_ignore_ascii_case(&file_name) {
                        return std::fs::read_to_string(&p)
                            .ok()
                            .map(|s| s.trim().to_string());
                    }
                }
            }
        }
        None
    }

    let resolved_pubkey = pubkey.or_else(|| {
        // try product / embedded_product first
        if let Some(prod) = product.as_ref().or_else(|| embedded_product.as_ref()) {
            if let Some(found) = find_product_file_recursive_opt(prod, "pubkey") {
                return Some(found);
            }
        }
        None
    });

    let resolved_license = signed_license.or_else(|| {
        if let Some(prod) = product.as_ref().or_else(|| embedded_product.as_ref()) {
            if let Some(found) = find_product_file_recursive_opt(prod, "slicense") {
                return Some(found);
            }
        }
        None
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

fn print_error(message: &str) {
    eprintln!("{}: {}", "error".red().bold(), message.white());
}

fn print_warning(message: &str) {
    eprintln!("{}: {}", "warning".yellow().bold(), message.white());
}

fn print_error_and_exit(message: &str) -> ! {
    print_error(message);
    std::process::exit(1);
}

// Helper: attempt to decrypt the first archive entry using the provided symmetric key.
// Returns Ok(()) on success; Err(...) on any failure (decryption or archive extraction).
fn test_decrypt_archive_with_key(
    dlc_pack_file: &str,
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
                        println!("{} -> {}", "GOOD".green().bold(), dlc_pack_file);
                    } else {
                        println!(
                            "{} -> {}\n{}",
                            "OKAY:".yellow().bold(),
                            dlc_pack_file,
                            ".dlcpack archive decrypts with embedded encrypt key (signature NOT verified).\nTry providing the corresponding public key and signed license to verify the signature."
                        );
                    }
                    Ok(())
                }
                Err(e) => Err(format!("(archive extract): {}", e).into()),
            }
        }
        Err(e) => Err(format!("{}", e).into()),
    }
}

fn validate_dlc_file(
    path: &std::path::Path,
    product_arg: Option<&str>,
    signed_license_arg: Option<&str>,
    pubkey_arg: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // read container bytes
    let bytes = std::fs::read(path)?;

    // Parse and get embedded product/dlc id
    let (prod, dlc_id, _v, _ents) = parse_encrypted_pack(&bytes)?;
    let embedded_product = Some(prod.to_string());

    // resolve pubkey and signed license with fallback to embedded product (recursively)
    let (supplied_pubkey, supplied_license) = resolve_keys(
        pubkey_arg.map(|s| s.to_string()),
        signed_license_arg.map(|s| s.to_string()),
        product_arg.map(|s| s.to_string()),
        embedded_product,
    );

    // Verify signature if pubkey provided
    if let Some(pk) = supplied_pubkey.as_deref() {
        match bevy_dlc::verify_pack_signature(&bytes, pk, DLC_PACK_VERSION) {
            Ok(true) => {}
            Ok(false) => {
                return Err("Pack signature verification failed, invalid signature".into());
            }
            Err(e) => return Err(format!("Pack signature verfication failed, {}", e).into()),
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
            test_decrypt_archive_with_key(
                path.to_str().unwrap(),
                &bytes,
                &key_bytes,
                supplied_pubkey.is_some(),
            )?;
        }
        Ok(None) => {
            if supplied_pubkey.is_some() {
                print_warning(
                    "License verified but does not carry an embedded encrypt key — cannot test decrypt",
                );
            } else {
                print_warning("Token payload does not contain an encrypt key; cannot test decrypt");
            }
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

/// Helper: search for a .dlcpack file with the specified dlc_id under root_path (recursive, up to depth)
fn find_dlcpack(root_path: &Path, dlc_id: impl Into<DlcId>, depth: Option<usize>) -> Result<(PathBuf, usize, DlcPack), Box<dyn std::error::Error>> {
    let dlc_id = dlc_id.into();
    let mut candidates: Vec<PathBuf> = Vec::new();
    collect_files_recursive(root_path, &mut candidates, Some("dlcpack"), depth.unwrap_or(5))?;
    let mut best_match: Option<(PathBuf, usize, DlcPack)> = None;
    for p in candidates {
        let bytes = std::fs::read(&p)?;
        let (_prod, did, version, ents) = parse_encrypted_pack(&bytes)?;
        let did = DlcId::from(did);
        // if dlc_id is not an exact match, skip
        if did != dlc_id {
            continue;
        }
        
        let pack = DlcPack::from((did,ents));
        best_match = Some((p, version, pack));
        break;
    }
    if let Some(matched) = best_match {
        Ok(matched)
    } else {
        Err(format!("no .dlcpack found with dlc_id '{}'", dlc_id).into())
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
            collect_files_recursive(entry, &mut selected_files, None, 10)?;
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
    let type_path_map = resolve_type_paths_from_bevy(app, &selected_files, &type_overrides).await?;

    let mut items: Vec<PackItem> = Vec::new();
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
        let filename = file.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let mut item = PackItem::new(filename.to_string(), bytes.clone());
        if let Some(ext) = file.extension().and_then(|e| e.to_str()) {
            item = item.with_extension(ext);
        }
        if let Some(tp) = type_path_map.get(file) {
            item = item.with_type_path(tp.clone());
        }
        items.push(item);

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
        let mut item = PackItem::new(rel.clone(), bytes.clone());
        if let Some(e) = ext {
            item = item.with_extension(e);
        }
        if let Some(tp) = type_path {
            item = item.with_type_path(tp);
        }
        items.push(item);
    }

    let dlc_id = DlcId::from(dlc_id_str.clone());
    // Generate a new signing key for the pack. The private seed is never embedded
    // in the signed license for security reasons - only the symmetric encryption key is.
    let dlc_key = if let Some(pk) = pubkey.as_deref() {
        match DlcKey::public(pk) {
            Ok(k) => k,
            Err(_) => DlcKey::generate_random(),
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
        let (_prod, did, version, ents) = parse_encrypted_pack(&container)?;
        println!("{} {} entries: {}", "dlc_id".blue(), did, ents.len());
        print_pack_entries(version, &ents);
    }

    let out_path = if let Some(out_val) = out {
        let path = PathBuf::from(&out_val);
        if path.exists() && path.is_dir() {
            // explicit existing directory
            path.join(format!("{}.dlcpack", dlc_id_str))
        } else if path.extension().is_some() {
            // path *looks like* a file (has an extension) — treat as file path
            path
        } else {
            // no extension: treat as directory (create it if necessary)
            if !path.exists() {
                std::fs::create_dir_all(&path)?;
            }
            path.join(format!("{}.dlcpack", dlc_id_str))
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
        Commands::Version { dlc } => {
            // package name & version
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            if let Some(path) = dlc {
                match std::fs::read(&path) {
                    Ok(bytes) => match parse_encrypted_pack(&bytes) {
                        Ok((_prod, did, version, _ents)) => {
                            println!(
                                "{} -> {} (pack v{})",
                                path.display(),
                                did.as_str(),
                                version
                            );
                        }
                        Err(e) => {
                            print_error(&format!(
                                "failed to parse dlcpack '{}': {}",
                                path.display(), e
                            ));
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        print_error(&format!(
                            "error reading '{}': {}",
                            path.display(), e
                        ));
                        std::process::exit(1);
                    }
                }
            }
            return Ok(());
        }
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
                collect_files_recursive(&dlc, &mut files, Some("dlcpack"), 10)?;
                if files.is_empty() {
                    return Err("no .dlcpack files found in directory".into());
                }
                for file in &files {
                    let bytes = std::fs::read(file)?;
                    let (_prod, did, version, ents) = parse_encrypted_pack(&bytes)?;
                    println!(
                        "{} -> {} {} (v{}) entries: {}",
                        "dlcpack:".color(AnsiColors::Blue),
                         did.as_str().color(AnsiColors::Magenta).bold(),
                        file.display(),
                        version,
                        ents.len()
                    );
                    print_pack_entries(version, &ents);
                }
                return Ok(());
            }

            // single-file mode
            let bytes = std::fs::read(&dlc)?;
            let (_prod, did, version, ents) = parse_encrypted_pack(&bytes)?;
            println!(
                "{} {} (v{}) entries: {}",
                "dlcpack".color(AnsiColors::Blue),
                did.as_str().color(AnsiColors::Magenta).bold(),
                version,
                ents.len()
            );
            print_pack_entries(version, &ents);
            return Ok(());
        }

        Commands::Validate {
            dlc,
            product,
            signed_license,
            pubkey,
        } => {
            // directory mode: validate every .dlcpack inside recursively
            if dlc.is_dir() {
                let mut files = Vec::new();
                collect_files_recursive(&dlc, &mut files, Some("dlcpack"), 10)?;
                if files.is_empty() {
                    print_error_and_exit("no .dlcpack files found in directory");
                }

                let mut failures = 0usize;
                for file in &files {
                    match validate_dlc_file(
                        file.as_path(),
                        product.as_deref(),
                        signed_license.as_deref(),
                        pubkey.as_deref(),
                    ) {
                        Ok(()) => {}
                        Err(e) => {
                            print_error(&format!("{}: {}", file.display(), e));
                            failures += 1;
                        }
                    }
                }

                if failures > 0 {
                    print_error_and_exit(&format!("{} file(s) failed validation", failures));
                }
                return Ok(());
            }

            // single-file mode
            match validate_dlc_file(
                &dlc,
                product.as_deref(),
                signed_license.as_deref(),
                pubkey.as_deref(),
            ) {
                Ok(()) => return Ok(()),
                Err(e) => print_error_and_exit(&e.to_string()),
            }
        }

        Commands::Generate {
            product,
            dlcs,
            out_dir,
            force,
            aes_key,
        } => {
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
                    print_error_and_exit(
                        format!(
                            "'{}' or '{}' already exists; use {} to overwrite",
                            slicense_path.display(),
                            pubkey_path.display(),
                            "--force".color(AnsiColors::Magenta).bold()
                        )
                        .as_str(),
                    );
                }
            }

            // print token + pubkey to stdout and write <product>.slicense / <product>.pubkey
            signedlicense.with_secret(|s| {
                print_signed_license_and_pubkey(s.as_str(), &dlc_key, true, Some(product.as_str()))
            });

            // optionally emit a random 32-byte AES key (base64url)
            if aes_key {
                let ek = EncryptionKey::from_random(32);
                ek.with_secret(|kb| {
                    println!(
                        "{} {}",
                        "AES KEY (base64url):".color(AnsiColors::Cyan).bold(),
                        URL_SAFE_NO_PAD.encode(kb)
                    );
                });
            }

            println!(
                "Wrote {} and {}",
                slicense_path.display(),
                pubkey_path.display()
            );
            return Ok(());
        }
        Commands::Edit {
            dlc,
            signed_license,
            pubkey,
            product,
        } => {
            // read container bytes to get embedded product/dlc id
            let bytes = std::fs::read(&dlc)?;
            let (emb_prod, _emb_did, _v, _ents) = parse_encrypted_pack(&bytes)?;
            
            // resolve pubkey and signed license with fallback to embedded product
            let (_, sup_lic) = resolve_keys(
                pubkey,
                signed_license,
                product,
                Some(emb_prod),
            );

            // extract the encryption key from the license if present
            let encrypt_key = if let Some(lic) = sup_lic.as_deref() {
                extract_encrypt_key_from_token(lic).ok().flatten()
            } else {
                None
            }.map(|k| EncryptionKey::from(k));

            repl::run_edit_repl(dlc, encrypt_key)?;
        },
        Commands::Find { dlc_id, dir, max_depth } =>{
            match find_dlcpack(&dir, dlc_id.clone(), Some(max_depth)) {
                Ok((path, _version, _pack)) => {
                    println!("Found .dlcpack at: {}", path.display().bold());
                },
                Err(e) => {
                    print_error(&format!("No .dlcpack found with dlc_id '{}': {}", dlc_id, e));
                }
            }
        }
    }

    Ok(())
}
