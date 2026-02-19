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
use hex::FromHex;

use bevy_dlc::{
    DLC_ASSET_MAGIC, DLC_PACK_MAGIC, EncryptionKey, pack_encrypted_asset, pack_encrypted_pack,
    parse_encrypted, parse_encrypted_pack, prelude::*,
};
use secure_gate::ExposeSecret;

const FORBIDDEN_EXTENSIONS: [&str; 4] = ["dlc", "dlcpack", "pubkey", "slicense"];

#[derive(Parser)]
#[command(
    author,
    version,
    about = "bevy-dlc helper: pack and unpack .dlc containers",
    long_about = "Utility for creating, inspecting and extracting bevy-dlc encrypted containers.\n\nPACK: encrypt an input asset and emit a .dlc container and print a symmetric encrypt key.\nUNPACK: inspect or decrypt a container using a symmetric encrypt key supplied via --encrypt-key."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Pack an input asset into a .dlc container (writes .dlc, prints private key + pub key)",
        long_about = "Encrypts the provided input file into the bevy-dlc container format and prints a signed private key and public key. Use --list to preview container metadata without writing files."
    )]
    Pack {
        /// DLC identifier to embed in the container/private key
        #[arg(
            help = "Identifier embedded into the container and private key (e.g. expansion_1)",
            value_name = "DLC_ID"
        )]
        dlc_id: String,
        /// Create a single `.dlcpack` bundle instead of individual `.dlc` files
        #[arg(
            long,
            help = "Bundle all files into a single .dlcpack container (encrypts each entry with the same encrypt key)"
        )]
        pack: bool,
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
        /// output path (defaults to <input>.dlc or <input>.dlcpack when `--pack`)
        #[arg(
            short,
            long,
            help = "Destination path for the generated file (default: <input>.dlc or .dlcpack when --pack)",
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
        /// Optionally emit a random 32-byte AES encrypt key (base64url/hex)
        #[arg(
            long = "emit-encrypt-key",
            help = "Also print a random 32-byte AES encrypt key (base64url) for use with secure crate"
        )]
        emit_encrypt_key: bool,
    },

    #[command(
        about = "Inspect or decrypt a .dlc container",
        long_about = "Read a bevy-dlc container and optionally decrypt it using a symmetric encrypt key supplied via --encrypt-key. Use --list to display container metadata without extracting the asset."
    )]
    Unpack {
        /// path to the .dlc container file or a directory containing .dlc files
        #[arg(
            help = "Path to a .dlc file or a directory containing .dlc files (recursive)",
            value_name = "DLC"
        )]
        dlc: PathBuf,
        /// print container metadata instead of unpacking
        #[arg(
            short,
            long,
            help = "Show metadata (dlc_id, extension, ciphertext length, nonce) and exit without decrypting."
        )]
        list: bool,
        /// output path for the decrypted asset (defaults to same-stem + original extension)
        #[arg(
            short,
            long,
            help = "Where to write the decrypted asset; defaults to <container-stem>.<original_extension>",
            value_name = "OUT"
        )]
        out: Option<PathBuf>,
        /// symmetric encrypt key (hex or base64url, 32 bytes)
        #[arg(
            long,
            help = "Symmetric encrypt key used to decrypt the container (hex or base64url)."
        )]
        encrypt_key: Option<String>,
    },
}

fn read_pubkey_bytes(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::path::Path;

    // If `s` is a path to an existing file, prefer reading the file.
    if Path::new(s).exists() {
        let data = std::fs::read(s)?;
        // Try to interpret file as UTF-8 containing base64/hex text
        if let Ok(text) = std::str::from_utf8(&data) {
            let trimmed = text.trim();
            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(trimmed.as_bytes()) {
                return Ok(decoded);
            }
            if let Some(rest) = trimmed.strip_prefix("0x") {
                return Ok(Vec::from_hex(rest)?);
            }
            if trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(Vec::from_hex(trimmed)?);
            }
        }
        // Fallback: accept raw 32-byte public key file
        if data.len() == 32 {
            return Ok(data);
        }
        return Err("could not decode public key file as base64, hex, or raw 32 bytes".into());
    }

    // Otherwise treat `s` as a base64url-encoded public key string.
    Ok(URL_SAFE_NO_PAD.decode(s.as_bytes())?)
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

/// Print `SignedLicense` and public-key information.
///
/// - Prints the compact `SignedLicense` token (format: `payload_base64url.signature_base64url`).
/// - DOES NOT print private seeds or raw symmetric keys; treat the token as
///   sensitive and provision it securely.
fn print_signed_license_and_pubkey(signedlicense: &str, dlc_key: &DlcKey) {
    println!("SIGNED LICENSE:\n{}", signedlicense);

    println!(
        "PUB KEY: {}",
        URL_SAFE_NO_PAD.encode(dlc_key.get_public_key().get())
    );
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

        // per-extension deadline — give Bevy a short window to register loaders
        const DEADLINE_MS: u64 = 2000;

        for ext in &extensions_to_query {
            // run one frame so plugins/systems can perform registrations
            app.update();

            match tokio::time::timeout(
                std::time::Duration::from_millis(DEADLINE_MS),
                asset_server.get_asset_loader_with_extension(ext),
            )
            .await
            {
                Ok(Ok(loader)) => {
                    let type_name = loader.asset_type_name();
                    ext_map.insert(ext.clone(), type_name.to_string());
                }
                Ok(Err(_)) => {
                    return Err(format!(
                        "no AssetLoader registered for extension '{}'; either add the plugin that provides the loader or pass --types {}=TypePath",
                        ext, ext
                    ).into());
                }
                Err(_) => {
                    return Err(format!(
                        "timed out waiting for AssetServer loader for extension '{}' ({}ms); try `--types {}` or increase warm-up",
                        ext, DEADLINE_MS, ext
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
            pack,
            files,
            list,
            out,
            product,
            types,
            pubkey,
            signed_license,
        } => {
            // If product-named helper files exist, prefer them unless the
            // explicit CLI args `--pubkey` / `--signed-license` were supplied.
            let default_pubkey_file = format!("{}.pubkey", product);
            let default_slicense_file = format!("{}.slicense", product);
            let pubkey = pubkey.or_else(|| {
                if std::path::Path::new(&default_pubkey_file).exists() {
                    std::fs::read_to_string(&default_pubkey_file)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            });
            let signed_license = signed_license.or_else(|| {
                if std::path::Path::new(&default_slicense_file).exists() {
                    std::fs::read_to_string(&default_slicense_file)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            });

            // `.dlcpack` mode: bundle multiple files into one container when
            // `--pack` is specified (accepts a directory or an explicit list
            // of files supplied with `--files`).
            if pack {
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

                // Parse manual type overrides
                let type_overrides = types
                    .as_ref()
                    .map(|t| parse_type_overrides(t))
                    .unwrap_or_default();

                // Resolve type paths using Bevy's AssetServer (STRICT: fail if AssetServer
                // cannot provide a loader for an extension).
                let type_path_map =
                    resolve_type_paths_from_bevy(&mut app, &selected_files, &type_overrides)
                        .await?;

                // build the in-memory items (relative path, ext, type_path, bytes)
                let mut items: Vec<(String, Option<String>, Option<String>, Vec<u8>)> = Vec::new();
                for file in &selected_files {
                    let mut f = File::open(file)?;
                    let mut bytes = Vec::new();
                    f.read_to_end(&mut bytes)?;

                    // refuse inputs that already look like a BDLC/BDLP container
                    if bytes.len() >= 4
                        && (&bytes[0..4] == DLC_ASSET_MAGIC || &bytes[0..4] == DLC_PACK_MAGIC)
                    {
                        return Err(format!(
                            "refusing to pack '{}' — input appears to be an existing container (BDLC/BDLP)",
                            file.display()
                        )
                        .into());
                    }

                    // compute relative path: prefer directory-relative when possible
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
                // For Approach A: DLC packs are self-signed with the product key.
                // Generate or use a provided key. If a signed-license contains an encrypt_key, we extract it.

                let dlc_key = if let Some(_) = signed_license.as_deref() {
                    if let Some(_) = pubkey.as_deref() {
                        // If both license and pubkey provided, verify (but we still need privkey to sign)
                        // For now, generate a new one - in practice, the platform would provide the private key
                        DlcKey::generate_random()
                    } else {
                        // generate new key for signing
                        DlcKey::generate_random()
                    }
                } else {
                    DlcKey::generate_random()
                };

                let encrypt_key = if let Some(lic_str) = signed_license.as_deref() {
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
                };

                let container = pack_encrypted_pack(
                    &dlc_id,
                    &items,
                    &Product::from(product.clone()),
                    &dlc_key,
                    &encrypt_key,
                )?;

                // Determine signed license / pubkey to emit. Prefer a supplied
                // `--signed-license` (optionally verified with `--pubkey`). If no
                // license was supplied, generate a new keypair + token as before.
                if let Some(sup_license) = signed_license.as_deref() {
                    if let Some(pubkey_str) = pubkey.as_deref() {
                        // verify supplied token with provided pubkey
                        let verifier = DlcKey::public(pubkey_str)
                            .map_err(|e| format!("invalid provided pubkey: {:?}", e))?;
                        let verified = verifier
                            .verify_signed_license(&SignedLicense::from(sup_license.to_string()))
                            .map_err(|e| {
                                format!("supplied signed-license verification failed: {:?}", e)
                            })?;
                        // product + dlc id sanity checks
                        if verified.product != product {
                            return Err(
                                "supplied signed-license product does not match --product".into()
                            );
                        }
                        if !verified.dlcs.iter().any(|d| d == &dlc_id_str) {
                            return Err(
                                "supplied signed-license does not include the requested DLC id"
                                    .into(),
                            );
                        }

                        println!("SIGNED LICENSE:\n{}", sup_license);
                        println!("PUB KEY: {}", pubkey_str);
                    } else {
                        eprintln!(
                            "warning: supplied signed-license not verified (no --pubkey supplied)"
                        );
                        println!("SIGNED LICENSE:\n{}", sup_license);
                    }
                } else {
                    // create signed token for logical gating (dlcs/product).
                    let dlc_key = DlcKey::generate_random();
                    let signedlicense =
                        dlc_key.create_signed_license(&[dlc_id], Product::from(product.clone()))?;

                    signedlicense
                        .with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key));
                }

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
                    // continue and still emit the generated file + private key below
                }

                let out_path =
                    out.unwrap_or_else(|| PathBuf::from(format!("{}.dlcpack", dlc_id_str)));
                std::fs::write(&out_path, &container)?;

                println!("created dlcpack: {}", out_path.display());

                return Ok(());
            }

            // directory mode: if the user supplied exactly one directory as the input
            // entry and `--pack` was not used, create individual .dlc files preserving
            // directory-relative paths.
            if !pack && files.len() == 1 && files[0].is_dir() {
                let mut input_files = Vec::new();
                collect_files_recursive(&files[0], &mut input_files, None)?;
                if input_files.is_empty() {
                    return Err("no files found in input directory".into());
                }

                let out_dir = out.unwrap_or_else(|| PathBuf::from("generated"));
                if out_dir.exists() && !out_dir.is_dir() {
                    return Err("output path must be a directory when packing a directory".into());
                }
                std::fs::create_dir_all(&out_dir)?;

                let dlc_id = DlcId::from(dlc_id_str.clone());
                let encrypt_key = if let Some(lic_str) = signed_license.as_deref() {
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
                };

                for file in &input_files {
                    let mut f = File::open(file)?;
                    let mut bytes = Vec::new();
                    f.read_to_end(&mut bytes)?;

                    let rel = file.strip_prefix(&files[0]).unwrap();
                    let ext = file.extension().and_then(|s| s.to_str()).unwrap_or("");
                    let (container, _nonce) = pack_encrypted_asset(
                        &bytes,
                        &dlc_id,
                        if ext.is_empty() { None } else { Some(ext) },
                        None,
                        &encrypt_key,
                    )?;

                    let mut out_path = out_dir.join(rel);
                    out_path.set_extension("dlc");
                    if let Some(parent) = out_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&out_path, &container)?;
                    println!("created encrypted asset: {}", out_path.display());
                }

                // emit signed license / pubkey as before
                if let Some(sup_license) = signed_license.as_deref() {
                    if let Some(pubkey_str) = pubkey.as_deref() {
                        let verifier = DlcKey::public(pubkey_str)
                            .map_err(|e| format!("invalid provided pubkey: {:?}", e))?;
                        let verified = verifier
                            .verify_signed_license(&SignedLicense::from(sup_license.to_string()))
                            .map_err(|e| {
                                format!("supplied signed-license verification failed: {:?}", e)
                            })?;
                        if verified.product != product {
                            return Err(
                                "supplied signed-license product does not match --product".into()
                            );
                        }
                        if !verified.dlcs.iter().any(|d| d == &dlc_id_str) {
                            return Err(
                                "supplied signed-license does not include the requested DLC id"
                                    .into(),
                            );
                        }
                        println!("SIGNED LICENSE:\n{}", sup_license);
                        println!("PUB KEY: {}", pubkey_str);
                    } else {
                        eprintln!(
                            "warning: supplied signed-license not verified (no --pubkey supplied)"
                        );
                        println!("SIGNED LICENSE:\n{}", sup_license);
                    }
                } else {
                    let dlc_key = DlcKey::generate_random();
                    let signedlicense = dlc_key.create_signed_license(
                        &[DlcId::from(dlc_id_str.clone())],
                        Product::from(product.clone()),
                    )?;
                    println!(
                        "created {} encrypted assets to {}",
                        input_files.len(),
                        out_dir.display()
                    );
                    signedlicense
                        .with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key));
                }

                return Ok(());
            }

            // Non-pack modes: support single-file or multiple-files input via `--files`.
            // When the user supplied exactly one file, produce a single .dlc; when a
            // single directory was supplied we already handled directory mode above; when
            // multiple files are supplied pack each into its own .dlc under `out`.
            if !pack {
                // expand input_entries into explicit_files
                let mut explicit_files: Vec<PathBuf> = Vec::new();
                for entry in &files {
                    if entry.is_dir() {
                        // directories were handled above; still allow packing multiple dirs/files
                        collect_files_recursive(entry, &mut explicit_files, None)?;
                    } else if entry.is_file() {
                        explicit_files.push(entry.clone());
                    } else {
                        return Err(format!("input path not found: {}", entry.display()).into());
                    }
                }

                if explicit_files.is_empty() {
                    return Err("no input files provided".into());
                }

                // single-file case
                if explicit_files.len() == 1 {
                    let input_file = &explicit_files[0];
                    let mut f = File::open(input_file)?;
                    let mut bytes = Vec::new();
                    f.read_to_end(&mut bytes)?;

                    let ext = input_file
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");

                    let dlc_id = DlcId::from(dlc_id_str.clone());
                    let encrypt_key = if let Some(lic_str) = signed_license.as_deref() {
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
                    };

                    let (container, _nonce) = pack_encrypted_asset(
                        &bytes,
                        &dlc_id,
                        if ext.is_empty() { None } else { Some(ext) },
                        None,
                        &encrypt_key,
                    )?;

                    // signed license / pubkey emission (unchanged)
                    if let Some(sup_license) = signed_license.as_deref() {
                        if let Some(pubkey_str) = pubkey.as_deref() {
                            let verifier = DlcKey::public(pubkey_str)
                                .map_err(|e| format!("invalid provided pubkey: {:?}", e))?;
                            let verified = verifier
                                .verify_signed_license(&SignedLicense::from(
                                    sup_license.to_string(),
                                ))
                                .map_err(|e| {
                                    format!("supplied signed-license verification failed: {:?}", e)
                                })?;
                            if verified.product != product {
                                return Err(
                                    "supplied signed-license product does not match --product"
                                        .into(),
                                );
                            }
                            if !verified.dlcs.iter().any(|d| d == &dlc_id_str) {
                                return Err(
                                    "supplied signed-license does not include the requested DLC id"
                                        .into(),
                                );
                            }
                            println!("SIGNED LICENSE:\n{}", sup_license);
                            println!("PUB KEY: {}", pubkey_str);
                        } else {
                            eprintln!(
                                "warning: supplied signed-license not verified (no --pubkey supplied)"
                            );
                            println!("SIGNED LICENSE:\n{}", sup_license);
                        }
                    } else {
                        let dlc_key = DlcKey::generate_random();
                        let signedlicense = dlc_key.create_signed_license(
                            &[dlc_id.clone()],
                            Product::from(product.clone()),
                        )?;
                        signedlicense
                            .with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key));
                    }

                    if list {
                        let enc = parse_encrypted(&container)?;
                        println!("dlc_id: {}", enc.dlc_id);
                        println!("original_extension: {}", enc.original_extension);
                        println!("ciphertext_len: {}", enc.ciphertext.len());
                        println!("nonce: {}", hex::encode(enc.nonce));
                    }

                    let out_path = out.unwrap_or_else(|| {
                        let mut p = input_file.clone();
                        p.set_extension("dlc");
                        p
                    });
                    std::fs::write(&out_path, &container)?;
                    println!("created encrypted asset: {}", out_path.display());
                    return Ok(());
                }

                // multiple files: write individual .dlc files under `out` (default: generated)
                let out_dir = out.unwrap_or_else(|| PathBuf::from("generated"));
                if out_dir.exists() && !out_dir.is_dir() {
                    return Err(
                        "output path must be a directory when packing multiple files".into(),
                    );
                }
                std::fs::create_dir_all(&out_dir)?;

                let dlc_id = DlcId::from(dlc_id_str.clone());
                let encrypt_key = if let Some(lic_str) = signed_license.as_deref() {
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
                };

                for file in &explicit_files {
                    let mut f = File::open(file)?;
                    let mut bytes = Vec::new();
                    f.read_to_end(&mut bytes)?;

                    // compute relative path (if file is under the single input dir) else use file name
                    let mut rel = file
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("file")
                        .to_string();
                    if files.len() == 1 && files[0].is_dir() && file.starts_with(&files[0]) {
                        rel = file
                            .strip_prefix(&files[0])
                            .unwrap()
                            .to_string_lossy()
                            .to_string();
                    }

                    let ext = file.extension().and_then(|s| s.to_str()).unwrap_or("");
                    let (container, _nonce) = pack_encrypted_asset(
                        &bytes,
                        &dlc_id,
                        if ext.is_empty() { None } else { Some(ext) },
                        None,
                        &encrypt_key,
                    )?;

                    let mut out_path = out_dir.join(rel);
                    out_path.set_extension("dlc");
                    if let Some(parent) = out_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&out_path, &container)?;
                    println!("created encrypted asset: {}", out_path.display());
                }

                // emit signed-license/pubkey as done in directory mode
                if let Some(sup_license) = signed_license.as_deref() {
                    if let Some(pubkey_str) = pubkey.as_deref() {
                        let verifier = DlcKey::public(pubkey_str)
                            .map_err(|e| format!("invalid provided pubkey: {:?}", e))?;
                        let verified = verifier
                            .verify_signed_license(&SignedLicense::from(sup_license.to_string()))
                            .map_err(|e| {
                                format!("supplied signed-license verification failed: {:?}", e)
                            })?;
                        if verified.product != product {
                            return Err(
                                "supplied signed-license product does not match --product".into()
                            );
                        }
                        if !verified.dlcs.iter().any(|d| d == &dlc_id_str) {
                            return Err(
                                "supplied signed-license does not include the requested DLC id"
                                    .into(),
                            );
                        }
                        println!("SIGNED LICENSE:\n{}", sup_license);
                        println!("PUB KEY: {}", pubkey_str);
                    } else {
                        eprintln!(
                            "warning: supplied signed-license not verified (no --pubkey supplied)"
                        );
                        println!("SIGNED LICENSE:\n{}", sup_license);
                    }
                } else {
                    let dlc_key = DlcKey::generate_random();
                    let signedlicense = dlc_key
                        .create_signed_license(&[dlc_id.clone()], Product::from(product.clone()))?;
                    signedlicense
                        .with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key));
                }

                return Ok(());
            }
        }

        Commands::List { dlc } => {
            if dlc.is_dir() {
                let mut files = Vec::new();
                collect_files_recursive(&dlc, &mut files, None)?;
                if files.is_empty() {
                    return Err("no files found in directory".into());
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
                    } else if ext.eq_ignore_ascii_case("dlc") {
                        let bytes = std::fs::read(file)?;
                        let enc = parse_encrypted(&bytes)?;
                        println!(
                            "{} -> dlc: dlc_id={} ext={} ciphertext_len={} nonce={}",
                            file.display(),
                            enc.dlc_id,
                            enc.original_extension,
                            enc.ciphertext.len(),
                            hex::encode(enc.nonce)
                        );
                    }
                }
                return Ok(());
            }

            // single-file mode
            let ext = dlc.extension().and_then(|s| s.to_str()).unwrap_or("");
            let bytes = std::fs::read(&dlc)?;
            if ext.eq_ignore_ascii_case("dlcpack")
                || (bytes.len() >= 4 && bytes.starts_with(DLC_PACK_MAGIC))
            {
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

            if ext.eq_ignore_ascii_case("dlc")
                || (bytes.len() >= 4 && bytes.starts_with(DLC_ASSET_MAGIC))
            {
                let enc = parse_encrypted(&bytes)?;
                println!("dlc_id: {}", enc.dlc_id);
                println!("original_extension: {}", enc.original_extension);
                println!("ciphertext_len: {}", enc.ciphertext.len());
                println!("nonce: {}", hex::encode(enc.nonce));
                return Ok(());
            }

            return Err("not a .dlc or .dlcpack container".into());
        }

        Commands::Validate {
            dlc,
            product,
            signed_license,
            pubkey,
        } => {
            // read container bytes
            let bytes = std::fs::read(&dlc)?;

            // determine dlc id and (for v3 .dlcpack) the embedded product from the container
            let (embedded_product, dlc_id) =
                if bytes.len() >= 4 && bytes.starts_with(DLC_PACK_MAGIC) {
                    let (prod, did, _v, _ents) = parse_encrypted_pack(&bytes)?;
                    (Some(prod), did)
                } else {
                    let enc = parse_encrypted(&bytes)?;
                    (None, enc.dlc_id)
                };

            // resolve pubkey: prefer explicit CLI `--pubkey`, then CLI `--product` files, then embedded pack product (if present)
            let supplied_pubkey = pubkey.or_else(|| {
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

            // For v3 dlcpack, verify the embedded signature if pubkey is available
            if bytes.len() >= 4 && bytes.starts_with(DLC_PACK_MAGIC) {
                if let Some(pk) = supplied_pubkey.as_deref() {
                    match bevy_dlc::verify_pack_signature(&bytes, pk) {
                        Ok(true) => println!("Pack signature verification: SUCCESS"),
                        Ok(false) => {
                            println!("Pack signature verification: FAILED (invalid signature)")
                        }
                        Err(e) => println!("Pack signature verification: ERROR ({})", e),
                    }
                }
            }

            // resolve signed license string (CLI arg takes precedence, then product.slicense or embedded pack product)
            let supplied_license = signed_license.or_else(|| {
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

            if supplied_license.is_none() {
                return Err("no signed license supplied or found (use --signed-license or --product <name> to pick <product>.slicense)".into());
            }
            let supplied_license = supplied_license.unwrap();

            // verify signature if pubkey present
            if let Some(pk) = supplied_pubkey.as_deref() {
                let verifier =
                    DlcKey::public(pk).map_err(|e| format!("invalid pubkey: {:?}", e))?;
                let verified = verifier
                    .verify_signed_license(&SignedLicense::from(supplied_license.clone()))
                    .map_err(|e| format!("signed-license verification failed: {:?}", e))?;

                // check that license covers this DLC id
                if !verified.dlcs.iter().any(|d| d == &dlc_id) {
                    return Err(format!("license does not include DLC id '{}'", dlc_id).into());
                }

                // try to extract embedded encrypt key from the token payload
                // (we've already verified the signature above so it's safe to trust)
                let parts: Vec<&str> = supplied_license.split('.').collect();
                if parts.len() != 2 {
                    return Err("malformed signed-license token".into());
                }
                let payload = URL_SAFE_NO_PAD.decode(parts[0].as_bytes())?;
                let payload_json: serde_json::Value = serde_json::from_slice(&payload)?;
                let ck_b64_opt = payload_json.get("encrypt_key").and_then(|v| v.as_str());
                if let Some(ck_b64) = ck_b64_opt {
                    println!("Found embedded encrypt_key (base64): {}", ck_b64);
                    let key_bytes = URL_SAFE_NO_PAD.decode(ck_b64.as_bytes())?;
                    if key_bytes.len() != 32 {
                        return Err("embedded encrypt key has invalid length".into());
                    }

                    // attempt to decrypt container directly using the embedded symmetric key
                    match std::path::Path::new(&dlc)
                        .extension()
                        .and_then(|s| s.to_str())
                    {
                        Some(ext) if ext.eq_ignore_ascii_case("dlc") => {
                            let enc = parse_encrypted(&bytes)?;
                            match decrypt_with_key_local(&key_bytes, &enc.ciphertext, &enc.nonce) {
                                Ok(_) => println!("Decryption test: SUCCESS!"),
                                Err(e) => println!("Decryption test: FAILURE - {}", e),
                            }
                        }
                        _ => {
                            // dlcpack: try parse_encrypted_pack then decrypt archive or entry(s)
                            let (_prod, _did, _v, entries) = parse_encrypted_pack(&bytes)?;
                            if entries.is_empty() {
                                println!("container has no entries");
                            } else {
                                // version >=2 will use shared archive ciphertext; attempt to decrypt archive
                                let archive_nonce = entries[0].1.nonce;
                                let archive_ciphertext = &entries[0].1.ciphertext;
                                match decrypt_with_key_local(
                                    &key_bytes,
                                    archive_ciphertext,
                                    &archive_nonce,
                                ) {
                                    Ok(plain) => {
                                        // verify gzip/tar is readable
                                        let dec = flate2::read::GzDecoder::new(
                                            std::io::Cursor::new(plain),
                                        );
                                        let mut ar = tar::Archive::new(dec);
                                        match ar.entries() {
                                            Ok(_) => println!("Decryption test: SUCCESS!"),
                                            Err(e) => println!("Decryption test: FAILURE - {}", e),
                                        }
                                    }
                                    Err(e) => println!("Decryption test: FAILURE - {}", e),
                                }
                            }
                        }
                    }
                } else {
                    println!(
                        "License verified but does not carry an embedded encrypt key — cannot test decrypt"
                    );
                }
            } else {
                // no pubkey supplied — attempt to decode the payload and extract encrypt key without verifying signature
                println!(
                    "No pubkey supplied; will attempt to extract encrypt key from token payload without verifying signature (not secure)"
                );
                let parts: Vec<&str> = supplied_license.split('.').collect();
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

                    // test decrypt locally using the helper in this binary
                    match std::path::Path::new(&dlc)
                        .extension()
                        .and_then(|s| s.to_str())
                    {
                        Some(ext) if ext.eq_ignore_ascii_case("dlc") => {
                            let enc = parse_encrypted(&bytes)?;
                            match decrypt_with_key_local(&key_bytes, &enc.ciphertext, &enc.nonce) {
                                Ok(_) => println!(
                                    "SUCCESS: .dlc decrypts with embedded encrypt key (signature NOT verified)"
                                ),
                                Err(e) => println!("DECRYPT FAILURE: {}", e),
                            }
                        }
                        _ => {
                            let (_prod, _did, _v, entries) = parse_encrypted_pack(&bytes)?;
                            if entries.is_empty() {
                                println!("container has no entries");
                            } else {
                                let archive_nonce = entries[0].1.nonce;
                                let archive_ciphertext = &entries[0].1.ciphertext;
                                match decrypt_with_key_local(
                                    &key_bytes,
                                    archive_ciphertext,
                                    &archive_nonce,
                                ) {
                                    Ok(plain) => {
                                        let dec = flate2::read::GzDecoder::new(
                                            std::io::Cursor::new(plain),
                                        );
                                        let mut ar = tar::Archive::new(dec);
                                        match ar.entries() {
                                            Ok(_) => println!(
                                                "SUCCESS: .dlcpack archive decrypts with embedded encrypt key (signature NOT verified)"
                                            ),
                                            Err(e) => {
                                                println!("DECRYPT FAILURE (archive extract): {}", e)
                                            }
                                        }
                                    }
                                    Err(e) => println!("DECRYPT FAILURE: {}", e),
                                }
                            }
                        }
                    }
                } else {
                    println!("Token payload does not contain a  encrypt key ; cannot test decrypt");
                }
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

            // write files
            signedlicense
                .with_secret(|s| std::fs::write(&slicense_path, s).expect("write slicense"));
            std::fs::write(
                &pubkey_path,
                URL_SAFE_NO_PAD.encode(dlc_key.get_public_key().get()),
            )?;

            // print token + pubkey to stdout
            signedlicense.with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key));

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

        Commands::Unpack {
            dlc,
            list,
            out,
            encrypt_key,
        } => {
            // single-file mode (existing behavior)
            let bytes = std::fs::read(&dlc)?;
            let enc = parse_encrypted(&bytes)?;

            if list {
                println!("dlc_id: {}", enc.dlc_id);
                println!("original_extension: {}", enc.original_extension);
                println!("ciphertext_len: {}", enc.ciphertext.len());
                println!("nonce: {}", hex::encode(enc.nonce));
                return Ok(());
            }

            // obtain the symmetric key from the provided --encrypt-key
            let sym_key_vec = match encrypt_key.as_deref() {
                Some(s) => {
                    let bytes = read_pubkey_bytes(s)?;
                    if bytes.len() != 32 {
                        return Err("encrypt key must be 32 bytes".into());
                    }
                    bytes
                }
                None => return Err("missing --encrypt-key".into()),
            };

            let plaintext = decrypt_with_key_local(&sym_key_vec, &enc.ciphertext, &enc.nonce)?;

            let out_path = match out {
                Some(p) => p,
                None => {
                    let stem = dlc
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("decrypted");
                    let ext = enc.original_extension;
                    let filename = format!("{}.{}", stem, ext);
                    dlc.with_file_name(filename)
                }
            };
            std::fs::write(&out_path, &plaintext)?;
            println!("created decrypted asset to {}", out_path.display());
        }
    }

    Ok(())
}
