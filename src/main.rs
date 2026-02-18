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

use bevy_dlc::{ContentKey, DLC_ASSET_MAGIC, DLC_PACK_MAGIC, pack_encrypted_asset, pack_encrypted_pack, parse_encrypted, parse_encrypted_pack, prelude::*};
use secure_gate::ExposeSecret;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "bevy-dlc helper: pack and unpack .dlc containers",
    long_about = "Utility for creating, inspecting and extracting bevy-dlc encrypted containers.\n\nPACK: encrypt an input asset and emit a .dlc container and print a symmetric content key.\nUNPACK: inspect or decrypt a container using a symmetric content key supplied via --content-key."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(
        about = "Pack an input asset into a .dlc container (writes .dlc, prints privatekey + pubkey)",
        long_about = "Encrypts the provided input file into the bevy-dlc container format and prints a signed privatekey and public key. Use --list to preview container metadata without writing files."
    )]
    Pack {
        /// input file or directory to pack
        #[arg(
            help = "Path to an asset file or directory to recursively pack (e.g. assets/texture.png or assets/)",
            value_name = "INPUT"
        )]
        input: PathBuf,
        /// DLC identifier to embed in the container/privatekey
        #[arg(
            help = "Identifier embedded into the container and privatekey (e.g. expansion_1)",
            value_name = "DLC_ID"
        )]
        dlc_id: String,
        /// Create a single `.dlcpack` bundle instead of individual `.dlc` files
        #[arg(
            long,
            help = "Bundle all files into a single .dlcpack container (encrypts each entry with the same content key)"
        )]
        pack: bool,
        /// Supply an explicit list of files to include (overrides directory recursion)
        #[arg(
            long = "files",
            value_name = "FILES...",
            num_args = 1..
        )]
        files: Option<Vec<PathBuf>>,
        /// print container metadata instead of writing
        #[arg(
            short,
            long,
            help = "Show the metadata the container would contain and exit; no file or privatekey will be produced."
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
        /// Product identifier to embed in the privatekey
        #[arg(
            long,
            help = "Product identifier to embed in the signed privatekey",
            long_help = "Embeds a product identifier in the privatekey. When the DlcManager has a product binding set, tokens must include a matching product value to be accepted. Use this to restrict tokens to a specific game or application.",
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
    },

    #[command(
        about = "List contents of a .dlc or .dlcpack (prints entries/metadata)",
        long_about = "Display detailed metadata for a single .dlc file or the entries inside a .dlcpack. If given a directory, lists all .dlc and .dlcpack files inside."
    )]
    List {
        /// path to a .dlc or .dlcpack file (or directory)
        #[arg(value_name = "DLC")]
        dlc: PathBuf,
    },

    #[command(
        about = "Inspect or decrypt a .dlc container",
        long_about = "Read a bevy-dlc container and optionally decrypt it using a symmetric content key supplied via --content-key. Use --list to display container metadata without extracting the asset."
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
        /// symmetric content key (hex or base64url, 32 bytes)
        #[arg(
            long,
            help = "Symmetric content key used to decrypt the container (hex or base64url)."
        )]
        content_key: Option<String>,
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
        URL_SAFE_NO_PAD.encode(dlc_key.public_key_bytes())
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

    eprintln!(
        "[type-resolve] extensions_to_query = {:?}",
        extensions_to_query
    );

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
                    eprintln!(
                        "[type-resolve] ext={} -> type={} (AssetServer)",
                        ext, type_name
                    );
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
            "content key must be 32 bytes (AES-256)",
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
            input,
            dlc_id: dlc_id_str,
            pack,
            files,
            list,
            out,
            product,
            types,
        } => {
            // `.dlcpack` mode: bundle multiple files into one container when
            // `--pack` is specified (accepts a directory or an explicit list
            // of files supplied with `--files`).
            if pack {
                let mut selected_files: Vec<PathBuf> = Vec::new();

                // determine whether the input was explicitly specified by the
                // user (either via `--files` or by passing a single file path).
                let explicit_mode = files.is_some() || input.is_file();

                if let Some(explicit) = files {
                    selected_files.extend(explicit.into_iter());
                } else if input.is_dir() {
                    collect_files_recursive(&input, &mut selected_files, None)?;
                } else if input.is_file() {
                    selected_files.push(input.clone());
                } else {
                    return Err("input path not found".into());
                }

                // exclude already-encrypted `.dlc` files from `.dlcpack` inputs
                // (a dlcpack should contain raw asset files that will be encrypted
                // together under one content key). If the user explicitly provided
                // `.dlc` files treat that as an error — they're not valid
                // inputs for creating a dlcpack.
                let mut skipped_dlc_files: Vec<PathBuf> = Vec::new();
                let mut skipped_container_files: Vec<PathBuf> = Vec::new();
                selected_files.retain(|p| {
                    if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                        if ext.eq_ignore_ascii_case("dlc") {
                            skipped_dlc_files.push(p.clone());
                            return false;
                        }
                        if ext.eq_ignore_ascii_case("dlcpack") {
                            // explicitly refuse .dlcpack inputs
                            skipped_container_files.push(p.clone());
                            return false;
                        }
                    }
                    true
                });

                if !skipped_container_files.is_empty() {
                    return Err(format!(
                        "input contains existing container file(s) — remove the following before creating a .dlcpack: {}",
                        skipped_container_files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                    .into());
                }

                if !skipped_dlc_files.is_empty() {
                    if explicit_mode {
                        return Err(
                            "explicitly-listed .dlc files are not allowed when creating a .dlcpack"
                                .into(),
                        );
                    }
                    eprintln!(
                        "warning: skipping {} .dlc file(s) when creating .dlcpack:",
                        skipped_dlc_files.len()
                    );
                    for p in &skipped_dlc_files {
                        eprintln!(" - {}", p.display());
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

                eprintln!("[pack] resolving types for {} files", selected_files.len());
                // Resolve type paths using Bevy's AssetServer (STRICT: fail if AssetServer
                // cannot provide a loader for an extension).
                let type_path_map =
                    resolve_type_paths_from_bevy(&mut app, &selected_files, &type_overrides)
                        .await?;
                eprintln!("[pack] resolved type map entries={}", type_path_map.len());

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

                    let rel = if input.is_dir() {
                        file.strip_prefix(&input)
                            .unwrap()
                            .to_string_lossy()
                            .to_string()
                    } else {
                        file.file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("file")
                            .to_string()
                    };
                    let ext = file
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string());
                    let type_path = type_path_map.get(file).cloned();
                    items.push((rel, ext, type_path, bytes));
                }

                let dlc_id = DlcId::from(dlc_id_str.clone());
                // generate a random content key for encrypting the whole pack (all entries are encrypted with the same key so one privatekey can unlock the whole pack)
                let content_key = ContentKey::from_random(32);

                let container = pack_encrypted_pack(&dlc_id, &items, &content_key)?;

                // create signed token for logical gating (dlcs/product).
                let dlc_key = DlcKey::generate_random();
                let signedlicense =
                    dlc_key.create_signed_license(&[dlc_id], Product::from(product.clone()))?;

                if list {
                    let (did, _v, ents) = parse_encrypted_pack(&container)?;
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
                    // continue and still emit the generated file + privatekey below
                }

                let out_path = out.unwrap_or_else(|| {
                    if input.is_dir() {
                        PathBuf::from(format!("{}.dlcpack", dlc_id_str))
                    } else {
                        let mut p = input.clone();
                        p.set_extension("dlcpack");
                        p
                    }
                });
                std::fs::write(&out_path, &container)?;

                println!("created dlcpack: {}", out_path.display());
                signedlicense.with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key));

                return Ok(());
            }

            // directory mode: recursively pack all files under `input` into the
            // provided `out` directory (or ./generated if none). A single
            // symmetric content key is used for all files so one privatekey can
            // unlock the whole DLC.
            if input.is_dir() {
                // collect files recursively

                let mut files = Vec::new();
                collect_files_recursive(&input, &mut files, None)?;
                if files.is_empty() {
                    return Err("no files found in input directory".into());
                }

                let out_dir = out.unwrap_or_else(|| PathBuf::from("generated"));
                if out_dir.exists() && !out_dir.is_dir() {
                    return Err("output path must be a directory when packing a directory".into());
                }
                std::fs::create_dir_all(&out_dir)?;

                let dlc_id = DlcId::from(dlc_id_str.clone());
                // generate a random content key for encrypting all files (one privatekey can unlock the whole DLC)
                let content_key = ContentKey::from_random(32);

                for file in &files {
                    let mut f = File::open(file)?;
                    let mut bytes = Vec::new();
                    f.read_to_end(&mut bytes)?;

                    let rel = file.strip_prefix(&input).unwrap();
                    let ext = file.extension().and_then(|s| s.to_str()).unwrap_or("");
                    let (container, _nonce) = pack_encrypted_asset(
                        &bytes,
                        &dlc_id,
                        if ext.is_empty() { None } else { Some(ext) },
                        None,
                        &content_key,
                    )?;

                    let mut out_path = out_dir.join(rel);
                    out_path.set_extension("dlc");
                    if let Some(parent) = out_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&out_path, &container)?;
                    println!("created encrypted asset: {}", out_path.display());
                }

                // single privatekey for the whole DLC
                let dlc_key = DlcKey::generate_random();
                let signedlicense = dlc_key.create_signed_license(
                    &[DlcId::from(dlc_id_str.clone())],
                    Product::from(product.clone()),
                )?;

                println!(
                    "created {} encrypted assets to {}",
                    files.len(),
                    out_dir.display()
                );
                signedlicense.with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key));

                return Ok(());
            }

            // single-file mode (unchanged)
            let mut f = File::open(&input)?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;

            let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("");

            let dlc_id = DlcId::from(dlc_id_str.clone());
            let content_key = ContentKey::from_random(32);
            let (container, _nonce) = pack_encrypted_asset(
                &bytes,
                &dlc_id,
                if ext.is_empty() { None } else { Some(ext) },
                None,
                &content_key,
            )?;

            // create signed token for logical gating (dlcs/product).
            let dlc_key = DlcKey::generate_random();
            let signedlicense =
                dlc_key.create_signed_license(&[dlc_id.clone()], Product::from(product.clone()))?;

            if list {
                // produce a sample container to show metadata
                let enc = parse_encrypted(&container)?;
                println!("dlc_id: {}", enc.dlc_id);
                println!("original_extension: {}", enc.original_extension);
                println!("ciphertext_len: {}", enc.ciphertext.len());
                println!("nonce: {}", hex::encode(enc.nonce));
            }

            let out_path = out.unwrap_or_else(|| {
                let mut p = input.clone();
                p.set_extension("dlc");
                p
            });
            std::fs::write(&out_path, &container)?;

            println!("created encrypted asset: {}", out_path.display());
            signedlicense.with_secret(|s| print_signed_license_and_pubkey(s.as_str(), &dlc_key));
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
                        let (did, _v, ents) = parse_encrypted_pack(&bytes)?;
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
                let (did, _v, ents) = parse_encrypted_pack(&bytes)?;
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

        Commands::Unpack {
            dlc,
            list,
            out,
            content_key,
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

            // obtain the symmetric key from the provided --content-key
            let sym_key_vec = match content_key.as_deref() {
                Some(s) => {
                    let bytes = read_pubkey_bytes(s)?;
                    if bytes.len() != 32 {
                        return Err("content key must be 32 bytes".into());
                    }
                    bytes
                }
                None => return Err("missing --content-key".into()),
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
