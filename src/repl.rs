use std::io::{Write, stdin, stdout, ErrorKind};
use std::path::{PathBuf, Path};
use clap::{Arg, Command};
use owo_colors::{AnsiColors, CssColors, OwoColorize};
use bevy_dlc::{prelude::*, DLC_PACK_MAGIC, parse_encrypted_pack, EncryptionKey};

use crate::{print_error, is_executable};

// Helper macros that ignore broken pipe errors when writing to stdout. When a pipe is
// closed (e.g. the parent process exits or the output is piped through a failing
// command), we want the REPL to quietly terminate instead of panicking.
macro_rules! safe_println {
    ($($arg:tt)*) => {{
        let res = writeln!(stdout(), $($arg)*);
        if let Err(e) = res {
            if e.kind() == ErrorKind::BrokenPipe {
                return Ok(());
            }
        }
    }};
}

/// Helper macro for print without newline, with the same broken pipe handling as `safe_println`.
macro_rules! safe_print {
    ($($arg:tt)*) => {{
        let res = write!(stdout(), $($arg)*);
        if let Err(e) = res {
            if e.kind() == ErrorKind::BrokenPipe {
                return Ok(());
            }
        }
    }};
}

// format a byte count into a human-readable string (KB/MB/GB)
fn human_bytes(bytes: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", size as usize, UNITS[unit])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}

pub fn run_edit_repl(path: PathBuf, encrypt_key: Option<EncryptionKey>) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(&path)?;
    let (product, mut dlc_id, version, mut entries): (String, String, usize, Vec<(String, EncryptedAsset)>) = parse_encrypted_pack(&bytes)?;

    safe_println!(
        "{} {} (v{}, {}: {}, dlc: {})",
        "REPL".color(AnsiColors::Cyan).bold(),
        path.display().to_string().color(AnsiColors::Cyan),
        version,
        "product".color(AnsiColors::Blue),
        product.as_str().color(AnsiColors::Magenta).bold(),
        dlc_id.as_str().color(AnsiColors::Magenta).bold()
    );

    if encrypt_key.is_some() {
        safe_println!("{} Encryption key available (adding new files enabled).", "".green());
    } else {
        safe_println!("{} No encryption key provided (adding new files disabled).", "".yellow());
    }
    safe_println!("Type 'help' for commands.");

    let mut dirty = false;
    let mut added_files: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();

    loop {
        safe_print!("{} ", ">".color(AnsiColors::Magenta).bold());
        if let Err(e) = stdout().flush() {
            if e.kind() == ErrorKind::BrokenPipe {
                stdout().flush().ok(); // Attempt to flush any remaining output, ignoring errors
                return Ok(());
            } else {
                return Err(e.into());
            }
        }
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.trim().is_empty() {
            continue;
        }

        let parts: Vec<String> = trimmed.split_whitespace().map(|s| s.to_string()).collect();
        if parts.is_empty() {
            continue;
        }

        let cmd = Command::new("repl")
            .no_binary_name(true)
            .subcommand(Command::new("info").about("Show pack info"))
            .subcommand(Command::new("ls").about("List all entries and their types").visible_alias("list"))
            .subcommand(
                Command::new("type")
                    .about("Set type_path for entry")
                    .visible_alias("set-type")
                    .arg(Arg::new("id").help("Index or path of the entry").required(true))
                    .arg(Arg::new("type").help("New TypePath").required(true))
            )
            .subcommand(
                Command::new("rm")
                    .about("Remove entry from manifest")
                    .visible_alias("remove")
                    .arg(Arg::new("id").help("Index or path of the entry").required(true))
            )
            .subcommand(
                Command::new("add")
                    .about("Add new local file to the pack (requires encryption key)")
                    .visible_alias("new")
                    .arg(Arg::new("file").help("Local filesystem path").required(true).num_args(1..))
                    .arg(Arg::new("inner_path").short('p').long("path").help("Archive-internal path (defaults to filename)"))
                    .arg(Arg::new("type").short('t').long("type").help("TypePath override"))
            )
            .subcommand(
                Command::new("id")
                    .about("Set the DLC ID for this pack")
                    .visible_alias("set-id")
                    .arg(Arg::new("new_id").help("The new DLC ID").required(true))
            )
            .subcommand(
                Command::new("export")
                    .about("Export (decrypt and save) an entry to a local file")
                    .arg(Arg::new("id").help("Index or path of the entry").required(true))
                    .arg(Arg::new("out").help("Optional output destination path (defaults to entry name)"))
            )
            .subcommand(Command::new("cls").about("Clear the console").visible_alias("clear"))
            .subcommand(Command::new("save").about("Write changes back to disk"))
            .subcommand(Command::new("exit").about("Exit the editor").visible_alias("quit"));

        match cmd.try_get_matches_from(parts) {
            Ok(matches) => {
                match matches.subcommand() {
                    Some(("info", _)) => {
                        safe_println!("Pack info: {}", path.display().to_string().color(AnsiColors::Cyan));
                        safe_println!(" Product: {}", product.color(AnsiColors::Blue));
                        safe_println!(" DLC ID: {}", dlc_id.color(AnsiColors::Magenta));
                        safe_println!(" Version: {}", version.to_string().color(AnsiColors::Yellow));
                        // we used to sum ciphertext lengths here, but for v2+ packs each
                        // entry points at the same blob, so the sum would be N×actual
                        // size. instead report the container size on disk which matches the
                        // file the user passed in.
                        if let Some((_,enc)) = entries.first() {
                            safe_println!(" Content Size: {}", human_bytes(enc.ciphertext.len()).color(CssColors::SlateGray));
                        } else {
                            // fallback if metadata fails – should be rare
                            let total: usize = entries.iter().map(|(_, e)| e.ciphertext.len()).sum();
                            safe_println!(" Content Size (approx): {}", human_bytes(total).color(CssColors::SlateGray));
                        }
                    }
                    Some(("ls", _)) => {
                        safe_println!("Entries in {}:", dlc_id.as_str().color(AnsiColors::Magenta));
                        for (i, (p, enc)) in entries.iter().enumerate() {
                            safe_println!(
                                " [{}] {} (ext: {}) type: {}",
                                i.color(AnsiColors::Cyan),
                                p.as_str().color(AnsiColors::Green),
                                enc.original_extension.as_str().color(AnsiColors::Yellow),
                                enc.type_path.as_deref().unwrap_or("None").color(AnsiColors::Yellow)
                            );
                        }
                    }
                    Some(("type", sub)) => {
                        let id = sub.get_one::<String>("id").unwrap();
                        let new_type = sub.get_one::<String>("type").unwrap();

                        let target = if let Ok(idx) = id.parse::<usize>() {
                            entries.get_mut(idx)
                        } else {
                            entries.iter_mut().find(|(p, _)| p == id)
                        };

                        if let Some((p, enc)) = target {
                            enc.type_path = Some(new_type.to_string());
                            safe_println!("Updated type for {} to {}", p.color(AnsiColors::Green), new_type.color(AnsiColors::Yellow));
                            dirty = true;
                        } else {
                            safe_println!("Entry not found: {}", id);
                        }
                    }
                    Some(("rm", sub)) => {
                        let id = sub.get_one::<String>("id").unwrap();
                        let idx = if let Ok(idx) = id.parse::<usize>() {
                            Some(idx)
                        } else {
                            entries.iter().position(|(p, _)| p == id)
                        };

                        if let Some(i) = idx {
                            if i < entries.len() {
                                let (p, _) = entries.remove(i);
                                added_files.remove(&p);
                                safe_println!("Removed entry from manifest: {}", p.color(AnsiColors::Green));
                                dirty = true;
                            } else {
                                safe_println!("Index out of bounds: {}", i);
                            }
                        } else {
                            safe_println!("Entry not found: {}", id);
                        }
                    }
                    Some(("add", sub)) => {
                        if encrypt_key.is_none() {
                            safe_println!("{} Command 'add' requires an encryption key. Provide a --signed-license or --aes-key to use this.", "error".red().bold());
                            continue;
                        }

                        let files = sub.get_many::<String>("file").unwrap();
                        let type_override = sub.get_one::<String>("type");
                        let inner_path_arg = sub.get_one::<String>("inner_path");

                        for f in files {
                            let f_path = Path::new(f);
                            if !f_path.exists() {
                                safe_println!("{} Local file not found: {}", "error".red(), f);
                                continue;
                            }
                            
                            match std::fs::metadata(f_path) {
                                Ok(meta) => {
                                    if !meta.is_file() {
                                        safe_println!("{} Path is not a file: {}", "error".red(), f);
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    safe_println!("{} Failed to read metadata for {}: {}", "error".red(), f, e);
                                    continue;
                                }
                            }

                            if is_executable(f_path) {
                                safe_println!("{} Refusing to pack executable file: {}", "error".red(), f);
                                continue;
                            }

                            let filename = f_path.file_name().unwrap().to_string_lossy().to_string();
                            let inner_path = inner_path_arg.cloned().unwrap_or(filename);
                            
                            let data = std::fs::read(f_path)?;
                            
                            let mut pack_item = match PackItem::new(inner_path.clone(), data) {
                                Ok(item) => item,
                                Err(e) => {
                                    print_error(&e.to_string());
                                    continue;
                                }
                            };

                            if let Some(tp) = type_override {
                                pack_item = pack_item.with_type_path(tp);
                            }

                            added_files.insert(inner_path.clone(), pack_item.plaintext().to_vec());
                            
                            // Staging entry for the REPL to display in 'ls'
                            entries.push((inner_path.clone(), EncryptedAsset {
                                dlc_id: dlc_id.clone(),
                                original_extension: pack_item.original_extension.unwrap_or_default(),
                                type_path: pack_item.type_path,
                                nonce: [0u8; 12],
                                ciphertext: vec![].into(),
                            }));
                            
                            safe_println!("Added local file to staging: {} -> {}", f.color(AnsiColors::Cyan), inner_path.color(AnsiColors::Green));
                        }
                        dirty = true;
                    }
                    Some(("id", sub)) => {
                        let new_id = sub.get_one::<String>("new_id").unwrap();
                        safe_println!("Renaming pack DLC ID: {} -> {}", dlc_id.color(AnsiColors::Magenta), new_id.color(AnsiColors::Magenta).bold());
                        dlc_id = new_id.clone();
                        dirty = true;
                    }
                    Some(("export", sub)) => {
                        let id = sub.get_one::<String>("id").unwrap();
                        let out_path_str = sub.get_one::<String>("out");

                        let target_path = if let Ok(idx) = id.parse::<usize>() {
                            entries.get(idx).map(|(p, _)| p.clone())
                        } else {
                            entries.iter().find(|(p, _)| p == id).map(|(p, _)| p.clone())
                        };

                        if let Some(p) = target_path {
                            let mut out_dest = out_path_str.map(PathBuf::from).unwrap_or_else(|| PathBuf::from(&p));
                            // If user provided a path that looks like a directory (exists or ends in slash), append the entry filename
                            if out_dest.is_dir() || out_path_str.map(|s| s.ends_with('/') || s.ends_with('\\')).unwrap_or(false) {
                                if !out_dest.exists() {
                                    std::fs::create_dir_all(&out_dest)?;
                                }
                                out_dest.push(&p);
                            }

                            // Ensure parent exists
                            if let Some(parent) = out_dest.parent() {
                                std::fs::create_dir_all(parent)?;
                            }

                            if let Some(ek) = encrypt_key.as_ref() {
                                if let Some(data) = added_files.get(&p) {
                                    std::fs::write(&out_dest, data)?;
                                    safe_println!("Exported (staged) file to {}", out_dest.display().to_string().color(AnsiColors::Cyan));
                                } else {
                                    // Must extract from the original pack bytes
                                    use flate2::read::GzDecoder;
                                    use tar::Archive;
                                    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
                                    use secure_gate::ExposeSecret;

                                    let cipher = ek.with_secret(|s| Aes256Gcm::new_from_slice(s)).map_err(|_| "Invalid key")?;
                                    let mut found = false;
                                    
                                    if let Some((_, first)) = entries.first() {
                                        let nonce = Nonce::from_slice(&first.nonce);
                                        let pt = cipher.decrypt(nonce, first.ciphertext.as_ref()).map_err(|_| "Decryption failed")?;
                                        let decoder = GzDecoder::new(&pt[..]);
                                        let mut archive = Archive::new(decoder);
                                        
                                        for entry_res in archive.entries()? {
                                            let mut entry = entry_res?;
                                            if entry.path()?.to_string_lossy() == p {
                                                let mut out_file = std::fs::File::create(&out_dest)?;
                                                std::io::copy(&mut entry, &mut out_file)?;
                                                safe_println!("Exported {} to {}", p.color(AnsiColors::Green), out_dest.display().to_string().color(AnsiColors::Cyan));
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                    if !found {
                                        safe_println!("{} Entry {} not found in archive.", "error".red(), p);
                                    }
                                }
                            } else {
                                safe_println!("{} Exporting requires an encryption key.", "error".red());
                            }
                        } else {
                            safe_println!("{} Entry not found: {}", "error".red(), id);
                        }
                    }
                    Some(("cls", _)) => {
                        safe_print!("\x1B[2J\x1B[1;1H");
                        if let Err(e) = stdout().flush() {
                            if e.kind() == ErrorKind::BrokenPipe {
                                return Ok(());
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                    Some(("save", _)) => {
                        if !dirty {
                            safe_println!("No changes to save.");
                        } else {
                            save_pack_optimized(&path, &bytes, version, &product, &dlc_id, &entries, &added_files, encrypt_key.as_ref())?;
                            safe_println!("Saved changes to {}", path.display().to_string().color(AnsiColors::Cyan));
                            dirty = false;
                            added_files.clear();
                        }
                    }
                    Some(("exit", _)) => {
                        if dirty {
                            safe_print!("You have unsaved changes. Exit anyway? (y/n) ");
                            if let Err(e) = stdout().flush() {
                                if e.kind() == ErrorKind::BrokenPipe {
                                    return Ok(());
                                } else {
                                    return Err(e.into());
                                }
                            }
                            let mut confirm = String::new();
                            stdin().read_line(&mut confirm)?;
                            if !confirm.trim().eq_ignore_ascii_case("y") {
                                continue;
                            }
                        }
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Err(e) => {
                safe_println!("{}", e);
            }
        }
    }
}

/// Save function that attempts to optimize for the case where no files were added/removed, since we can just update the manifest and headers without touching the archive content. If files were added, we have to re-pack the archive which requires the encryption key.
fn save_pack_optimized(
    path: &Path,
    bytes: &[u8],
    version: usize,
    product: &str,
    dlc_id: &str,
    entries: &[(String, EncryptedAsset)],
    added_files: &std::collections::HashMap<String, Vec<u8>>,
    encrypt_key: Option<&EncryptionKey>
) -> Result<(), Box<dyn std::error::Error>> {
    use flate2::Compression;
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;
    use tar::{Archive, Builder};
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
    use secure_gate::ExposeSecret;

    // If no files were ADDED, we can just update the manifest and headers without re-encrypting the archive.
    if added_files.is_empty() {
        return update_manifest(path, bytes, version, product, dlc_id, entries);
    }

    // Re-packing requires the key
    let ek = encrypt_key.ok_or("Re-packing with new files requires an signed license (--signed-license)")?;
    
    // 1. Recover old archive content
    let (_old_prod, _old_did, _old_v, old_entries) = parse_encrypted_pack(bytes)?;
    
    let mut new_tar_buffer = Vec::new();
    {
        let mut builder = Builder::new(&mut new_tar_buffer);
        
        // 1a. Extract and add existing files from original archive
        if let Some((_, first)) = old_entries.first() {
            let cipher = ek.with_secret(|s| Aes256Gcm::new_from_slice(s)).map_err(|_| "Invalid key")?;
            let nonce = Nonce::from_slice(&first.nonce);
            let pt = cipher.decrypt(nonce, first.ciphertext.as_ref()).map_err(|_| "Decryption failed (key may be incorrect for this pack)")?;
            
            let mut decoder = GzDecoder::new(&pt[..]);
            let mut archive = Archive::new(&mut decoder);
            
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?.to_path_buf();
                let path_str = path.to_string_lossy().to_string();
                
                // Only keep it if it wasn't REMOVED in the REPL
                if entries.iter().any(|(p, _)| p == &path_str) {
                    builder.append_data(&mut entry.header().clone(), &path, &mut entry)?;
                }
            }
        }
        
        // 1b. Add newly staged files
        for (p, data) in added_files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, p, &data[..])?;
        }
        builder.finish()?;
    }

    // 2. Compress and re-encrypt
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&new_tar_buffer)?;
    let compressed = gz.finish()?;

    let nonce_bytes = EncryptionKey::from_random(12).with_secret(|kb| {
        let mut n = [0u8; 12];
        n.copy_from_slice(&kb[0..12]);
        n
    });
    let cipher = ek.with_secret(|s| Aes256Gcm::new_from_slice(s)).map_err(|_| "Cipher error")?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), compressed.as_ref()).map_err(|_| "Encryption error")?;

    // 3. Assemble final container
    let mut out = Vec::new();
    out.extend_from_slice(DLC_PACK_MAGIC);
    out.push(version as u8);

    if version >= 3 {
        let prod_bytes = product.as_bytes();
        out.extend_from_slice(&(prod_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(prod_bytes);
        
        let sig_offset = 4 + 1 + 2 + prod_bytes.len();
        out.extend_from_slice(&bytes[sig_offset..sig_offset + 64]);
    }

    let dlc_bytes = dlc_id.as_bytes();
    out.extend_from_slice(&(dlc_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(dlc_bytes);

    #[derive(serde::Serialize)]
    struct ManifestEntry<'a> {
        path: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        original_extension: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        type_path: Option<&'a str>,
    }

    let manifest: Vec<ManifestEntry<'_>> = entries.iter().map(|(p, enc)| {
        ManifestEntry { path: p, original_extension: Some(&enc.original_extension), type_path: enc.type_path.as_deref() }
    }).collect();
    
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    out.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&manifest_bytes);

    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&ciphertext);

    std::fs::write(path, &out)?;
    Ok(())
}

/// Update the manifest and headers of the pack without re-encrypting the archive (only works if no files were added/removed, just metadata changes)
fn update_manifest(
    path: &Path,
    bytes: &[u8],
    version: usize,
    product: &str,
    dlc_id: &str,
    entries: &[(String, EncryptedAsset)]
) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    out.extend_from_slice(DLC_PACK_MAGIC);
    out.push(version as u8);

    if version >= 3 {
        let prod_bytes = product.as_bytes();
        out.extend_from_slice(&(prod_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(prod_bytes);
        
        let sig_offset = 4 + 1 + 2 + prod_bytes.len();
        out.extend_from_slice(&bytes[sig_offset..sig_offset + 64]);
    }

    let dlc_bytes = dlc_id.as_bytes();
    out.extend_from_slice(&(dlc_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(dlc_bytes);

    #[derive(serde::Serialize)]
    struct ManifestEntry<'a> {
        path: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        original_extension: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        type_path: Option<&'a str>,
    }

    let manifest: Vec<ManifestEntry<'_>> = entries.iter().map(|(p, enc)| {
        ManifestEntry {
            path: p,
            original_extension: Some(&enc.original_extension),
            type_path: enc.type_path.as_deref(),
        }
    }).collect();
    
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    out.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&manifest_bytes);

    if let Some((_, first_enc)) = entries.first() {
        out.extend_from_slice(&first_enc.nonce);
        out.extend_from_slice(&(first_enc.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&first_enc.ciphertext);
    }

    std::fs::write(path, &out)?;
    Ok(())
}
