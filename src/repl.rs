use bevy_dlc::{
    DLC_PACK_MAGIC,
    EncryptionKey,
    parse_encrypted_pack,
    prelude::*,
};
use clap::{Arg, ArgAction, Command};
use owo_colors::{AnsiColors, CssColors, OwoColorize};
use std::io::{ErrorKind, Write, stdin, stdout};
use std::path::{Path, PathBuf};


use crate::{extract_encrypt_key_from_token, is_executable, print_error, resolve_keys};

// Helper macros that ignore broken pipe errors when writing to stdout. When a pipe is
// closed (e.g. the parent process exits or the output is piped through a failing
// command), we want the REPL to quietly terminate instead of panicking.
macro_rules! safe_println {
    ($($arg:tt)*) => {{
        let res = writeln!(stdout(), $($arg)*);
        if let Err(e) = res {
            if e.kind() == ErrorKind::BrokenPipe {
                // return with the default value for the surrounding function's
                // Result<_, _> so that both `Result<(), _>` and
                // `Result<bool, _>` callers compile.
                return Ok(Default::default());
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
                return Ok(Default::default());
            }
        }
    }};
}


pub fn run_edit_repl(
    path: PathBuf,
    mut encrypt_key: Option<EncryptionKey>,
    initial_command: Option<Vec<String>>, // new parameter for one-shot commands
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(&path)?;
    let (product, mut dlc_id, version, mut entries): (
        String,
        String,
        usize,
        Vec<(String, EncryptedAsset)>,
    ) = parse_encrypted_pack(&bytes)?;

    safe_println!(
        "{} {} (v{}, {}: {}, dlc: {})",
        "REPL".color(AnsiColors::Cyan).bold(),
        path.display().to_string().color(AnsiColors::Cyan),
        version,
        "product".color(AnsiColors::Blue),
        product.as_str().color(AnsiColors::Magenta).bold(),
        dlc_id.as_str().color(AnsiColors::Magenta).bold()
    );

    let adding_enabled = if encrypt_key.is_some() {
        format!("{}", "(adding new files enabled)".green())
    } else {
        format!("{}", "(adding new files disabled)".yellow())
    };

    safe_println!("Encryption key available {}.", adding_enabled);
    safe_println!("Type 'help' for commands.");

    let mut dirty = false;
    let mut added_files: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();

    // helper to build the command parser so we can reuse it both in the
    // interactive loop and for the one-shot invocation.
    let build_repl_cli = || {
        Command::new("edit")
            .no_binary_name(true)
            .subcommand(Command::new("info").about("Show pack info"))
            .subcommand(
                Command::new("ls")
                    .about("List all entries and their types")
                    .visible_alias("list"),
            )
            .subcommand(
                Command::new("type")
                    .about("Set type_path for entry")
                    .visible_alias("ty")
                    .arg(
                        Arg::new("id")
                            .help("Index or path of the entry")
                            .required(true),
                    )
                    .arg(Arg::new("type").help("New TypePath").required(true)),
            )
            .subcommand(
                Command::new("rm")
                    .about("Remove entry from manifest")
                    .visible_alias("remove")
                    .arg(
                        Arg::new("id")
                            .help("Index or path of the entry")
                            .required(true),
                    ),
            )
            .subcommand(
                Command::new("add")
                    .about("Add new local file to the pack (requires encryption key)")
                    .visible_alias("new")
                    .arg(
                        Arg::new("file")
                            .help("Local filesystem path")
                            .required(true)
                            .num_args(1..),
                    )
                    .arg(
                        Arg::new("inner_path")
                            .short('p')
                            .long("path")
                            .help("Archive-internal path (defaults to filename)"),
                    )
                    .arg(
                        Arg::new("type")
                            .short('t')
                            .long("type")
                            .help("TypePath override"),
                    ),
            )
            .subcommand(
                Command::new("id")
                    .about("Set the DLC ID for this pack")
                    .visible_alias("set-id")
                    .arg(Arg::new("new_id").help("The new DLC ID").required(true)),
            )
            .subcommand(
                Command::new("export")
                    .about("Export (decrypt and save) an entry to a local file")
                    .arg(
                        Arg::new("id")
                            .help("Index or path of the entry")
                            .required(true),
                    )
                    .arg(
                        Arg::new("out")
                            .help("Optional output destination path (defaults to entry name)"),
                    ),
            )
            .subcommand(
                Command::new("cls")
                    .about("Clear the console")
                    .visible_alias("clear"),
            )
            .subcommand(Command::new("save").about("Write changes back to disk"))
            .subcommand(
                Command::new("merge")
                    .about("Merge entries from another .dlcpack into the current one")
                    .arg(
                        Arg::new("file")
                            .help("Path to other dlcpack")
                            .required(true),
                    )
                    .arg(
                        Arg::new("signed_license")
                            .long("signed-license")
                            .help("SignedLicense token for the source pack")
                            .value_name("SIGNED_LICENSE"),
                    )
                    .arg(
                        Arg::new("pubkey")
                            .long("pubkey")
                            .help("Public key to verify the supplied license")
                            .value_name("PUBKEY"),
                    )
                    .arg(
                        Arg::new("delete_source")
                            .long("delete")
                            .short('d')
                            .help("Remove source pack file after successful merge")
                            .action(ArgAction::SetTrue),
                    ),
            )
            .subcommand(
                Command::new("exit")
                    .about("Exit the editor")
                    .visible_alias("quit")
                    .visible_alias("q"),
            )
    };

    // wrapper that executes a single parsed command. returns `true` if we
    // should break out of the interactive loop (i.e. exit requested), false
    // means continue.
    let mut execute = |parts: Vec<String>| -> Result<bool, Box<dyn std::error::Error>> {
        let cmd = build_repl_cli();
        match cmd.try_get_matches_from(parts) {
            Ok(matches) => {
                match matches.subcommand() {
                    Some(("info", _)) => {
                        safe_println!(
                            "Pack info: {}",
                            path.display().to_string().color(AnsiColors::Cyan)
                        );
                        safe_println!(" Product: {}", product.color(AnsiColors::Blue));
                        safe_println!(" DLC ID: {}", dlc_id.color(AnsiColors::Magenta));
                        safe_println!(
                            " Version: {}",
                            version.to_string().color(AnsiColors::Yellow)
                        );
                        // report both the encrypted archive blob length and the
                        // actual file size on disk.  if the user saved without a key
                        // (manifest-only change) then only the manifest shrinks and the
                        // archive bytes stay the same.
                        let archive_size =
                            entries.get(0).map(|(_, e)| e.ciphertext.len()).unwrap_or(0);

                        safe_println!(
                            " Archive Size: {} ({} bytes)",
                            bevy_dlc::human_bytes!(archive_size).color(CssColors::SlateGray),
                            archive_size,
                        );
                        return Ok(false);
                    }
                    Some(("ls", _)) => {
                        safe_println!("Entries in {}:", dlc_id.as_str().color(AnsiColors::Magenta));
                        for (i, (p, enc)) in entries.iter().enumerate() {
                            safe_println!(
                                " [{}] {} (ext: {}) type: {}",
                                i.color(AnsiColors::Cyan),
                                p.as_str().color(AnsiColors::Green),
                                enc.original_extension.as_str().color(AnsiColors::Yellow),
                                enc.type_path
                                    .as_deref()
                                    .unwrap_or("None")
                                    .color(AnsiColors::Yellow),
                            );
                        }
                        return Ok(false);
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
                            safe_println!(
                                "Updated type for {} to {}",
                                p.color(AnsiColors::Green),
                                new_type.color(AnsiColors::Yellow),
                            );
                            dirty = true;
                        } else {
                            safe_println!("Entry not found: {}", id);
                        }
                        return Ok(false);
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
                                safe_println!(
                                    "Removed entry from manifest: {}",
                                    p.color(AnsiColors::Green),
                                );
                                dirty = true;
                            } else {
                                safe_println!("Index out of bounds: {}", i);
                            }
                        } else {
                            safe_println!("Entry not found: {}", id);
                        }
                        return Ok(false);
                    }
                    Some(("add", sub)) => {
                        if encrypt_key.is_none() {
                            safe_println!(
                                "{} Command 'add' requires an encryption key. Provide a --signed-license (and optionally --pubkey) when launching the editor.",
                                "error".red().bold(),
                            );
                            return Ok(false);
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
                                        safe_println!(
                                            "{} Path is not a file: {}",
                                            "error".red(),
                                            f,
                                        );
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    safe_println!(
                                        "{} Failed to read metadata for {}: {}",
                                        "error".red(),
                                        f,
                                        e,
                                    );
                                    continue;
                                }
                            }
                            if is_executable(f_path) {
                                safe_println!(
                                    "{} Refusing to pack a executable file: {}",
                                    "error".red(),
                                    f,
                                );
                                continue;
                            }
                            let filename =
                                f_path.file_name().unwrap().to_string_lossy().to_string();
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
                            entries.push((
                                inner_path.clone(),
                                EncryptedAsset {
                                    dlc_id: dlc_id.clone(),
                                    original_extension: pack_item.ext().unwrap_or_default(),
                                    type_path: pack_item.type_path(),
                                    nonce: [0u8; 12],
                                    ciphertext: vec![].into(),
                                },
                            ));
                            safe_println!(
                                "Added local file to staging: {} -> {}",
                                f.color(AnsiColors::Cyan),
                                inner_path.color(AnsiColors::Green),
                            );
                        }
                        dirty = true;
                    }
                    Some(("id", sub)) => {
                        let new_id = sub.get_one::<String>("new_id").unwrap();
                        safe_println!(
                            "Renaming pack DLC ID: {} -> {}",
                            dlc_id.color(AnsiColors::Magenta),
                            new_id.color(AnsiColors::Magenta).bold(),
                        );
                        dlc_id = new_id.clone();
                        dirty = true;
                        return Ok(false);
                    }
                    Some(("export", sub)) => {
                        let id = sub.get_one::<String>("id").unwrap();
                        let out_path_str = sub.get_one::<String>("out");
                        let target_path = if let Ok(idx) = id.parse::<usize>() {
                            entries.get(idx).map(|(p, _)| p.clone())
                        } else {
                            entries
                                .iter()
                                .find(|(p, _)| p == id)
                                .map(|(p, _)| p.clone())
                        };
                        if let Some(p) = target_path {
                            let mut out_dest = out_path_str
                                .map(PathBuf::from)
                                .unwrap_or_else(|| PathBuf::from(&p));
                            if out_dest.is_dir()
                                || out_path_str
                                    .map(|s| s.ends_with('/') || s.ends_with('\\'))
                                    .unwrap_or(false)
                            {
                                if !out_dest.exists() {
                                    std::fs::create_dir_all(&out_dest)?;
                                }
                                out_dest.push(&p);
                            }
                            if let Some(parent) = out_dest.parent() {
                                std::fs::create_dir_all(parent)?;
                            }
                            if let Some(ek) = encrypt_key.as_ref() {
                                if let Some(data) = added_files.get(&p) {
                                    std::fs::write(&out_dest, data)?;
                                    safe_println!(
                                        "Exported (staged) file to {}",
                                        out_dest.display().to_string().color(AnsiColors::Cyan),
                                    );
                                } else {
                                    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
                                    use flate2::read::GzDecoder;
                                    use secure_gate::ExposeSecret;
                                    use tar::Archive;
                                    let cipher = ek
                                        .with_secret(|s| Aes256Gcm::new_from_slice(s))
                                        .map_err(|_| "Invalid key")?;
                                    let mut found = false;
                                    if let Some((_, first)) = entries.first() {
                                        let nonce = Nonce::from_slice(&first.nonce);
                                        let pt = cipher
                                            .decrypt(nonce, first.ciphertext.as_ref())
                                            .map_err(|_| "Decryption failed")?;
                                        let decoder = GzDecoder::new(&pt[..]);
                                        let mut archive = Archive::new(decoder);
                                        for entry_res in archive.entries()? {
                                            let mut entry = entry_res?;
                                            if entry.path()?.to_string_lossy() == p {
                                                let mut out_file =
                                                    std::fs::File::create(&out_dest)?;
                                                std::io::copy(&mut entry, &mut out_file)?;
                                                safe_println!(
                                                    "Exported {} to {}",
                                                    p.color(AnsiColors::Green),
                                                    out_dest
                                                        .display()
                                                        .to_string()
                                                        .color(AnsiColors::Cyan),
                                                );
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                    if !found {
                                        safe_println!(
                                            "{} Entry {} not found in archive.",
                                            "error".red(),
                                            p,
                                        );
                                    }
                                }
                            } else {
                                safe_println!(
                                    "{} Exporting requires an encryption key.",
                                    "error".red()
                                );
                            }
                        } else {
                            safe_println!("{} Entry not found: {}", "error".red(), id);
                        }
                        return Ok(false);
                    }
                    Some(("cls", _)) => {
                        safe_print!("\x1B[2J\x1B[1;1H");
                        if let Err(e) = stdout().flush() {
                            if e.kind() == ErrorKind::BrokenPipe {
                                return Ok(true);
                            } else {
                                return Err(e.into());
                            }
                        }
                        return Ok(false);
                    }
                    Some(("save", _)) => {
                        if !dirty {
                            safe_println!("No changes to save.");
                        } else if dry_run {
                            safe_println!(
                                "dry-run: would save changes to {}",
                                path.display().to_string().color(AnsiColors::Cyan)
                            );
                        } else {
                            save_pack_optimized(
                                &path,
                                &bytes,
                                version,
                                &product,
                                &dlc_id,
                                &entries,
                                &added_files,
                                encrypt_key.as_ref(),
                            )?;
                            safe_println!(
                                "Saved changes to {}",
                                path.display().to_string().color(AnsiColors::Cyan),
                            );
                            dirty = false;
                            added_files.clear();
                        }
                        return Ok(false);
                    }
                    Some(("merge", sub)) => {
                        let file = sub.get_one::<String>("file").unwrap();
                        let other_path = Path::new(file);
                        let delete_source = sub.get_flag("delete_source");

                        if !other_path.exists() {
                            safe_println!("{} file not found: {}", "error".red(), file);
                            return Ok(false);
                        }

                        // try to resolve encryption key if we don't already have one
                        if encrypt_key.is_none() {
                            // parse other pack to get product for heuristics
                            if let Ok(bytes) = std::fs::read(other_path) {
                                if let Ok((other_prod, _other_did, _ver, _ents)) =
                                    parse_encrypted_pack(&bytes)
                                {
                                    let (_resolved_pubkey, resolved_license): (
                                        Option<String>,
                                        Option<String>,
                                    ) = resolve_keys(
                                        sub.get_one::<String>("pubkey").cloned(),
                                        sub.get_one::<String>("signed_license").cloned(),
                                        Some(other_prod.clone()),
                                        None,
                                    );
                                    if encrypt_key.is_none() {
                                        if let Some(lic) = resolved_license.as_deref() {
                                            if let Ok(Some(kb)) =
                                                extract_encrypt_key_from_token(lic)
                                            {
                                                encrypt_key = Some(EncryptionKey::from(kb));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if encrypt_key.is_none() {
                            safe_println!(
                                "{}: merging packs requires an encryption key",
                                "error".red(),
                            );
                            return Ok(false);
                        }

                        if let Err(e) = merge_pack_into(
                            other_path,
                            &mut entries,
                            &mut added_files,
                            encrypt_key.as_ref(),
                            &product,
                            &dlc_id,
                        ) {
                            safe_println!("{}: failed to merge: {}", "error".red(), e);
                        } else {
                            dirty = true;
                            if delete_source {
                                if !dry_run {
                                    let _ = std::fs::remove_file(other_path);
                                }
                            }
                        }
                        return Ok(false);
                    }
                    Some(("exit", _)) => {
                        if dirty {
                            safe_print!(
                                "You have unsaved changes. {}? ({}/{}) ",
                                "Save before exiting".yellow(),
                                'y'.green(),
                                'n'.red(),
                            );
                            if let Err(e) = stdout().flush() {
                                if e.kind() == ErrorKind::BrokenPipe {
                                    save_pack_optimized(
                                        &path,
                                        &bytes,
                                        version,
                                        &product,
                                        &dlc_id,
                                        &entries,
                                        &added_files,
                                        encrypt_key.as_ref(),
                                    )?;
                                    safe_println!(
                                        "Saved changes to {}",
                                        path.display().to_string().color(AnsiColors::Cyan),
                                    );
                                    added_files.clear();
                                    return Ok(true);
                                } else {
                                    return Err(e.into());
                                }
                            }
                            let mut confirm = String::new();
                            stdin().read_line(&mut confirm)?;
                            if confirm.trim().eq_ignore_ascii_case("y") {
                                save_pack_optimized(
                                    &path,
                                    &bytes,
                                    version,
                                    &product,
                                    &dlc_id,
                                    &entries,
                                    &added_files,
                                    encrypt_key.as_ref(),
                                )?;
                                safe_println!(
                                    "Saved changes to {}",
                                    path.display().to_string().color(AnsiColors::Cyan),
                                );
                                added_files.clear();
                            }
                        }
                        return Ok(true);
                    }
                    _ => {}
                }
            }
            Err(e) => {
                safe_println!("{}", e);
            }
        }
        Ok(false)
    };

    // if a one-shot command was provided via the CLI, execute it and return
    if let Some(cmd_parts) = initial_command {
        // pass the raw arguments directly; the parser is configured with
        // `no_binary_name(true)` so no leading name should be supplied.
        let _ = execute(cmd_parts)?;
        return Ok(());
    }

    // interactive loop
    loop {
        safe_print!("{} ", ">".color(AnsiColors::Magenta).bold());
        if let Err(e) = stdout().flush() {
            if e.kind() == ErrorKind::BrokenPipe {
                stdout().flush().ok();
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
        if execute(parts)? {
            break;
        }
    }
    Ok(())
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
    encrypt_key: Option<&EncryptionKey>,
) -> Result<(), Box<dyn std::error::Error>> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use flate2::Compression;
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;
    use secure_gate::ExposeSecret;
    use tar::{Archive, Builder};

    // Determine whether entries were removed by comparing against the original
    // manifest.  We must parse the pack regardless so we can make this
    // decision; this also allows us to fall through to the repack logic when
    // files have been deleted even if nothing was added.
    let (_old_prod, _old_did, _old_v, old_entries) = parse_encrypted_pack(bytes)?;
    let removed = old_entries.len() > entries.len();

    // simple case: nothing added and nothing removed -> just update headers/manifest
    if added_files.is_empty() && !removed {
        return update_manifest(path, bytes, version, product, dlc_id, entries);
    }

    // removal-only case without encryption key: update manifest but leave
    // archive blob untouched.  This mirrors previous behaviour and allows the
    // editor to drop entries even when the user only supplied a public key.
    if added_files.is_empty() && removed && encrypt_key.is_none() {
        return update_manifest(path, bytes, version, product, dlc_id, entries);
    }

    // from here on, we need to repack. ensure a key is present.
    let ek = encrypt_key
        .ok_or("Re-packing with new files requires a signed license (--signed-license)")?;

    // 1. Recover old archive content
    let (_old_prod, _old_did, _old_v, old_entries) = parse_encrypted_pack(bytes)?;

    let mut new_tar_buffer = Vec::new();
    {
        let mut builder = Builder::new(&mut new_tar_buffer);

        // 1a. Extract and add existing files from original archive
        if let Some((_, first)) = old_entries.first() {
            let cipher = ek
                .with_secret(|s| Aes256Gcm::new_from_slice(s))
                .map_err(|_| "Invalid key")?;
            let nonce = Nonce::from_slice(&first.nonce);
            let pt = cipher
                .decrypt(nonce, first.ciphertext.as_ref())
                .map_err(|_| "Decryption failed (key may be incorrect for this pack)")?;

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
    let cipher = ek
        .with_secret(|s| Aes256Gcm::new_from_slice(s))
        .map_err(|_| "Cipher error")?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), compressed.as_ref())
        .map_err(|_| "Encryption error")?;

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

    let manifest: Vec<ManifestEntry<'_>> = entries
        .iter()
        .map(|(p, enc)| ManifestEntry {
            path: p,
            original_extension: Some(&enc.original_extension),
            type_path: enc.type_path.as_deref(),
        })
        .collect();

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
    entries: &[(String, EncryptedAsset)],
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

    let manifest: Vec<ManifestEntry<'_>> = entries
        .iter()
        .map(|(p, enc)| ManifestEntry {
            path: p,
            original_extension: Some(&enc.original_extension),
            type_path: enc.type_path.as_deref(),
        })
        .collect();

    let manifest_bytes = serde_json::to_vec(&manifest)?;
    out.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&manifest_bytes);

    // When there are still entries the first one provides the nonce/
    // ciphertext blob we need to keep.  However if the user removed every
    // entry we still need to preserve the original archive bytes so the
    // container remains valid (the manifest may be empty but we can't
    // re-pack without the encryption key).  In that case parse the original
    // pack to pull its first encrypted blob and write it unchanged.
    if entries.is_empty() {
        if let Ok((_, _, _, orig_entries)) = parse_encrypted_pack(bytes) {
            if let Some((_, orig_first)) = orig_entries.first() {
                out.extend_from_slice(&orig_first.nonce);
                out.extend_from_slice(&(orig_first.ciphertext.len() as u32).to_be_bytes());
                out.extend_from_slice(&orig_first.ciphertext);
            }
        }
    } else if let Some((_, first_enc)) = entries.first() {
        out.extend_from_slice(&first_enc.nonce);
        out.extend_from_slice(&(first_enc.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&first_enc.ciphertext);
    }

    std::fs::write(path, &out)?;
    Ok(())
}

/// Merge entries from another `.dlcpack` into the working manifest and
/// staging area.  The `encrypt_key` is used to decrypt the source container so
/// we can extract individual files; it must be the same key that was used to
/// create the other pack (typically the same product/license key as the
/// current pack).
fn merge_pack_into(
    other_pack: &Path,
    entries: &mut Vec<(String, EncryptedAsset)>,
    added_files: &mut std::collections::HashMap<String, Vec<u8>>,
    encrypt_key: Option<&EncryptionKey>,
    current_product: &str,
    current_dlc_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use flate2::read::GzDecoder;
    use secure_gate::ExposeSecret;
    use tar::Archive;

    let ek = encrypt_key.ok_or("encryption key required to merge")?;

    let bytes = std::fs::read(other_pack)?;
    let (other_prod, _other_did, _ver, other_entries) = parse_encrypted_pack(&bytes)?;

    if other_prod != current_product {
        return Err(format!(
            "cannot merge two different products '{}' into '{}'",
            other_prod, current_product
        )
        .into());
    }

    if other_entries.is_empty() {
        return Ok(());
    }

    // decrypt blob from the other pack
    let cipher = ek
        .with_secret(|s| Aes256Gcm::new_from_slice(s))
        .map_err(|_| "cipher init");
    let cipher = cipher?;
    let first = &other_entries[0].1;
    let nonce = Nonce::from_slice(&first.nonce);
    let pt = cipher
        .decrypt(nonce, first.ciphertext.as_ref())
        .map_err(|_| "decryption failed (key mismatch?)")?;
    let decoder = GzDecoder::new(&pt[..]);
    let mut archive = Archive::new(decoder);

    let mut stray_found = false;
    for entry_res in archive.entries()? {
        let mut entry = entry_res?;
        let path = entry.path()?.to_string_lossy().to_string();

        // Only consider files that are listed in the source pack's manifest.  The
        // tar.gz archive may contain leftover or stray files (e.g. previous
        // packing runs) which are intentionally omitted from the manifest; these
        // should *not* be merged.
        if !other_entries.iter().any(|(p, _)| p == &path) {
            stray_found = true;
            continue;
        }

        if entries.iter().any(|(p, _)| p == &path) || added_files.contains_key(&path) {
            //safe_println!("Skipping existing entry: {}", path.color(AnsiColors::Yellow));
            continue;
        }

        let mut data = Vec::new();
        std::io::copy(&mut entry, &mut data)?;

        let mut pack_item = PackItem::new(path.clone(), data)?;
        // preserve type_path if present in source metadata
        if let Some((_, enc)) = other_entries.iter().find(|(p, _)| p == &path) {
            if let Some(tp) = &enc.type_path {
                pack_item = pack_item.with_type_path(tp);
            }
        }

        added_files.insert(path.clone(), pack_item.plaintext().to_vec());
        entries.push((
            path.clone(),
            EncryptedAsset {
                dlc_id: current_dlc_id.to_string(),
                original_extension: pack_item.ext().unwrap_or_default(),
                type_path: pack_item.type_path(),
                nonce: [0u8; 12],
                ciphertext: vec![].into(),
            },
        ));
        safe_println!("Merged entry: {}", path.color(AnsiColors::Green));
    }

// stray entries are intentionally ignored; we don't mutate the
        // source pack. if the caller wants the archive cleaned they can
        // repack manually using `save` or the CLI.
        if stray_found {
            safe_println!(
                "{} warning: pack contains unmanifested files; they were skipped. Repack using 'bevy-dlc pack'",
                "warning".yellow().bold()
            );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::{Command, pkg_name};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use bevy_dlc::{DlcId, DlcKey, EncryptionKey, PackItem, Product, pack_encrypted_pack};
    use predicates::prelude::*;
    use secure_gate::ExposeSecret;
    use tempfile::tempdir;

    #[test]
    fn human_bytes_macro_formats_expected() {
        assert_eq!(bevy_dlc::human_bytes!(0), "0 B");
        assert_eq!(bevy_dlc::human_bytes!(1023), "1023 B");
        assert_eq!(bevy_dlc::human_bytes!(1024), "1.00 KB");
        assert_eq!(bevy_dlc::human_bytes!(10 * 1024 * 1024 + 512), "10.00 MB");
    }

    #[test]
    fn merge_pack_into_adds_new_files() {
        // prepare two simple packs with different entries
        let dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("prod");

        let item1 = PackItem::new("a.txt", b"foo".to_vec()).unwrap();
        let bytes_a = pack_encrypted_pack(
            &DlcId::from("a".to_string()),
            &[item1],
            &product,
            &dlc_key,
            &enc_key,
        )
        .unwrap();

        let item2 = PackItem::new("b.txt", b"bar".to_vec()).unwrap();
        let bytes_b = pack_encrypted_pack(
            &DlcId::from("b".to_string()),
            &[item2],
            &product,
            &dlc_key,
            &enc_key,
        )
        .unwrap();

        let dir = tempdir().unwrap();
        let path_a = dir.path().join("a.dlcpack");
        let path_b = dir.path().join("b.dlcpack");
        std::fs::write(&path_a, &bytes_a).unwrap();
        std::fs::write(&path_b, &bytes_b).unwrap();

        let (_p, _id, _ver, mut entries) = parse_encrypted_pack(&bytes_a).unwrap();
        let mut added_files = std::collections::HashMap::new();

        // merge pack B into A
        merge_pack_into(
            &path_b,
            &mut entries,
            &mut added_files,
            Some(&enc_key),
            "prod",
            "a",
        )
        .unwrap();

        // expect the new entry to be staged
        assert!(entries.iter().any(|(p, _)| p == "b.txt"));
        assert!(added_files.contains_key("b.txt"));
        // original entry remains
        assert!(entries.iter().any(|(p, _)| p == "a.txt"));
    }

    #[test]
    fn merge_pack_into_ignores_unmanifested_archive_entries() {
        // regression test for packing behavior when an archive contains an
        // extra file that is *not* listed in the manifest.  instead of relying
        // on a pre-existing asset on disk we build a pack on the fly, then
        // inject a stray entry into the encrypted tar blob while leaving the
        // manifest untouched.  this allows the test to exercise the same
        // stray-detection / rewrite logic in a self‑contained way.

        /// Helper that takes an already‑valid pack produced by
        /// `pack_encrypted_pack` and returns a new byte vector with an
        /// additional tar entry added to the encrypted blob.  The manifest is
        /// deliberately left unchanged so the entry is "unmanifested".
        fn add_stray_to_pack(
            original: &[u8],
            encrypt_key: &EncryptionKey,
            stray_path: &str,
            stray_data: &[u8],
        ) -> Vec<u8> {
            use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
            use flate2::{read::GzDecoder, write::GzEncoder, Compression};
            use tar::Archive;
            use secure_gate::ExposeSecret;
            // need pack constants and the shared ManifestEntry type
            use bevy_dlc::{DLC_PACK_VERSION_LATEST, ManifestEntry};

            // parse header/manifest from the existing pack so we can rebuild
            let (product, did, ver, entries) =
                parse_encrypted_pack(original).expect("parse original pack");

            // decrypt the first (and only) ciphertext blob to get the tar
            let cipher = encrypt_key
                .with_secret(|s| Aes256Gcm::new_from_slice(s))
                .expect("cipher init");
            let first = &entries[0].1;
            let nonce = Nonce::from_slice(&first.nonce);
            let pt = cipher
                .decrypt(nonce, first.ciphertext.as_ref())
                .expect("decrypt tar");
            let decoder = GzDecoder::new(&pt[..]);
            let mut archive = Archive::new(decoder);

            // gather existing entries from the tar
            let mut existing: Vec<(String, Vec<u8>)> = Vec::new();
            for entry_res in archive.entries().unwrap() {
                let mut entry = entry_res.unwrap();
                let path = entry.path().unwrap().to_string_lossy().to_string();
                let mut data = Vec::new();
                std::io::copy(&mut entry, &mut data).unwrap();
                existing.push((path, data));
            }

            // append stray
            existing.push((stray_path.to_string(), stray_data.to_vec()));

            // rebuild tar+gzip payload
            let mut new_tar = Vec::new();
            {
                let mut builder = tar::Builder::new(&mut new_tar);
                for (p, data) in &existing {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(data.len() as u64);
                    header.set_cksum();
                    builder.append_data(&mut header, p, &data[..]).unwrap();
                }
                builder.finish().unwrap();
            }
            let mut gz = GzEncoder::new(Vec::new(), Compression::default());
            gz.write_all(&new_tar).unwrap();
            let compressed = gz.finish().unwrap();

            // encrypt with fresh random nonce
            let nonce_bytes: [u8; 12] = rand::random();
            let cipher2 = encrypt_key
                .with_secret(|s| Aes256Gcm::new_from_slice(s))
                .expect("cipher init");
            let ciphertext = cipher2
                .encrypt(Nonce::from_slice(&nonce_bytes), compressed.as_ref())
                .expect("encrypt");

            // reconstruct the pack bytes copying all header/manifest data but
            // replacing the first entry ciphertext
            let mut out = Vec::new();
            out.extend_from_slice(DLC_PACK_MAGIC);
            out.push(ver as u8);
            if ver == DLC_PACK_VERSION_LATEST as usize {
                let prod_bytes = product.as_bytes();
                out.extend_from_slice(&(prod_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(prod_bytes);
                let sig_offset = 4 + 1 + 2 + prod_bytes.len();
                out.extend_from_slice(&original[sig_offset..sig_offset + 64]);
            }
            let dlc_bytes = did.as_bytes();
            out.extend_from_slice(&(dlc_bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(dlc_bytes);
            let manifest: Vec<ManifestEntry> = entries
                .iter()
                .map(|(p, enc)| ManifestEntry {
                    path: p.clone(),
                    original_extension: if enc.original_extension.is_empty() {
                        None
                    } else {
                        Some(enc.original_extension.clone())
                    },
                    type_path: enc.type_path.clone(),
                })
                .collect();
            let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
            out.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&manifest_bytes);
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&ciphertext);
            out
        }

        // create a pristine pack containing a single entry
        let dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("example");
        let item = PackItem::new("a.txt", b"hello".to_vec()).unwrap();
        let base_pack = pack_encrypted_pack(
            &DlcId::from("dlcA".to_string()),
            &[item],
            &product,
            &dlc_key,
            &enc_key,
        )
        .unwrap();

        // inject stray entry into the encrypted blob
        let bytes = add_stray_to_pack(&base_pack, &enc_key, "test.lua", b"bad");

        let dir = tempdir().unwrap();
        let tmp_pack = dir.path().join("copy.dlcpack");
        std::fs::write(&tmp_pack, &bytes).unwrap();

        let (_prod, _did, _ver, mut entries) = parse_encrypted_pack(&bytes).unwrap();
        let mut added_files = std::collections::HashMap::new();

        // merging the pack into itself should detect and skip the stray file
        merge_pack_into(
            &tmp_pack,
            &mut entries,
            &mut added_files,
            Some(&enc_key),
            "example",
            "dlcA",
        )
        .unwrap();

        assert!(
            !entries.iter().any(|(p, _)| p == "test.lua"),
            "unexpected unmanifested entry added"
        );
        assert!(!added_files.contains_key("test.lua"));

        // verify the on-disk copy still contains the stray file
        let cleaned_bytes = std::fs::read(&tmp_pack).unwrap();
        let mut found_in_disk = false;
        {
            use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
            use flate2::read::GzDecoder;
            use secure_gate::ExposeSecret;
            use tar::Archive;

            let cipher = enc_key
                .with_secret(|s| Aes256Gcm::new_from_slice(s))
                .unwrap();
            let (_, _, _, disk_entries) = parse_encrypted_pack(&cleaned_bytes).unwrap();
            if let Some((_, first)) = disk_entries.first() {
                let nonce = Nonce::from_slice(&first.nonce);
                let pt = cipher.decrypt(nonce, first.ciphertext.as_ref()).unwrap();
                let decoder = GzDecoder::new(&pt[..]);
                let mut archive = Archive::new(decoder);
                for entry_res in archive.entries().unwrap() {
                    let entry = entry_res.unwrap();
                    if entry.path().unwrap().to_string_lossy() == "test.lua" {
                        found_in_disk = true;
                        break;
                    }
                }
            }
        }
        assert!(
            found_in_disk,
            "pack should still contain stray entry on disk since we don't rewrite"
        );
    }

    #[test]
    fn save_pack_removes_deleted_entries() {
        // ensure that removing an item and saving does not leave its data in
        // the encrypted archive.
        let dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("prod");
        let id = DlcId::from("removal".to_string());
        let item1 = PackItem::new("a.txt", b"one".to_vec()).unwrap();
        let item2 = PackItem::new("b.txt", b"two".to_vec()).unwrap();
        let bytes = pack_encrypted_pack(&id, &[item1, item2], &product, &dlc_key, &enc_key)
            .unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("pack.dlcpack");
        std::fs::write(&path, &bytes).unwrap();

        let (_prod, _did, ver, mut entries) = parse_encrypted_pack(&bytes).unwrap();
        // drop b.txt from manifest
        entries.retain(|(p, _)| p != "b.txt");
        let added_files = std::collections::HashMap::new();

        // save with no added files -- removal should trigger repack
        save_pack_optimized(&path, &bytes, ver, &product.get(), &id.to_string(), &entries, &added_files, Some(&enc_key))
            .unwrap();

        // decrypt resulting pack and confirm only a.txt remains
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        use flate2::read::GzDecoder;
        use secure_gate::ExposeSecret;
        use tar::Archive;

        let cipher = enc_key
            .with_secret(|s| Aes256Gcm::new_from_slice(s))
            .unwrap();
        let saved_bytes = std::fs::read(&path).unwrap();
        match parse_encrypted_pack(&saved_bytes) {
            Ok((_, _, _, disk_entries)) => {
                // manifest should reflect the removed file
                assert_eq!(disk_entries.len(), 1);
                if let Some((_, first)) = disk_entries.first() {
                    let nonce = Nonce::from_slice(&first.nonce);
                    let pt = cipher.decrypt(nonce, first.ciphertext.as_ref()).unwrap();
                    let decoder = GzDecoder::new(&pt[..]);
                    let mut archive = Archive::new(decoder);
                    let paths: Vec<_> = archive
                        .entries()
                        .unwrap()
                        .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
                        .collect();
                    assert_eq!(paths, vec!["a.txt"]);
                }
            }
            Err(e) => {
                eprintln!("parse failed: {:?}", e);
                eprintln!("saved bytes len = {}", saved_bytes.len());
                let dump_len = saved_bytes.len().min(64);
                eprintln!("first {} bytes: {:02x?}", dump_len, &saved_bytes[..dump_len]);
                panic!("save pack parse error");
            }
        }
    }

    #[test]
    fn edit_one_shot_ls() {
        // verify that providing a command after '--' runs it and exits
        let dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("prod");
        let item = PackItem::new("foo.txt", b"hello".to_vec()).unwrap();
        let bytes = pack_encrypted_pack(
            &DlcId::from("p".to_string()),
            &[item],
            &product,
            &dlc_key,
            &enc_key,
        )
        .unwrap();

        let tmp = tempdir().unwrap();
        let pack_path = tmp.path().join("p.dlcpack");
        std::fs::write(&pack_path, &bytes).unwrap();

        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("edit").arg("p.dlcpack").arg("--").arg("ls");
        cmd.assert()
            .success()
            // color codes may surround the DLC ID so just look for the prefix
            .stdout(
                predicates::str::contains("Entries in ")
                    .and(predicates::str::contains("foo.txt"))
                    // initial entry count message with plain number
                    .and(predicates::str::contains("Entries: 1")),
            );
    }

    #[test]
    fn edit_dry_run_save_does_not_modify() {
        let tmp = tempdir().unwrap();
        let pack_path = tmp.path().join("p.dlcpack");
        let dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("prod");
        let item = PackItem::new("foo.txt", b"hello".to_vec()).unwrap();
        let bytes = pack_encrypted_pack(
            &DlcId::from("p".to_string()),
            &[item],
            &product,
            &dlc_key,
            &enc_key,
        )
        .unwrap();
        std::fs::write(&pack_path, &bytes).unwrap();

        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("--dry-run").arg("edit").arg("p.dlcpack");
        cmd.write_stdin("rm foo.txt\nsave\nexit\n");
        cmd.assert().success();

        let data = std::fs::read(&pack_path).unwrap();
        let (_p, _id, _v, entries) = parse_encrypted_pack(&data).unwrap();
        assert!(entries.iter().any(|(p, _)| p == "foo.txt"));
    }

    #[test]
    fn merge_with_delete_and_dry_run_behaviour() {
        let dlc_key = DlcKey::generate_random();
        let product = Product::from("prod");

        // create a signed license for pack B and compute the corresponding
        // encryption key; we'll use the same key for both packs so the merge
        // helper can decrypt the source using the license token.
        let signed_b = dlc_key
            .create_signed_license(&[DlcId::from("b".to_string())], product.clone())
            .unwrap();
        let enc_key: EncryptionKey = bevy_dlc::extract_encrypt_key_from_license(&signed_b)
            .expect("license should contain encrypt_key");

        let item_a = PackItem::new("a.txt", b"foo".to_vec()).unwrap();
        let bytes_a = pack_encrypted_pack(
            &DlcId::from("a".to_string()),
            &[item_a],
            &product,
            &dlc_key,
            &enc_key,
        )
        .unwrap();
        let item_b = PackItem::new("b.txt", b"bar".to_vec()).unwrap();
        let bytes_b = pack_encrypted_pack(
            &DlcId::from("b".to_string()),
            &[item_b],
            &product,
            &dlc_key,
            &enc_key,
        )
        .unwrap();

        let tmp = tempdir().unwrap();
        let path_a = tmp.path().join("a.dlcpack");
        let path_b = tmp.path().join("b.dlcpack");
        std::fs::write(&path_a, &bytes_a).unwrap();
        std::fs::write(&path_b, &bytes_b).unwrap();

        // convert the previously-created license token into strings we can
        // pass on the CLI.
        let mut lic_str = String::new();
        signed_b.with_secret(|s| lic_str = s.to_string());
        let pub_b64 = URL_SAFE_NO_PAD.encode(dlc_key.get_public_key().get());

        // normal merge with delete
        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("edit")
            .arg("a.dlcpack")
            .arg("--")
            .arg("merge")
            .arg("b.dlcpack")
            .arg("--signed-license")
            .arg(&lic_str)
            .arg("--pubkey")
            .arg(&pub_b64)
            .arg("-d");
        cmd.assert().success();
        let output = cmd.output().expect("failed to read output");
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        assert!(!path_b.exists());

        // recreate b and perform dry-run merge+delete
        std::fs::write(&path_b, &bytes_b).unwrap();
        let mut cmd2 = Command::new(pkg_name!());
        cmd2.current_dir(tmp.path());
        cmd2.arg("--dry-run")
            .arg("edit")
            .arg("a.dlcpack")
            .arg("--")
            .arg("merge")
            .arg("b.dlcpack")
            .arg("--signed-license")
            .arg(&lic_str)
            .arg("--pubkey")
            .arg(&pub_b64)
            .arg("-d");
        cmd2.assert().success();
        assert!(path_b.exists());
    }

    #[test]
    fn pack_and_generate_dry_run() {
        let tmp = tempdir().unwrap();
        let file_path = tmp.path().join("foo.txt");
        std::fs::write(&file_path, b"data").unwrap();

        // pack dry-run
        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("--dry-run")
            .arg("pack")
            .arg("mypack")
            .arg("--product")
            .arg("prod")
            .arg("--types")
            .arg("txt=DummyType")
            .arg("--")
            .arg(file_path.to_str().unwrap());
        // run pack command with dry-run; we don't need to examine stderr in
        // the final test version since functionality is covered by earlier
        // debugging.
        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("--dry-run")
            .arg("pack")
            .arg("mypack")
            .arg("--product")
            .arg("prod")
            .arg("--types")
            .arg("txt=DummyType")
            .arg("--")
            .arg(file_path.to_str().unwrap());
        cmd.assert().success();
        assert!(!tmp.path().join("mypack.dlcpack").exists());
        assert!(!tmp.path().join("prod.slicense").exists());
        assert!(!tmp.path().join("prod.pubkey").exists());

        // generate dry-run
        let mut cmd2 = Command::new(pkg_name!());
        cmd2.current_dir(tmp.path());
        cmd2.arg("--dry-run")
            .arg("generate")
            .arg("prod")
            .arg("dlc1");
        cmd2.assert().success();
        assert!(!tmp.path().join("prod.slicense").exists());
        assert!(!tmp.path().join("prod.pubkey").exists());
    }

    #[test]
    fn generate_refuses_overwrite_with_invalid_files() {
        let tmp = tempdir().unwrap();
        let prod = "prod";
        let sl = tmp.path().join("prod.slicense");
        let pk = tmp.path().join("prod.pubkey");
        // drop some garbage into both files
        std::fs::write(&sl, "not-a-license").unwrap();
        std::fs::write(&pk, "not-a-pubkey").unwrap();

        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("generate").arg(prod).arg("dlcA");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("not a valid"));

        // force should override even though contents are invalid
        let mut cmd2 = Command::new(pkg_name!());
        cmd2.current_dir(tmp.path());
        cmd2.arg("generate").arg("--force").arg(prod).arg("dlcA");
        cmd2.assert().success();
    }

    #[test]
    fn generate_refuses_overwrite_with_valid_files() {
        let tmp = tempdir().unwrap();
        let prod = "prod";

        // produce a sane pair first
        let mut cmd_gen = Command::new(pkg_name!());
        cmd_gen.current_dir(tmp.path());
        cmd_gen.arg("generate").arg(prod).arg("dlcA");
        cmd_gen.assert().success();

        // running again without force should emit the generic exists message
        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("generate").arg(prod).arg("dlcA");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("already exists"));
    }

    #[test]
    fn exit_prompt_saves_if_yes() {
        let tmp = tempdir().unwrap();
        let pack_path = tmp.path().join("p.dlcpack");
        let dlc_key = DlcKey::generate_random();
        let product = Product::from("prod");
        // generate license now so we can derive the symmetric key for packing
        let signed = dlc_key
            .create_signed_license(&["p"], product.clone())
            .unwrap();
        let signed_str = signed.expose_secret().to_string();
        let key_bytes = bevy_dlc::extract_encrypt_key_from_license(&signed).unwrap();
        let enc_key = EncryptionKey::from(key_bytes);

        let item = PackItem::new("foo.txt", b"hello".to_vec()).unwrap();
        let bytes = pack_encrypted_pack(
            &DlcId::from("p".to_string()),
            &[item],
            &product,
            &dlc_key,
            &enc_key,
        )
        .unwrap();
        std::fs::write(&pack_path, &bytes).unwrap();

        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("edit")
            .arg("p.dlcpack")
            .arg("--signed-license")
            .arg(&signed_str);
        cmd.write_stdin("rm foo.txt\nexit\ny\n");
        cmd.assert().success();

        let data = std::fs::read(&pack_path).unwrap();
        let (_p, _id, _v, entries) = parse_encrypted_pack(&data).unwrap();
        assert!(!entries.iter().any(|(p, _)| p == "foo.txt"));
    }
}
