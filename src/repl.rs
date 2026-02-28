use bevy_dlc::{DLC_PACK_MAGIC, EncryptionKey, parse_encrypted_pack, prelude::*};
use secure_gate::ExposeSecret;
use clap::{Arg, ArgAction, Command};
use owo_colors::{AnsiColors, CssColors, OwoColorize};
use std::io::{ErrorKind, Write, stdin, stdout};
use std::path::{Path, PathBuf};

use crate::{is_executable, print_error, resolve_keys};

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
    let file = std::fs::File::open(&path)?;
    let mut reader = std::io::BufReader::new(file);
    let (product, mut dlc_id, version, mut entries, block_metadatas) =
        parse_encrypted_pack(&mut reader)?;

    safe_println!(
        "{} {} (v{}, {}: {}, dlc: {})",
        "REPL".color(AnsiColors::Cyan).bold(),
        path.display().to_string().color(AnsiColors::Cyan),
        version,
        "product".color(AnsiColors::Blue),
        product.as_ref().color(AnsiColors::Magenta).bold(),
        dlc_id.as_str().color(AnsiColors::Magenta).bold()
    );

    let adding_enabled = if encrypt_key.is_some() {
        format!("{}", "Adding new files enabled.".green())
    } else {
        format!("{}", "Adding new files disabled, no signed license.".yellow())
    };

    safe_println!("{}.", adding_enabled);
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
                        safe_println!(" Product: {}", product.as_ref().color(AnsiColors::Blue));
                        safe_println!(" DLC ID: {}", dlc_id.color(AnsiColors::Magenta));
                        safe_println!(
                            " Version: {}",
                            version.to_string().color(AnsiColors::Yellow)
                        );
                        // report both the encrypted archive blob length and the
                        // actual file size on disk.  if the user saved without a key
                        // (manifest-only change) then only the manifest shrinks and the
                        // archive bytes stay the same.
                        let archive_size: u64 = if version >= 4 {
                            block_metadatas.iter().map(|b| b.encrypted_size as u64).sum()
                        } else if version >= 2 {
                            entries.get(0).map(|(_, e)| e.ciphertext.len() as u64).unwrap_or(0)
                        } else {
                            entries.iter().map(|(_, e)| e.ciphertext.len() as u64).sum()
                        };

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
                                " [{}] {} (ext: {}, size: {}) type: {}",
                                i.color(AnsiColors::Cyan),
                                p.as_str().color(AnsiColors::Green),
                                enc.original_extension.as_str().color(AnsiColors::Yellow),
                                bevy_dlc::human_bytes!(enc.size as u64).color(CssColors::SlateGray),
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
                                    dlc_id: dlc_id.to_string(),
                                    original_extension: pack_item.ext().unwrap_or_default(),
                                    type_path: pack_item.type_path(),
                                    nonce: [0u8; 12],
                                    ciphertext: vec![].into(),
                                    block_id: 0,
                                    block_offset: 0,
                                    size: 0,
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
                        dlc_id = bevy_dlc::DlcId(new_id.clone());
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
                            if let Ok(file) = std::fs::File::open(other_path) {
                                let mut reader = std::io::BufReader::new(file);
                                if let Ok((other_prod, _other_did, _ver, _ents, _blocks)) =
                                    parse_encrypted_pack(&mut reader)
                                {
                                    let (_resolved_pubkey, resolved_license): (
                                        Option<crate::DlcKey>,
                                        Option<crate::SignedLicense>,
                                    ) = resolve_keys(
                                        sub.get_one::<String>("pubkey").cloned(),
                                        sub.get_one::<String>("signed_license").cloned(),
                                        Some(other_prod.clone()),
                                        None,
                                    );
                                    if encrypt_key.is_none() {
                                        if let Some(lic) = resolved_license.as_ref() {
                        if let Some(enc_key) = bevy_dlc::extract_encrypt_key_from_license(lic) {
                            let key_bytes: Vec<u8> = enc_key.with_secret(|kb| kb.to_vec());
                            encrypt_key = Some(EncryptionKey::from(key_bytes));
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
    _version: usize,
    product: &Product,
    dlc_id: &DlcId,
    entries: &[(String, EncryptedAsset)],
    added_files: &std::collections::HashMap<String, Vec<u8>>,
    encrypt_key: Option<&EncryptionKey>,
) -> Result<(), Box<dyn std::error::Error>> {
    use flate2::read::GzDecoder;
    use tar::Archive;
    use std::io::{Read, Seek, SeekFrom};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use secure_gate::ExposeSecret;

    // determine whether entries were removed
    let (old_entries, blocks) = {
        let mut file = std::fs::File::open(path)?;
        let (_old_prod, _old_did, _old_v, old_entries, blocks) = parse_encrypted_pack(&mut file)?;
        (old_entries, blocks)
    };
    let removed = old_entries.len() > entries.len();

    // simple metadata-only update (if nothing added/removed)
    if added_files.is_empty() && !removed {
        return update_manifest(path, bevy_dlc::DLC_PACK_VERSION_LATEST as usize, product, dlc_id, entries);
    }

    let ek = encrypt_key
        .ok_or("Re-packing with new files requires a signed license (--signed-license)")?;

    let mut items = Vec::new();
    let cipher = ek
        .with_secret(|s| Aes256Gcm::new_from_slice(s))
        .map_err(|_| "cipher init")?;

    // 1. Recover existing files from old pack
    {
        let mut file = std::fs::File::open(path)?;
        let block_data = if !blocks.is_empty() {
            // v4
            let mut configs = Vec::new();
            for b in blocks {
                file.seek(SeekFrom::Start(b.file_offset))?;
                let mut ct = vec![0u8; b.encrypted_size as usize];
                file.read_exact(&mut ct)?;
                configs.push((b.nonce, ct));
            }
            configs
        } else if let Some((_, first)) = old_entries.first() {
            // legacy
            vec![(first.nonce, first.ciphertext.to_vec())]
        } else {
            vec![]
        };

        for (nonce_bytes, ct) in block_data {
            let nonce = Nonce::from_slice(&nonce_bytes);
            let pt = cipher
                .decrypt(nonce, ct.as_slice())
                .map_err(|_| "Decryption failed (key may be incorrect for this pack)")?;
            let mut archive = Archive::new(GzDecoder::new(&pt[..]));
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path_str = entry.path()?.to_string_lossy().to_string();
                if entries.iter().any(|(p, _)| p == &path_str) {
                    let mut data = Vec::new();
                    std::io::copy(&mut entry, &mut data)?;
                    let mut item = PackItem::new(path_str.clone(), data)?;
                    // preserve type_path
                    if let Some((_, e)) = old_entries.iter().find(|(p, _)| p == &path_str) {
                        if let Some(tp) = &e.type_path {
                            item = item.with_type_path(tp);
                        }
                    }
                    items.push(item);
                }
            }
        }
    }

    // 2. Add newly staged files
    for (p, data) in added_files {
        let mut item = PackItem::new(p.clone(), data.clone())?;
        // try to find type_path in current manifest (if it was set by user)
        if let Some((_, e)) = entries.iter().find(|(path, _)| path == p) {
            if let Some(tp) = &e.type_path {
                item = item.with_type_path(tp);
            }
        }
        items.push(item);
    }

    // 3. Re-pack using latest format
    let bytes = bevy_dlc::pack_encrypted_pack(dlc_id, &items, product, ek)
        .map_err(|e: bevy_dlc::DlcError| e.to_string())?;
    std::fs::write(path, bytes)?;

    Ok(())
}

/// Update the manifest and headers of the pack without re-encrypting the archive (only works if no files were added/removed, just metadata changes)
fn update_manifest(
    path: &Path,
    version: usize,
    product: &Product,
    dlc_id: &DlcId,
    entries: &[(String, EncryptedAsset)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    out.extend_from_slice(DLC_PACK_MAGIC);
    out.push(version as u8);

    if version == 4 {
        // v4 header
        let prod_bytes = product.as_str().as_bytes();
        out.extend_from_slice(&(prod_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(prod_bytes);

        let dlc_bytes = dlc_id.as_str().as_bytes();
        out.extend_from_slice(&(dlc_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(dlc_bytes);

        // Manifest
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (p, enc) in entries {
            let p_bytes = p.as_bytes();
            out.extend_from_slice(&(p_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(p_bytes);

            let ext_bytes = enc.original_extension.as_bytes();
            out.push(ext_bytes.len() as u8);
            out.extend_from_slice(ext_bytes);

            if let Some(tp) = &enc.type_path {
                let tp_bytes = tp.as_bytes();
                out.extend_from_slice(&(tp_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(tp_bytes);
            } else {
                out.extend_from_slice(&0u16.to_be_bytes());
            }

            out.extend_from_slice(&enc.block_id.to_be_bytes());
            out.extend_from_slice(&enc.block_offset.to_be_bytes());
            out.extend_from_slice(&enc.size.to_be_bytes());
        }

        // We need to preserve the blocks from the original file
        let mut file = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(&mut file);
        let (_p, _id, _v, _e, blocks) = parse_encrypted_pack(&mut reader)?;
        
        out.extend_from_slice(&(blocks.len() as u32).to_be_bytes());
        
        let mut block_data_to_copy = Vec::new();
        for b in blocks {
            // Write metadata (File offset will need update!)
            out.extend_from_slice(&b.block_id.to_be_bytes());
            
            // We'll update the offset later
            let offset_pos = out.len();
            out.extend_from_slice(&0u64.to_be_bytes());
            
            out.extend_from_slice(&b.encrypted_size.to_be_bytes());
            out.extend_from_slice(&b.uncompressed_size.to_be_bytes());
            out.extend_from_slice(&b.nonce);
            out.extend_from_slice(&b.crc32.to_be_bytes());
            
            // Read block ciphertext
            use std::io::{Seek, SeekFrom, Read};
            file.seek(SeekFrom::Start(b.file_offset))?;
            let mut ct = vec![0u8; b.encrypted_size as usize];
            file.read_exact(&mut ct)?;
            block_data_to_copy.push((offset_pos, ct));
        }
        
        // Append blocks and update offsets
        for (offset_pos, ct) in block_data_to_copy {
            let current_pos = out.len() as u64;
            out[offset_pos..offset_pos+8].copy_from_slice(&current_pos.to_be_bytes());
            out.extend_from_slice(&ct);
        }

    } else {
        // legacy formats are no longer supported; this branch should never be
        // taken because all packs are assumed to be v4.  If we do hit it we
        // bail out early so the caller can handle the error.
        return Err("pack format <4 is unsupported".into());
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
    current_product: &Product,
    current_dlc_id: &DlcId,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use flate2::read::GzDecoder;
    use secure_gate::ExposeSecret;
    use tar::Archive;

    let ek = encrypt_key.ok_or("encryption key required to merge")?;

    let mut file = std::fs::File::open(other_pack)?;
    let (other_prod, _other_did, _ver, other_entries, blocks) = parse_encrypted_pack(&mut file)?;

    if other_prod != *current_product {
        return Err(format!(
            "cannot merge two different products '{}' into '{}'",
            other_prod, current_product
        )
        .into());
    }

    if other_entries.is_empty() {
        return Ok(Vec::new());
    }

    // decrypt blobs from the other pack (v4 or legacy)
    let cipher = ek
        .with_secret(|s| Aes256Gcm::new_from_slice(s))
        .map_err(|_| "cipher init")?;

    let mut strays: Vec<String> = Vec::new();

    if blocks.is_empty() {
        // unsupported legacy format
        return Err("cannot merge from pre-v4 pack".into());
    } else {
        // v4 multi-block
        use std::io::{Read, Seek, SeekFrom};
        for block in blocks {
            file.seek(SeekFrom::Start(block.file_offset))?;
            let mut ciphertext = vec![0u8; block.encrypted_size as usize];
            file.read_exact(&mut ciphertext)?;

            let nonce = Nonce::from_slice(&block.nonce);
            let pt = cipher
                .decrypt(nonce, ciphertext.as_slice())
                .map_err(|_| "decryption failed (key mismatch?)")?;
            let decoder = GzDecoder::new(&pt[..]);
            let mut archive = Archive::new(decoder);
            for entry_res in archive.entries()? {
                let mut entry = entry_res?;
                let path = entry.path()?.to_string_lossy().to_string();
                process_merge_entry(
                    &mut entry,
                    path,
                    &other_entries,
                    &mut strays,
                    entries,
                    added_files,
                    current_dlc_id,
                )?;
            }
        }
    }

    // stray entries are intentionally ignored; we don't mutate the
    // source pack. if the caller wants the archive cleaned they can
    // repack manually using `save` or the CLI.  Strays should not happen anymore.
    if !strays.is_empty() {
        safe_println!(
            "{} warning: pack contains unmanifested files; they were skipped. Repack using 'bevy-dlc pack':\n{}",
            "warning".yellow().bold(),
            strays.join(", "),
        );
    }

    Ok(strays)
}

fn process_merge_entry(
    entry: &mut tar::Entry<impl std::io::Read>,
    path: String,
    other_entries: &[(String, EncryptedAsset)],
    strays: &mut Vec<String>,
    entries: &mut Vec<(String, EncryptedAsset)>,
    added_files: &mut std::collections::HashMap<String, Vec<u8>>,
    current_dlc_id: &DlcId,
) -> Result<(), Box<dyn std::error::Error>> {
    // Only consider files that are listed in the source pack's manifest.
    if !other_entries.iter().any(|(p, _)| p == &path) {
        strays.push(path.clone());
        return Ok(());
    }

    if entries.iter().any(|(p, _)| p == &path) || added_files.contains_key(&path) {
        return Ok(());
    }

    let mut data = Vec::new();
    std::io::copy(entry, &mut data)?;

    let mut pack_item = PackItem::new(path.clone(), data)?;
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
            block_id: 0,
            block_offset: 0,
            size: 0,
        },
    ));
    safe_println!("Merged entry: {}", path.color(AnsiColors::Green));

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
        let _dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("prod");

        let item1 = PackItem::new("a.txt", b"foo".to_vec()).unwrap();
        let bytes_a = pack_encrypted_pack(
            &DlcId::from("a".to_string()),
            &[item1],
            &product,
            &enc_key,
        )
        .unwrap();

        let item2 = PackItem::new("b.txt", b"bar".to_vec()).unwrap();
        let bytes_b = pack_encrypted_pack(
            &DlcId::from("b".to_string()),
            &[item2],
            &product,
            &enc_key,
        )
        .unwrap();

        let dir = tempdir().unwrap();
        let path_a = dir.path().join("a.dlcpack");
        let path_b = dir.path().join("b.dlcpack");
        std::fs::write(&path_a, &bytes_a).unwrap();
        std::fs::write(&path_b, &bytes_b).unwrap();

        let (_p, _id, _ver, mut entries, _b) = parse_encrypted_pack(&bytes_a[..]).unwrap();
        let mut added_files = std::collections::HashMap::new();

        // merge pack B into A
        let strays = merge_pack_into(
            &path_b,
            &mut entries,
            &mut added_files,
            Some(&enc_key),
            &Product::from("prod"),
            &DlcId::from("a"),
        )
        .unwrap();
        assert!(strays.is_empty());

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
            use flate2::{Compression, read::GzDecoder, write::GzEncoder};
            use secure_gate::ExposeSecret;
            use tar::Archive;
            use std::io::{Read, Seek, SeekFrom};

            // parse header from the existing pack so we can rebuild
            let mut reader = std::io::Cursor::new(original);
            let (product, did, _ver, entries, blocks) =
                parse_encrypted_pack(&mut reader).expect("parse original pack");

            // decrypt the first block to get the tar
            let cipher = encrypt_key
                .with_secret(|s| Aes256Gcm::new_from_slice(s))
                .expect("cipher init");

            let (nonce_bytes, ciphertext) = if blocks.is_empty() {
                // legacy
                let first = &entries[0].1;
                (first.nonce, first.ciphertext.clone())
            } else {
                // v4
                let first_block = &blocks[0];
                let mut data = vec![0u8; first_block.encrypted_size as usize];
                reader.seek(SeekFrom::Start(first_block.file_offset)).unwrap();
                reader.read_exact(&mut data).unwrap();
                (first_block.nonce, std::sync::Arc::from(data))
            };

            let nonce = Nonce::from_slice(&nonce_bytes);
            let pt = cipher
                .decrypt(nonce, ciphertext.as_ref())
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

            // rebuild using the actual packer to ensure v4 format is correct
            // but we want to KEEP the original manifest (to test stray detection)
            let _items: Vec<PackItem> = existing.into_iter().map(|(p, d)| {
                PackItem::new(p, d).unwrap()
            }).collect();
            
            // If we use the standard packer it will update the manifest.
            // So we manually build the v4 pack but use the OLD manifest entries.
            
            let _encrypted_size = compressed.len() as u32;
            let new_nonce: [u8; 12] = rand::random();
            let cipher2 = encrypt_key
                .with_secret(|s| Aes256Gcm::new_from_slice(s))
                .expect("cipher init");
            let new_ciphertext = cipher2.encrypt(Nonce::from_slice(&new_nonce), compressed.as_ref()).unwrap();
            
            // Reconstruct a minimalist v4 pack
            let mut out = Vec::new();
            out.extend_from_slice(DLC_PACK_MAGIC);
            out.push(4); // version
            
            let p_bytes = product.as_str().as_bytes();
            out.extend_from_slice(&(p_bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(p_bytes);
            
            let d_bytes = did.as_str().as_bytes();
            out.extend_from_slice(&(d_bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(d_bytes);
            
            // Manifest count (use original entries)
            out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
            for (path, enc) in entries {
                // write binary entry (V4 format)
                let p_bytes = path.as_bytes();
                out.extend_from_slice(&(p_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(p_bytes);
                
                let ext_bytes = enc.original_extension.as_bytes();
                out.push(ext_bytes.len() as u8);
                out.extend_from_slice(ext_bytes);
                
                if let Some(tp) = enc.type_path {
                    let tp_bytes = tp.as_bytes();
                    out.extend_from_slice(&(tp_bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(tp_bytes);
                } else {
                    out.extend_from_slice(&0u16.to_be_bytes());
                }
                
                out.extend_from_slice(&0u32.to_be_bytes()); // block_id
                out.extend_from_slice(&0u32.to_be_bytes()); // block_offset (not perfect but OK for test)
                out.extend_from_slice(&0u32.to_be_bytes()); // size
            }
            
            // Block count (1)
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes()); // block_id
            
            let _header_size = out.len() as u64 + 8 + 4 + 4 + 12 + 4; // approximate
            out.extend_from_slice(&0u64.to_be_bytes()); // temp offset
            let offset_pos = out.len() - 8;
            
            out.extend_from_slice(&(new_ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes()); // uncompressed
            out.extend_from_slice(&new_nonce);
            out.extend_from_slice(&0u32.to_be_bytes()); // crc
            
            let final_offset = out.len() as u64;
            let offset_bytes = final_offset.to_be_bytes();
            out[offset_pos..offset_pos+8].copy_from_slice(&offset_bytes);
            
            out.extend_from_slice(&new_ciphertext);
            out
        }

        // create a pristine pack containing a single entry
        let _dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("example");
        let item = PackItem::new("a.txt", b"hello".to_vec()).unwrap();
        let base_pack = pack_encrypted_pack(
            &DlcId::from("dlcA".to_string()),
            &[item],
            &product,
            &enc_key,
        )
        .unwrap();

        // inject stray entry into the encrypted blob
        let bytes = add_stray_to_pack(&base_pack, &enc_key, "test.lua", b"bad");

        let dir = tempdir().unwrap();
        let tmp_pack = dir.path().join("copy.dlcpack");
        std::fs::write(&tmp_pack, &bytes).unwrap();

        let (_prod, _did, _ver, mut entries, _b) = parse_encrypted_pack(&bytes[..]).unwrap();
        let mut added_files = std::collections::HashMap::new();

        // merging the pack into itself should detect and skip the stray file
        let strays = merge_pack_into(
            &tmp_pack,
            &mut entries,
            &mut added_files,
            Some(&enc_key),
            &Product::from("example"),
            &DlcId::from("dlcA"),
        )
        .unwrap();
        assert_eq!(strays, vec!["test.lua".to_string()]);

        assert!(
            !entries.iter().any(|(p, _)| p == "test.lua"),
            "unexpected unmanifested entry added"
        );
        assert!(!added_files.contains_key("test.lua"));

        // verify the on-disk copy still contains the stray file
        let mut file = std::fs::File::open(&tmp_pack).unwrap();
        let mut found_in_disk = false;
        {
            use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
            use flate2::read::GzDecoder;
            use secure_gate::ExposeSecret;
            use tar::Archive;
            use std::io::{Read, Seek, SeekFrom};

            let cipher = enc_key
                .with_secret(|s| Aes256Gcm::new_from_slice(s))
                .unwrap();
            let (_, _, _, disk_entries, blocks) = parse_encrypted_pack(&mut file).unwrap();
            
            let block_data = if blocks.is_empty() {
                let first = &disk_entries[0].1;
                (first.nonce, first.ciphertext.clone())
            } else {
                let b = &blocks[0];
                file.seek(SeekFrom::Start(b.file_offset)).unwrap();
                let mut data = vec![0u8; b.encrypted_size as usize];
                file.read_exact(&mut data).unwrap();
                (b.nonce, std::sync::Arc::from(data))
            };

            let nonce = Nonce::from_slice(&block_data.0);
            let pt = cipher.decrypt(nonce, block_data.1.as_ref()).unwrap();
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
        assert!(
            found_in_disk,
            "pack should still contain stray entry on disk since we don't rewrite"
        );
    }

    #[test]
    fn save_pack_removes_deleted_entries() {
        // ensure that removing an item and saving does not leave its data in
        // the encrypted archive.
        let _dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("prod");
        let id = DlcId::from("removal".to_string());
        let item1 = PackItem::new("a.txt", b"one".to_vec()).unwrap();
        let item2 = PackItem::new("b.txt", b"two".to_vec()).unwrap();
        let bytes =
            pack_encrypted_pack(&id, &[item1, item2], &product, &enc_key).unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("pack.dlcpack");
        std::fs::write(&path, &bytes).unwrap();

        let (_prod, _did, ver, mut entries, _) = parse_encrypted_pack(&bytes[..]).unwrap();
        // drop b.txt from manifest
        entries.retain(|(p, _)| p != "b.txt");
        let added_files = std::collections::HashMap::new();

        // save with no added files -- removal should trigger repack
        save_pack_optimized(
            &path,
            ver,
            &product,
            &id,
            &entries,
            &added_files,
            Some(&enc_key),
        )
        .unwrap();

        // decrypt resulting pack and confirm only a.txt remains
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        use flate2::read::GzDecoder;
        use secure_gate::ExposeSecret;
        use tar::Archive;
        use std::io::{Read, Seek, SeekFrom};

        let cipher = enc_key
            .with_secret(|s| Aes256Gcm::new_from_slice(s))
            .unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        match parse_encrypted_pack(&mut file) {
            Ok((_, _, _, disk_entries, blocks)) => {
                // manifest should reflect the removed file
                assert_eq!(disk_entries.len(), 1);

                let block_data = if blocks.is_empty() {
                    let first = &disk_entries[0].1;
                    (first.nonce, first.ciphertext.clone())
                } else {
                    let b = &blocks[0];
                    file.seek(SeekFrom::Start(b.file_offset)).unwrap();
                    let mut data = vec![0u8; b.encrypted_size as usize];
                    file.read_exact(&mut data).unwrap();
                    (b.nonce, std::sync::Arc::from(data))
                };

                let nonce = Nonce::from_slice(&block_data.0);
                let pt = cipher.decrypt(nonce, block_data.1.as_ref()).unwrap();
                let decoder = GzDecoder::new(&pt[..]);
                let mut archive = Archive::new(decoder);
                let paths: Vec<_> = archive
                    .entries()
                    .unwrap()
                    .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
                    .collect();
                assert_eq!(paths, vec!["a.txt"]);
            }
            Err(e) => {
                eprintln!("parse failed: {:?}", e);
                panic!("save pack parse error");
            }
        }
    }

    #[test]
    fn edit_one_shot_ls() {
        // verify that providing a command after '--' runs it and exits
        let _dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("prod");
        let item = PackItem::new("foo.txt", b"hello".to_vec()).unwrap();
        let bytes = pack_encrypted_pack(
            &DlcId::from("p".to_string()),
            &[item],
            &product,
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
            );
    }

    #[test]
    fn edit_dry_run_save_does_not_modify() {
        let tmp = tempdir().unwrap();
        let pack_path = tmp.path().join("p.dlcpack");
        let _dlc_key = DlcKey::generate_random();
        let enc_key = EncryptionKey::from_random(32);
        let product = Product::from("prod");
        let item = PackItem::new("foo.txt", b"hello".to_vec()).unwrap();
        let bytes = pack_encrypted_pack(
            &DlcId::from("p".to_string()),
            &[item],
            &product,
            &enc_key,
        )
        .unwrap();
        std::fs::write(&pack_path, &bytes).unwrap();

        let mut cmd = Command::new(pkg_name!());
        cmd.current_dir(tmp.path());
        cmd.arg("--dry-run").arg("edit").arg("p.dlcpack");
        cmd.write_stdin("rm foo.txt\nsave\nexit\n");
        cmd.assert().success();

        let file = std::fs::File::open(&pack_path).unwrap();
        let (_p, _id, _v, entries, _) = parse_encrypted_pack(file).unwrap();
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
            &enc_key,
        )
        .unwrap();
        let item_b = PackItem::new("b.txt", b"bar".to_vec()).unwrap();
        let bytes_b = pack_encrypted_pack(
            &DlcId::from("b".to_string()),
            &[item_b],
            &product,
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
        let pub_b64 = URL_SAFE_NO_PAD.encode(dlc_key.get_public_key().0);

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
            .arg(format!("--pubkey={}", pub_b64))
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
            .arg(pub_b64)
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
            .failure();

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
            .failure();
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

        let file = std::fs::File::open(&pack_path).unwrap();
        let (_p, _id, _v, entries, _) = parse_encrypted_pack(file).unwrap();
        assert!(!entries.iter().any(|(p, _)| p == "foo.txt"));
    }
}
