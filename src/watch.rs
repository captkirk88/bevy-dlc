use std::collections::{BTreeSet, HashMap};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use owo_colors::OwoColorize;

use bevy_dlc::{EncryptionKey, extract_encrypt_key_from_license, parse_encrypted_pack_info};

use crate::{
    collect_files_recursive, print_warning, repl::save_pack_with_replacements,
    resolve_keys_with_search_roots,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PackEntryTarget {
    pack_path: PathBuf,
    entry_path: String,
}

#[derive(Debug, Default)]
struct WatchIndex {
    by_source: HashMap<PathBuf, Vec<PackEntryTarget>>,
    fingerprints: HashMap<PathBuf, FileFingerprint>,
    watched_dirs: BTreeSet<PathBuf>,
    scanned_packs: usize,
    skipped_packs: usize,
    unresolved_entries: usize,
}

const WATCH_EXIT_AFTER_FIRST_EVENT_ENV: &str = "BEVY_DLC_WATCH_EXIT_AFTER_FIRST_EVENT";
const WATCH_READY_FILE_ENV: &str = "BEVY_DLC_WATCH_READY_FILE";

pub(crate) fn run_watch_command(dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let current_dir = std::env::current_dir()?;
    let root = canonicalize_existing_path(&current_dir);
    let mut index = scan_watch_index(&root)?;
    let watched_pack_count = unique_pack_count(&index);

    if index.by_source.is_empty() {
        return Err(format!(
            "found {} .dlcpack file(s), but no watchable source files were resolved",
            index.scanned_packs
        )
        .into());
    }

    println!(
        "{} {} source file(s) across {} .dlcpack file(s)",
        "watching".cyan().bold(),
        index.by_source.len().to_string().bold(),
        watched_pack_count.to_string().bold()
    );
    if index.skipped_packs > 0 || index.unresolved_entries > 0 {
        print_warning(
            format!(
                "skipped {} pack(s) and left {} entry path(s) unresolved during startup scan",
                index.skipped_packs, index.unresolved_entries
            )
            .as_str(),
        );
    }
    if dry_run {
        print_warning("dry-run: tracked changes will be reported but .dlcpack files will not be rewritten");
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let shutdown_requested = install_shutdown_handler()?;
    let mut watcher = RecommendedWatcher::new(
        move |result| {
            let _ = tx.send(result);
        },
        Config::default(),
    )?;

    for dir in &index.watched_dirs {
        watcher.watch(dir, RecursiveMode::NonRecursive)?;
    }

    write_watch_ready_file()?;

    loop {
        if shutdown_requested.load(Ordering::SeqCst) {
            return Ok(());
        }

        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(event)) => {
                let handled_change = handle_watch_event(&mut index, &event, dry_run);
                if handled_change && watch_should_exit_after_first_event() {
                    return Ok(());
                }
            }
            Ok(Err(error)) => {
                print_warning(format!("watch error: {}", error).as_str());
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(error) => {
                return Err(format!("watch channel closed: {}", error).into());
            }
        }
    }
}

fn install_shutdown_handler() -> Result<Arc<AtomicBool>, Box<dyn std::error::Error>> {
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&shutdown_requested);

    ctrlc::set_handler(move || {
        handler_flag.store(true, Ordering::SeqCst);
    })?;

    Ok(shutdown_requested)
}

fn handle_watch_event(index: &mut WatchIndex, event: &Event, dry_run: bool) -> bool {
    let mut affected_sources = BTreeSet::new();
    for event_path in &event.paths {
        let normalized_path = canonicalize_lossy_path(event_path);
        if index.by_source.contains_key(&normalized_path) {
            affected_sources.insert(normalized_path);
        }
    }

    let mut handled_change = false;

    for source_path in affected_sources {
        let Some(new_fingerprint) = read_fingerprint(&source_path).ok().flatten() else {
            print_warning(
                format!(
                    "tracked source file is missing or unreadable; skipping: {}",
                    display_path(&source_path)
                )
                .as_str(),
            );
            continue;
        };

        if index.fingerprints.get(&source_path) == Some(&new_fingerprint) {
            continue;
        }

        let repack_result = match index.by_source.get(&source_path) {
            Some(targets) => repack_source_for_targets(&source_path, targets, dry_run),
            None => Ok(()),
        };

        match repack_result {
            Ok(()) => {
                index.fingerprints.insert(source_path, new_fingerprint);
                handled_change = true;
            }
            Err(error) => {
                print_warning(error.to_string().as_str());
            }
        }
    }

    handled_change
}

fn repack_source_for_targets(
    source_path: &Path,
    targets: &[PackEntryTarget],
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let source_bytes = std::fs::read(source_path)?;

    for target in targets {
        repack_single_target(source_path, target, &source_bytes, dry_run)?;
    }

    Ok(())
}

fn repack_single_target(
    source_path: &Path,
    target: &PackEntryTarget,
    source_bytes: &[u8],
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (product, dlc_id, version, metadata, entries, encrypt_key) =
        load_pack_for_repack(&target.pack_path)?;

    if !entries
        .iter()
        .any(|(entry_path, _)| entry_path == &target.entry_path)
    {
        return Err(format!(
            "pack '{}' no longer contains entry '{}'",
            display_path(&target.pack_path),
            target.entry_path
        )
        .into());
    }

    if dry_run {
        println!(
            "{}: {} -> {}#{}",
            "detected change".yellow().bold(),
            display_path(source_path).cyan(),
            display_path(&target.pack_path).green(),
            target.entry_path.yellow()
        );
        return Ok(());
    }

    let added_files = HashMap::new();
    let mut replacement_files = HashMap::new();
    replacement_files.insert(target.entry_path.clone(), source_bytes.to_vec());

    save_pack_with_replacements(
        &target.pack_path,
        version,
        &product,
        &dlc_id,
        &metadata,
        false,
        &entries,
        &added_files,
        &replacement_files,
        Some(&encrypt_key),
    )?;

    println!(
        "{} {} from {}",
        "repacked".green().bold(),
        display_path(&target.pack_path).green(),
        display_path(source_path).cyan()
    );

    Ok(())
}

fn load_pack_for_repack(
    pack_path: &Path,
) -> Result<
    (
        bevy_dlc::Product,
        bevy_dlc::DlcId,
        usize,
        bevy_dlc::PackMetadata,
        Vec<(String, bevy_dlc::EncryptedAsset)>,
        EncryptionKey,
    ),
    Box<dyn std::error::Error>,
> {
    let file = std::fs::File::open(pack_path)?;
    let mut reader = std::io::BufReader::new(file);
    let parsed_without_key = parse_encrypted_pack_info(&mut reader, None)?;

    let search_roots = build_key_search_roots(pack_path, None);
    let (_, signed_license) = resolve_keys_with_search_roots(
        None,
        None,
        None,
        Some(parsed_without_key.product.clone()),
        &search_roots,
    );
    let signed_license = signed_license.ok_or_else(|| {
        format!(
            "no signed license found for product '{}' while watching {}",
            parsed_without_key.product.as_ref(),
            display_path(pack_path)
        )
    })?;

    let encrypt_key = extract_encrypt_key_from_license(&signed_license).ok_or_else(|| {
        format!(
            "signed license for product '{}' does not embed an encrypt key",
            parsed_without_key.product.as_ref()
        )
    })?;

    let file = std::fs::File::open(pack_path)?;
    let mut reader = std::io::BufReader::new(file);
    let parsed = parse_encrypted_pack_info(&mut reader, Some(&encrypt_key))?;

    Ok((
        parsed.product,
        parsed.dlc_id,
        parsed.version,
        parsed.metadata,
        parsed.entries,
        encrypt_key,
    ))
}

fn scan_watch_index(root: &Path) -> Result<WatchIndex, Box<dyn std::error::Error>> {
    let mut pack_paths = Vec::new();
    collect_files_recursive(root, &mut pack_paths, Some("dlcpack"), 12)?;

    let mut source_candidates = Vec::new();
    collect_files_recursive(root, &mut source_candidates, None, 12)?;
    let source_candidates: Vec<PathBuf> = source_candidates
        .into_iter()
        .map(|path| canonicalize_existing_path(&path))
        .collect();

    let mut index = WatchIndex::default();

    for pack_path in pack_paths {
        index.scanned_packs += 1;
        let pack_path = canonicalize_existing_path(&pack_path);
        let file = match std::fs::File::open(&pack_path) {
            Ok(file) => file,
            Err(error) => {
                index.skipped_packs += 1;
                print_warning(
                    format!("failed to open {}: {}", display_path(&pack_path), error).as_str(),
                );
                continue;
            }
        };
        let mut reader = std::io::BufReader::new(file);
        let parsed = match parse_encrypted_pack_info(&mut reader, None) {
            Ok(parsed) => parsed,
            Err(error) => {
                index.skipped_packs += 1;
                print_warning(
                    format!("failed to parse {}: {}", display_path(&pack_path), error).as_str(),
                );
                continue;
            }
        };

        let search_roots = build_key_search_roots(&pack_path, Some(root));
        let (_, signed_license) = resolve_keys_with_search_roots(
            None,
            None,
            None,
            Some(parsed.product.clone()),
            &search_roots,
        );
        if signed_license
            .as_ref()
            .and_then(extract_encrypt_key_from_license)
            .is_none()
        {
            index.skipped_packs += 1;
            print_warning(
                format!(
                    "skipping {} because no matching signed license with an encrypt key was found for product '{}'",
                    display_path(&pack_path),
                    parsed.product.as_ref()
                )
                .as_str(),
            );
            continue;
        }

        for (entry_path, _) in parsed.entries {
            let Some(source_path) = resolve_source_path(root, &pack_path, &entry_path, &source_candidates) else {
                index.unresolved_entries += 1;
                print_warning(
                    format!(
                        "no real file found for {}#{}",
                        display_path(&pack_path),
                        entry_path
                    )
                    .as_str(),
                );
                continue;
            };

            let watch_dir = source_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| root.to_path_buf());
            index.watched_dirs.insert(watch_dir);
            if let Some(fingerprint) = read_fingerprint(&source_path)? {
                index.fingerprints.insert(source_path.clone(), fingerprint);
            }
            let targets = index.by_source.entry(source_path).or_default();
            if !targets.iter().any(|target| {
                target.pack_path == pack_path && target.entry_path == entry_path
            }) {
                targets.push(PackEntryTarget {
                    pack_path: pack_path.clone(),
                    entry_path,
                });
            }
        }
    }

    Ok(index)
}

fn resolve_source_path(
    root: &Path,
    pack_path: &Path,
    entry_path: &str,
    source_candidates: &[PathBuf],
) -> Option<PathBuf> {
    let pack_dir = pack_path.parent().unwrap_or(root);
    let direct_candidate = pack_dir.join(entry_path);
    if direct_candidate.is_file() {
        return Some(canonicalize_existing_path(&direct_candidate));
    }

    let normalized_entry = normalize_path_string(Path::new(entry_path));
    let entry_suffix = format!("/{normalized_entry}");
    let mut best: Option<((usize, usize, usize), PathBuf)> = None;
    let mut ambiguous = false;

    for candidate in source_candidates {
        let Ok(relative_candidate) = candidate.strip_prefix(root) else {
            continue;
        };
        let normalized_candidate = normalize_path_string(relative_candidate);
        if normalized_candidate != normalized_entry
            && !normalized_candidate.ends_with(&entry_suffix)
        {
            continue;
        }

        let candidate_parent = candidate.parent().unwrap_or(root);
        let score = (
            usize::from(normalized_candidate == normalized_entry),
            common_prefix_len(pack_dir, candidate_parent),
            usize::MAX.saturating_sub(candidate.components().count()),
        );

        match &best {
            Some((best_score, _)) if &score < best_score => {}
            Some((best_score, _)) if &score == best_score => {
                ambiguous = true;
            }
            _ => {
                ambiguous = false;
                best = Some((score, candidate.clone()));
            }
        }
    }

    if ambiguous {
        None
    } else {
        best.map(|(_, path)| path)
    }
}

fn unique_pack_count(index: &WatchIndex) -> usize {
    index
        .by_source
        .values()
        .flat_map(|targets| targets.iter().map(|target| &target.pack_path))
        .collect::<BTreeSet<_>>()
        .len()
}

fn read_fingerprint(
    path: &Path,
) -> Result<Option<FileFingerprint>, Box<dyn std::error::Error>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Ok(None);
    }

    Ok(Some(FileFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    }))
}

fn canonicalize_existing_path(path: &Path) -> PathBuf {
    match path.canonicalize() {
        Ok(path) => path,
        Err(_) => path.to_path_buf(),
    }
}

fn canonicalize_lossy_path(path: &Path) -> PathBuf {
    if path.exists() {
        return canonicalize_existing_path(path);
    }

    if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(current_dir) => current_dir.join(path),
            Err(_) => path.to_path_buf(),
        }
    }
}

fn normalize_path_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn common_prefix_len(left: &Path, right: &Path) -> usize {
    let left_components: Vec<String> = left
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    let right_components: Vec<String> = right
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();

    left_components
        .iter()
        .zip(right_components.iter())
        .take_while(|(left_component, right_component)| left_component == right_component)
        .count()
}

fn build_key_search_roots(pack_path: &Path, root: Option<&Path>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut search_roots = Vec::new();

    for ancestor in pack_path.ancestors() {
        if !ancestor.is_dir() {
            continue;
        }
        let canonical = canonicalize_existing_path(ancestor);
        if seen.insert(canonical.clone()) {
            search_roots.push(canonical);
        }
    }

    if let Some(root) = root {
        let canonical = canonicalize_existing_path(root);
        if seen.insert(canonical.clone()) {
            search_roots.push(canonical);
        }
    }

    if let Ok(current_dir) = std::env::current_dir() {
        let canonical = canonicalize_existing_path(&current_dir);
        if seen.insert(canonical.clone()) {
            search_roots.push(canonical);
        }
    }

    search_roots
}

fn display_path(path: &Path) -> String {
    let display_path = strip_windows_verbatim_prefix(path);

    match std::env::current_dir() {
        Ok(current_dir) => {
            let current_dir = strip_windows_verbatim_prefix(&canonicalize_existing_path(&current_dir));
            if let Some(relative) = relative_display_path(&display_path, &current_dir) {
                return relative;
            }
            if let Some(relative) = relative_display_path_by_string(&display_path, &current_dir) {
                return relative;
            }
            display_path.display().to_string()
        }
        Err(_) => display_path.display().to_string(),
    }
}

fn relative_display_path(path: &Path, base: &Path) -> Option<String> {
    let path_components: Vec<Component<'_>> = path.components().collect();
    let base_components: Vec<Component<'_>> = base.components().collect();

    if base_components.len() > path_components.len() {
        return None;
    }

    for (path_component, base_component) in path_components.iter().zip(base_components.iter()) {
        if !components_equal_for_display(path_component, base_component) {
            return None;
        }
    }

    let relative = path_components[base_components.len()..]
        .iter()
        .fold(PathBuf::new(), |mut acc, component| {
            acc.push(component.as_os_str());
            acc
        });

    let relative_display = relative.display().to_string();
    if relative_display.is_empty() {
        None
    } else {
        Some(relative_display)
    }
}

fn components_equal_for_display(left: &Component<'_>, right: &Component<'_>) -> bool {
    #[cfg(windows)]
    {
        use std::path::Prefix;

        match (left, right) {
            (Component::Prefix(left_prefix), Component::Prefix(right_prefix)) => {
                match (left_prefix.kind(), right_prefix.kind()) {
                    (Prefix::Disk(left_disk), Prefix::Disk(right_disk))
                    | (Prefix::VerbatimDisk(left_disk), Prefix::VerbatimDisk(right_disk))
                    | (Prefix::Disk(left_disk), Prefix::VerbatimDisk(right_disk))
                    | (Prefix::VerbatimDisk(left_disk), Prefix::Disk(right_disk)) => {
                        return left_disk.eq_ignore_ascii_case(&right_disk);
                    }
                    (Prefix::UNC(left_server, left_share), Prefix::UNC(right_server, right_share))
                    | (
                        Prefix::VerbatimUNC(left_server, left_share),
                        Prefix::VerbatimUNC(right_server, right_share),
                    )
                    | (
                        Prefix::UNC(left_server, left_share),
                        Prefix::VerbatimUNC(right_server, right_share),
                    )
                    | (
                        Prefix::VerbatimUNC(left_server, left_share),
                        Prefix::UNC(right_server, right_share),
                    ) => {
                        return left_server
                            .to_string_lossy()
                            .eq_ignore_ascii_case(&right_server.to_string_lossy())
                            && left_share
                                .to_string_lossy()
                                .eq_ignore_ascii_case(&right_share.to_string_lossy());
                    }
                    _ => {
                        return left.as_os_str().to_string_lossy().eq_ignore_ascii_case(
                            &right.as_os_str().to_string_lossy(),
                        );
                    }
                }
            }
            _ => {
                return left
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy());
            }
        }
    }

    #[cfg(not(windows))]
    {
        left == right
    }
}

fn relative_display_path_by_string(path: &Path, base: &Path) -> Option<String> {
    let path_display = path.display().to_string();
    let base_display = base.display().to_string();

    #[cfg(windows)]
    {
        let normalized_path = path_display.replace('/', "\\");
        let normalized_base = base_display.replace('/', "\\").trim_end_matches('\\').to_string();
        let normalized_path_lower = normalized_path.to_ascii_lowercase();
        let normalized_base_lower = normalized_base.to_ascii_lowercase();

        if normalized_path_lower == normalized_base_lower {
            return None;
        }

        if normalized_path_lower.starts_with(&normalized_base_lower) {
            let suffix = &normalized_path[normalized_base.len()..];
            let relative = suffix.trim_start_matches('\\');
            if !relative.is_empty() {
                return Some(relative.to_string());
            }
        }

        return None;
    }

    #[cfg(not(windows))]
    {
        let normalized_base = base_display.trim_end_matches('/');
        if path_display == normalized_base {
            return None;
        }
        if let Some(stripped) = path_display.strip_prefix(normalized_base) {
            let relative = stripped.trim_start_matches('/');
            if !relative.is_empty() {
                return Some(relative.to_string());
            }
        }
        None
    }
}

fn strip_windows_verbatim_prefix(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::path::{Component, Prefix};

        let mut components = path.components();
        if let Some(Component::Prefix(prefix_component)) = components.next() {
            let remainder = components.as_path();
            match prefix_component.kind() {
                Prefix::VerbatimDisk(drive) => {
                    let mut rebuilt = PathBuf::from(format!("{}:", drive as char));
                    if !remainder.as_os_str().is_empty() {
                        rebuilt.push(remainder);
                    }
                    return rebuilt;
                }
                Prefix::VerbatimUNC(server, share) => {
                    let mut rebuilt = PathBuf::from(OsString::from(format!(
                        r#"\\{}\{}"#,
                        server.to_string_lossy(),
                        share.to_string_lossy()
                    )));
                    if !remainder.as_os_str().is_empty() {
                        rebuilt.push(remainder);
                    }
                    return rebuilt;
                }
                Prefix::Verbatim(value) => {
                    let mut rebuilt = PathBuf::from(value);
                    if !remainder.as_os_str().is_empty() {
                        rebuilt.push(remainder);
                    }
                    return rebuilt;
                }
                _ => {}
            }
        }
    }

    path.to_path_buf()
}

fn watch_should_exit_after_first_event() -> bool {
    std::env::var_os(WATCH_EXIT_AFTER_FIRST_EVENT_ENV)
        .map(|value| value != "0")
        .unwrap_or(false)
}

fn write_watch_ready_file() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::var_os(WATCH_READY_FILE_ENV) else {
        return Ok(());
    };

    let ready_path = PathBuf::from(path);
    if let Some(parent) = ready_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(ready_path, b"ready")?;
    Ok(())
}