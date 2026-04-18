mod common;

use std::thread;
use std::time::{Duration, Instant};

use common::prelude::*;

const WATCH_EXIT_AFTER_FIRST_EVENT_ENV: &str = "BEVY_DLC_WATCH_EXIT_AFTER_FIRST_EVENT";
const WATCH_READY_FILE_ENV: &str = "BEVY_DLC_WATCH_READY_FILE";

fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }

    out
}

fn setup_watch_pack(
    ctx: &CliTestCtx,
    product: &str,
    dlc_id: &str,
    source_rel: &str,
    pack_rel: &str,
) {
    ctx.generate(product, &[dlc_id], None, false).success();
    ctx.run_args(&[
        "pack",
        product,
        dlc_id,
        "--signed-license",
        &format!("{}.slicense", product),
        "--pubkey",
        &format!("{}.pubkey", product),
        "--types",
        "txt=examples::TextAsset",
        "-o",
        pack_rel,
        "--",
        source_rel,
    ])
    .success();
}

fn run_watch_until_first_event(
    ctx: &CliTestCtx,
    dry_run: bool,
    extra_args: &[&str],
    modify: impl FnOnce() + Send + 'static,
) -> std::process::Output {
    let ready_path = ctx.path().join("watch.ready");
    let ready_for_thread = ready_path.clone();
    let modifier = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if ready_for_thread.exists() {
                modify();
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("watch command did not signal readiness in time");
    });

    let mut args = Vec::new();
    if dry_run {
        args.push("--dry-run");
    }
    args.push("watch");
    args.extend(extra_args.iter().copied());

    let output = ctx.run_and_capture_with_env(
        &args,
        &[
            (WATCH_EXIT_AFTER_FIRST_EVENT_ENV, "1".to_string()),
            (
                WATCH_READY_FILE_ENV,
                ready_path.to_string_lossy().to_string(),
            ),
        ],
        Duration::from_secs(15),
    );

    modifier.join().expect("join watch modifier thread");
    output
}

#[test]
#[serial_test::serial]
fn watch_cli_repacks_changed_file() {
    let ctx = CliTestCtx::new();
    let product = "watch_prod";
    let dlc_id = "watch_pack";

    ctx.write_file("assets/foo.txt", b"old");
    setup_watch_pack(&ctx, product, dlc_id, "assets/foo.txt", "assets/bundle.dlcpack");

    let source_path = ctx.path().join("assets/foo.txt");
    let output = run_watch_until_first_event(&ctx, false, &[], move || {
        std::fs::write(&source_path, b"updated").expect("update watched source file");
    });

    assert!(output.status.success(), "watch command should succeed");
    let stdout = strip_ansi(&String::from_utf8(output.stdout).expect("utf8 stdout from watch"));
    assert!(stdout.contains("repacked assets\\bundle.dlcpack from assets\\foo.txt"), "expected repack output: {stdout}");

    let encrypt_key = ctx.read_encrypt_key(product);
    let repacked = ctx.read_pack_entry_bytes(
        ctx.path().join("assets/bundle.dlcpack"),
        &encrypt_key,
        "foo.txt",
    );
    assert_eq!(repacked, b"updated");
}

#[test]
#[serial_test::serial]
fn watch_cli_dry_run_reports_change_without_repacking() {
    let ctx = CliTestCtx::new();
    let product = "watch_prod";
    let dlc_id = "watch_pack";

    ctx.write_file("assets/foo.txt", b"old");
    setup_watch_pack(&ctx, product, dlc_id, "assets/foo.txt", "assets/bundle.dlcpack");

    let source_path = ctx.path().join("assets/foo.txt");
    let output = run_watch_until_first_event(&ctx, true, &[], move || {
        std::fs::write(&source_path, b"updated").expect("update watched source file");
    });

    assert!(output.status.success(), "watch command should succeed");
    let stdout = strip_ansi(&String::from_utf8(output.stdout).expect("utf8 stdout from watch"));
    assert!(stdout.contains("detected change:"), "expected dry-run change output: {stdout}");
    assert!(stdout.contains("assets\\foo.txt -> assets\\bundle.dlcpack#foo.txt"), "expected formatted dry-run output: {stdout}");

    let encrypt_key = ctx.read_encrypt_key(product);
    let repacked = ctx.read_pack_entry_bytes(
        ctx.path().join("assets/bundle.dlcpack"),
        &encrypt_key,
        "foo.txt",
    );
    assert_eq!(repacked, b"old");
}

#[test]
#[serial_test::serial]
fn watch_cli_prefers_source_nearest_to_pack() {
    let ctx = CliTestCtx::new();
    let product = "watch_prod";
    let dlc_id = "watch_pack";

    ctx.write_file("assets/source/foo.txt", b"old");
    ctx.write_file("other/foo.txt", b"other");
    setup_watch_pack(
        &ctx,
        product,
        dlc_id,
        "assets/source/foo.txt",
        "assets/bundle.dlcpack",
    );

    let other_path = ctx.path().join("other/foo.txt");
    let preferred_path = ctx.path().join("assets/source/foo.txt");

    let output = run_watch_until_first_event(&ctx, true, &[], move || {
        std::fs::write(&other_path, b"other changed").expect("update unrelated source file");
        thread::sleep(Duration::from_millis(400));
        std::fs::write(&preferred_path, b"preferred changed").expect("update preferred source file");
    });

    assert!(output.status.success(), "watch command should succeed");
    let stdout = strip_ansi(&String::from_utf8(output.stdout).expect("utf8 stdout from watch"));
    assert!(stdout.contains("assets\\source\\foo.txt"), "expected preferred source path in output: {stdout}");
    assert!(!stdout.contains("other\\foo.txt"), "did not expect unrelated source path in output: {stdout}");
    println!("watch output:\n{stdout}");
}

#[test]
#[serial_test::serial]
fn watch_cli_dlc_id_filters_to_matching_pack() {
    let ctx = CliTestCtx::new();

    ctx.write_file("assets/foo.txt", b"old foo");
    ctx.write_file("assets/bar.txt", b"old bar");

    setup_watch_pack(
        &ctx,
        "watch_prod_a",
        "watch_pack_a",
        "assets/foo.txt",
        "assets/bundle_a.dlcpack",
    );
    setup_watch_pack(
        &ctx,
        "watch_prod_b",
        "watch_pack_b",
        "assets/bar.txt",
        "assets/bundle_b.dlcpack",
    );

    let foo_path = ctx.path().join("assets/foo.txt");
    let bar_path = ctx.path().join("assets/bar.txt");
    let output = run_watch_until_first_event(
        &ctx,
        true,
        &["--dlc-id", "watch_pack_b"],
        move || {
            std::fs::write(&foo_path, b"foo changed").expect("update non-target source file");
            thread::sleep(Duration::from_millis(400));
            std::fs::write(&bar_path, b"bar changed").expect("update filtered source file");
        },
    );

    assert!(output.status.success(), "watch command should succeed");
    let stdout = strip_ansi(&String::from_utf8(output.stdout).expect("utf8 stdout from watch"));
    assert!(stdout.contains("assets\\bar.txt -> assets\\bundle_b.dlcpack#bar.txt"), "expected filtered pack output: {stdout}");
    assert!(!stdout.contains("bundle_a.dlcpack"), "did not expect non-matching pack output: {stdout}");
    assert!(!stdout.contains("assets\\foo.txt"), "did not expect non-matching source output: {stdout}");
}