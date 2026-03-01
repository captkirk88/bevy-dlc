use criterion::{Criterion, criterion_group, criterion_main};

use bevy_dlc::{
    DlcId, DlcPack, EncryptionKey, PackItem, Product, pack_encrypted_pack, parse_encrypted_pack,
    prelude::DlcPackEntry,
};

/// Helper that builds a moderately-sized set of `PackItem`s for benchmarking.
fn build_items(count: usize, size: usize) -> Vec<PackItem> {
    (0..count)
        .map(|i| {
            let name = format!("file{}.txt", i);
            let data = vec![0u8; size];
            PackItem::new(name, data).expect("create pack item")
        })
        .collect()
}

fn bench_pack(c: &mut Criterion) {
    let items = build_items(100, 1024 * 1024 * 1); // 100 files of 1MB each to get a meaningful packing time
    let product = Product::from("bench");
    let dlc_id = DlcId::from("bench");
    let key = EncryptionKey::from_random();

    c.bench_function("pack_100_files", |b| {
        b.iter(|| {
            // each iteration re-packs the same data; the overhead of preparing
            // the items has already been paid above so the benchmark focuses on
            // the pack_encrypted_pack path.
            let _ = pack_encrypted_pack(&dlc_id, &items, &product, &key).unwrap();
        });
    });
}

fn bench_parse(c: &mut Criterion) {
    let items = build_items(100, 1024 * 1024 * 1); // 100 files of 1MB each to get a meaningful parsing time
    let product = Product::from("bench");
    let dlc_id = DlcId::from("bench");
    let key = EncryptionKey::from_random();

    // pre-generate a pack so parsing can be isolated
    let pack_bytes = pack_encrypted_pack(&dlc_id, &items, &product, &key).unwrap();

    c.bench_function("parse_100_files", |b| {
        b.iter(|| {
            let mut slice = &pack_bytes[..];
            let _ = parse_encrypted_pack(&mut slice).unwrap();
        });
    });
}

/// Benchmark the time to decrypt all entries in a pack, which simulates the common runtime use case of loading a DLC pack and decrypting its contents for use in the game.
fn bench_decrypt_all_entries(c: &mut Criterion) {
    let items = build_items(30, 1024 * 1024); // 30 files of 1MB each to get a meaningful decryption time
    let product = Product::from("bench");
    let dlc_id = DlcId::from("bench");
    let key = EncryptionKey::from_random();
    let pack_bytes = pack_encrypted_pack(&dlc_id, &items, &product, &key).unwrap();

    let (prod2, id2, version, entries, _blocks) =
        parse_encrypted_pack(&mut &pack_bytes[..]).expect("parse");

    // build a DlcPack with the parsed entries, which is what the asset loader does at runtime
    let pack = DlcPack::new(
        id2,
        prod2,
        version.try_into().unwrap(),
        entries.iter().map(|e| DlcPackEntry::from(e)).collect(),
    );

    bevy_dlc::encrypt_key_registry::insert(&dlc_id.to_string(), key);

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let pack_path = temp_dir.path().join("bench.dlcpack");
    std::fs::write(&pack_path, &pack_bytes).expect("write pack file");
    bevy_dlc::encrypt_key_registry::register_asset_path(
        &dlc_id.to_string(),
        pack_path.to_str().unwrap(),
    );

    c.benchmark_group("decrypt")
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(5))
        .bench_function("decrypt_all", |b| {
            b.iter(|| {
                for (path, _enc) in &entries {
                    let _ = pack.decrypt_entry(path).expect("decrypt entry");
                }
            });
        });
}

criterion_group!(
    dlc_benches,
    bench_pack,
    bench_parse,
    bench_decrypt_all_entries
);
criterion_main!(dlc_benches);
