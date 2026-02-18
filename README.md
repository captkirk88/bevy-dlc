<p align="center">
  <img src="dlc.png" alt="bevy-dlc" title="Yes this was AI generated! Don't like it?  Too bad...  Complain to the AI Overlords." />
</p>

# bevy-dlc — DLC (Downloadable Content support)

[![Crates.io](https://img.shields.io/crates/v/bevy-dlc.svg)](https://crates.io/crates/bevy-dlc)
[![docs.rs](https://docs.rs/bevy-dlc/badge.svg)](https://docs.rs/bevy-dlc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Compact helper crate for shipping encrypted DLC assets and unlocking them with offline-signed licenses.

- Encrypt and ship asset packs `.dlcpack`
- Verify signed license tokens (Ed25519)
- Provision symmetric encryption keys from tokens and unlock encrypted assets at runtime
- Lazy / labeled sub-asset support (e.g. `pack.dlcpack#sprites/player.png`)

This README covers quick usage, the `bevy-dlc` CLI for packing, the `App` extension helpers, and short examples.


**Install (library & CLI)**

- As a dependency in `Cargo.toml` (for apps and examples):

```toml
bevy-dlc = { path = "." }
```

- To install the CLI tool (optional):

```bash
cargo install bevy-dlc
```

After `cargo install bevy-dlc` you get the `bevy-dlc` binary with convenient commands (examples below).

**CLI: `bevy-dlc pack`**

Use the CLI to create encrypted `.dlcpack` files for distribution. Example usage:

```bash
# Quick (one-line) pack example — embeds product and writes a .dlcpack
bevy-dlc pack --product example assets/pack_src expansion_1 --pack -o assets/expansionA.dlcpack
```

The CLI supports additional flags. See `bevy-dlc help` for the full flag list.

### App Extension & Plugin Usage

`bevy-dlc` exposes `register_dlc_type` on `App` to register DLC asset types.  If your DLC has a custom asset type, you must register it.

Example (minimal):

```rust
use bevy::prelude::*;
use bevy_dlc::prelude::*;
use bevy_dlc::example_util::*; // example-only helper

fn main() {
        let dlc_key = DlcKey::public(...pubkey...).unwrap();
        let signed_license = SignedLicense::from(...license...);

        App::new()
                .add_plugins(DefaultPlugins)
                // `DlcPlugin::new(product, public_key, optional_signed_license)`
                .add_plugins(DlcPlugin::new(Product::from("example"), dlc_key, signed_license))
                // Register any custom DLC asset types used in your packs
                .register_dlc_type::<MyCustomAssetType>()
                .run();
}
```

### Loading & Unlocking Flow

- Load a pack like any other asset:

```rust
let pack_handle: Handle<DlcPack> = asset_server.load("expansionA.dlcpack");
```

- After applying a verified license (or when the content key is present in the registry), load labeled entries:

```rust
let img_handle: Handle<Image> = asset_server.load("expansionA.dlcpack#test.png");
```


