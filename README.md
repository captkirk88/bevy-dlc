<p align="center">
  <img src="dlc.png" alt="bevy-dlc" title="Yes this was AI generated! Don't like it?  Too bad...  Complain to the AI Overlords." />
</p>

---

[![Crates.io](https://img.shields.io/crates/v/bevy-dlc.svg)](https://crates.io/crates/bevy-dlc)
[![docs.rs](https://docs.rs/bevy-dlc/badge.svg)](https://docs.rs/bevy-dlc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Encrypt and ship DLC asset packs with offline-signed license tokens. Works with Bevy's asset pipeline.

## Features

- Pack assets into encrypted `.dlc` or `.dlcpack` containers
- Sign licenses with Ed25519 (private key embeds the symmetric encryption key)
- Verify signatures at runtime and unlock encrypted content
- Lazy loading of labeled assets (e.g. `pack.dlcpack#sprites/player.png`)
- Product binding — prevent token reuse across games

## Install

Add to your `Cargo.toml`:

```toml
bevy-dlc = "0.1"
```

To use the CLI tool:

```bash
cargo install bevy-dlc
```

Then `bevy-dlc --help` for available commands.

## Quick Start

### Create a pack

```bash
bevy-dlc pack --product my-game assets/expansion_1 expansion_1 --pack [-o expansion_1.dlcpack]
```

- `--product` — binds the pack to a product name (enforced by `DlcManager`)
- `assets/expansion_1` — directory of assets to pack
- `expansion_1` — DLC ID (used in licenses to unlock this pack)
- `--pack` — create a single encrypted archive (`.dlcpack`) instead of individual encrypted files
- `-o expansion_1.dlcpack` — output path for the pack (defaults to `{dlc_id}.dlcpack`)

This creates `expansion_1.dlcpack` and prints a signed license token.

Alternatively you can use `bevy-dlc generate --help` to review how to generate tokens without packing, or `bevy-dlc validate --help` to verify tokens.

> [!NOTE]
> `bevy-dlc help <command>` for detailed usage of each CLI command.

### Load in your app

```rust
use bevy::prelude::*;
use bevy_dlc::prelude::*;

fn main() {
    let dlc_key = DlcKey::public(pubkey_base64).unwrap();
    let license = SignedLicense::from(token_string);

    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(DlcPlugin::new(
            Product::from("my-game"),
            dlc_key,
            license,
        ))
        .register_dlc_type::<Image>()  // if your pack has custom types
        .run();
}
```

### Load assets

Once unlocked, load assets from your pack like normal:

```rust
let pack: Handle<DlcPack> = asset_server.load("expansion_1.dlcpack");
let image: Handle<Image> = asset_server.load("expansion_1.dlcpack#sprites/player.png");
```

*Review [real.rs](examples/real.rs) for a complete example.*

## License

MIT



