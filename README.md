<p align="center">
  <img src="dlc.png" alt="bevy-dlc" title="Yes this was AI generated! Don't like it?  Too bad...  Complain to the AI Overlords." />
</p>

---

[![Crates.io](https://img.shields.io/crates/v/bevy-dlc.svg)](https://crates.io/crates/bevy-dlc)
[![docs.rs](https://docs.rs/bevy-dlc/badge.svg)](https://docs.rs/bevy-dlc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Encrypt and ship your DLC!  Create your DLC logic and assets and securely unlock it at runtime with signed licenses (generated using `bevy-dlc` CLI).

Works with Bevy's asset pipeline.

## Features

- Pack assets into encrypted `.dlcpack` containers
- Sign licenses with Ed25519 (private key embeds the symmetric encryption key)
- Verify signatures at runtime and unlock encrypted content
- Lazy loading of labeled assets (e.g. `pack.dlcpack#sprites/player.png`)
- Product binding — prevent token reuse across games

## Install

Add to your `Cargo.toml`:

```toml
bevy-dlc = "1.1"
```

To use the CLI tool:

```bash
cargo install bevy-dlc
```

Then `bevy-dlc --help` for available commands.

## Quick Start

### Generate a license

```bash
bevy-dlc generate -o keys/ my-game expansion_1
```

This will generate two files in `keys/`:
- `expansion_1.slicense` — a secure license token that can be safely embedded in your game binary (e.g. with `secure::include_secure_str_aes!()`) or stored securely on disk.  This token contains the encrypted symmetric key needed to unlock the DLC, but can't be decrypted without the private key.
- `expansion_1.pubkey` — the public key that your game uses to verify the license and extract the symmetric key to unlock the DLC.

### Create a pack

```bash
bevy-dlc pack --product my-game expansion_1 assets/expansionA -o dlc/expansion_1.dlcpack
```

- `--product` — binds the pack to a product name (enforced by `DlcManager`)
- `assets/expansionA` — directory or file(s) to pack
- `expansion_1` — DLC ID (used in licenses to unlock this pack)
- `-o dlc/expansion_1.dlcpack` — output path for the pack (defaults to `{dlc_id}.dlcpack`)

This creates `expansion_1.dlcpack` and prints a signed license token.

Alternatively you can use `bevy-dlc generate --help` to review how to generate a signed license without packing, or `bevy-dlc validate --help` to verify it.

> [!NOTE]
> `bevy-dlc help <command>` for detailed usage of each CLI command.

### Load in your app

```rust
use bevy::prelude::*;
use bevy_dlc::prelude::*;

fn main() {
    let dlc_key = DlcKey::public(pubkey_base64).unwrap();
    let license = SignedLicense::from(secure_token_str);  // from CLI output or other secure source

    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(DlcPlugin::new(
            Product::from("my-game"),
            dlc_key,
            license,
        ))
        .register_dlc_type::<MyCustomType>()  // if your pack has custom types
        .run();
}
```

### Load assets

Once unlocked, load assets from your pack like normal:

```rust
let pack: Handle<DlcPack> = asset_server.load("expansion_1.dlcpack");
let image: Handle<Image> = asset_server.load("expansion_1.dlcpack#sprites/player.png");
```

*Review the [examples](examples/) for a complete example (run with `cargo run --manifest-path bevy-dlc-examples/Cargo.toml`).*

### Suggestions and Contributions

Contributions are very welcome!  Please open an issue or submit a pull request with any improvements, bug fixes, PERFORMANCE IMPROVEMENTS, or new features.

## License

MIT



