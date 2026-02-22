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
- Security checks to prevent common mistakes like packing executables or other packs

## Install

Add to your `Cargo.toml`:

```bash
cargo add bevy-dlc
```
> [!NOTE]
> `bevy-dlc` will always be compatible with Bevy 1.## with the minor version being used for bug fixes and new features.  So `bevy-dlc = "1.18"` will also work and automatically get you any compatible bug fixes.

To use the CLI tool:

```bash
cargo install bevy-dlc
```

Then `bevy-dlc --help` for available commands.

## Quick Start

### Generate a license

```bash
bevy-dlc generate -o keys/ my-game dlcA
```

This will generate two files in `keys/`:
- `dlcA.slicense` — a secure license token that can be safely embedded in your game binary (e.g. with `secure::include_secure_str_aes!()`) or stored securely on disk.  This token contains the encrypted symmetric key needed to unlock the DLC, but can't be decrypted without the private key.
- `dlcA.pubkey` — the public key that your game uses to verify the license and extract the symmetric key to unlock the DLC.

### Create a pack

```bash
bevy-dlc pack --product my-game dlcA -o dlc -- assets/dlcA
```

- `--product` — binds the pack to a product name
- `assets/dlcA` — directory or file(s) to pack
- `dlcA` — DLC ID (used in licenses to unlock this pack)
- `-o dlc` — output path for the generated `.dlcpack`
- `--types` — optional list of asset type paths to include in the pack index (e.g. `bevy::prelude::Image`), otherwise all assets will be indexed with their full type paths.  This can be used to normalize type paths across different versions of Bevy or your game.  The types you specify are fuzzy matched against the actual asset types in the pack, so you can just specify `assets::MyAsset` and it will match `my_game::assets::MyAsset` in the pack if that's the actual type.

This creates `dlcA.dlcpack` and prints a signed license token.

Alternatively you can use `bevy-dlc generate --help` to review how to generate a signed license without packing, or `bevy-dlc validate --help` to verify it.

> [!NOTE]
> `bevy-dlc help <command>` for detailed usage of each CLI command.

### Edit a pack
You can edit the contents of a `.dlcpack` with `bevy-dlc edit`:

```bash
bevy-dlc edit <my_dlc>.dlcpack
```
This opens an interactive REPL where you can add/remove files, list contents, or even merge entries from another `.dlcpack` (use `merge <other-pack>`).  Changes are saved back to the `.dlcpack` when you `save` and if you forget and exit, REPL will ask you.

### Usage

Review the [examples](examples/) for a complete example (run with `cargo run --release --example <example>`).

### API Overview

* `DlcLoader` acts as a pass-through `AssetLoader` to the actual asset loader for that type (as long as it was registered).
* `DlcPack` is a custom Bevy `Asset` that represents a loaded DLC pack, and contains the decrypted asset data and metadata.  You can load it directly with `AssetServer::load("my_pack.dlcpack")`.
* `DlcPackEntry` represents a single asset within a pack, and can be loaded with `AssetServer::load("my_pack.dlcpack#path/to/asset.png")` (note the `#` separator).  You can also query the `DlcPack` directly for its entries.
* Events are emitted when packs and entries are loaded, so you can react to them with Bevy's event system.
  - `DlcPackLoaded` — emitted when a pack is loaded and decrypted, contains the `DlcId` and `DlcPack`.
* Finally, `DlcPlugin` is the main plugin that sets up the DLC system.  It requires a `DlcKey::Public` and `SignedLicense` to verify and unlock packs.

#### Helper macros

The crate exports a few convenient macros to reduce boilerplate when dealing with
DLC packs and assets.  They are defined in `src/macros.rs` and available at the
crate root:

* `pack_items!` – build a `Vec<PackItem>` from literal path/bytes pairs, with optional `ext=` or `type=` metadata.
* `dlc_register_types!(app, ..)` – call `register_dlc_type` for multiple types at once.
* `dlc_simple_asset!(Asset, Loader, Plugin, "ext"...)` – define a simple text-like asset type, its loader, and a Bevy plugin that registers both.  The examples use this macro to keep the sample assets minimal. (best for testing quickly, not recommended for production use)

This convenience tooling is mostly useful for tests and small examples, but can
also speed up rapid prototyping in your own games.

### Suggestions and Contributions

Contributions are very welcome!  Please open an issue or submit a pull request with any improvements, bug fixes, or new features.

## License

MIT



