use proc_macro::TokenStream;
use quote::quote;
use std::path::{Path, PathBuf};
use syn::{parse_macro_input, parse::Parse, parse::ParseStream, LitStr, Token};

struct IncludeSignedLicenseAesArgs {
    path: LitStr,
    key: LitStr,
}

impl Parse for IncludeSignedLicenseAesArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let path: LitStr = input.parse()?;
        input.parse::<Token![,]>()?;
        let key: LitStr = input.parse()?;
        // Allow an optional trailing comma for ergonomic macro usage.
        let _ = input.parse::<Token![,]>();
        Ok(IncludeSignedLicenseAesArgs { path, key })
    }
}

/// Includes a secure license token from file and returns it as a `SignedLicense`.
///
/// This wrapper is specialized for `bevy-dlc`.
/// 
/// Example usage:
/// ```ignore
/// use bevy_dlc::prelude::*;
/// use bevy_dlc_macro::include_signed_license_aes;
/// 
/// let signed_license = include_signed_license_aes!(
///     "examples/example_keys/example.slicense",
///    "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
/// );
/// ```
#[proc_macro]
pub fn include_signed_license_aes(input: TokenStream) -> TokenStream {
    let IncludeSignedLicenseAesArgs { path, key } = parse_macro_input!(input as IncludeSignedLicenseAesArgs);
    let key_value = key.value();

    // The AES-256 key for byte-aes must be 32 bytes.
    if key_value.len() != 32 {
        panic!("license key must be exactly 32 characters");
    }

    let resolved = resolve_path(&path.value());
    let license_bytes = std::fs::read(&resolved)
        .unwrap_or_else(|e| panic!("Cannot read signed license from '{}': {e}", resolved.display()));
    let license_str = String::from_utf8(license_bytes)
        .unwrap_or_else(|e| panic!("Signed license is not valid UTF-8 at '{}': {e}", resolved.display()));
    let cryptor = byte_aes::Aes256Cryptor::try_from(key_value.as_str())
        .expect("license key must be exactly 32 characters");
    let encrypted_bytes = cryptor.encrypt(&license_str);
    drop(license_str);
    let encrypted_b64 = base64::Engine::encode(
        &base64::prelude::BASE64_STANDARD,
        encrypted_bytes,
    );
    let encrypted_b64_lit = LitStr::new(&encrypted_b64, proc_macro2::Span::call_site());

    quote! {{
        ::bevy_dlc::__decode_embedded_signed_license_aes(#encrypted_b64_lit, #key)
    }}
    .into()
}

fn resolve_path(path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        return path.to_path_buf();
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let manifest_path = Path::new(&manifest_dir);
        let candidate = manifest_path.join(path);
        if candidate.exists() {
            return candidate;
        }

        // Support paths typically written relative to `src/` call sites.
        let src_candidate = manifest_path.join("src").join(path);
        if src_candidate.exists() {
            return src_candidate;
        }

        return candidate;
    }

    path.to_path_buf()
}
