use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, parse::Parse, parse::ParseStream, Ident, LitStr, Token};

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

    // Replace path separators and extension separators so the generated function name is valid.
    let sanitized = sanitize_path(&path.value());
    let name_literal = LitStr::new(&sanitized, Span::call_site());

    let func_ident = Ident::new(&format!("get_{}", sanitized), Span::call_site());

    quote! {{
        ::bevy_dlc::include_secure_str_aes!(#path, #key, #name_literal);
        ::bevy_dlc::SignedLicense::from(#func_ident())
    }}
    .into()
}

fn sanitize_path(path: &str) -> String {
    let mut s = path
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();

    if s.is_empty() {
        return "bevy_dlc_signed_license".to_string();
    }

    // Ensure the identifier doesn't start with a digit.
    if s.chars().next().map_or(false, |c| c.is_ascii_digit()) {
        s.insert(0, '_');
    }

    s
}
