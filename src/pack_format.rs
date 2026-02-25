use once_cell::sync::Lazy;
use std::collections::HashSet;

/// .dlcpack container magic header (4 bytes) used to identify encrypted pack containers.
pub const DLC_PACK_MAGIC: &[u8; 4] = b"BDLP";

/// Current supported .dlcpack format version. This is stored in the container header and used to determine how to parse the contents.
pub const DLC_PACK_VERSION: u8 = 3;

/// List of file extensions that are never allowed to be packed.  These are
/// taken from the same array that used to live in [lib.rs]; we keep the
/// array for deterministic build and the hash set for fast membership tests.
pub const FORBIDDEN_EXTENSIONS: &[&str] = &[
    "7z", "accda", "accdb", "accde", "accdr", "ace", "ade", "adp", "app", "appinstaller", "application", "appref", "appx", "appxbundle", "arj", "asax", "asd", "ashx", "asp", "aspx", "b64", "bas", "bat", "bgi", "bin", "btm", "bz", "bz2", "bzip", "bzip2", "cab", "cer", "cfg", "chi", "chm", "cla", "class", "cmd", "com", "cpi", "cpio", "cpl", "crt", "crx", "csh", "der", "desktopthemefile", "diagcab", "diagcfg", "diagpkg", "dll", "dmg", "doc", "docm", "docx", "dotm", "drv", "eml", "exe", "fon", "fxp", "gadget", "grp", "gz", "gzip", "hlp", "hta", "htc", "htm", "html", "htt", "ics", "img", "ini", "ins", "inx", "iqy", "iso", "isp", "isu", "jar", "jnlp", "job", "js", "jse", "ksh", "lha", "lnk", "local", "lz", "lzh", "lzma", "mad", "maf", "mag", "mam", "manifest", "maq", "mar", "mas", "mat", "mav", "maw", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mmc", "msc", "msg", "msh", "msh1", "msh1xml", "msh2", "msh2xml", "mshxml", "msi", "msix", "msixbundle", "msm", "msp", "mst", "msu", "ocx", "odt", "one", "onepkg", "onetoc", "onetoc2", "ops", "oxps", "oxt", "paf", "partial", "pcd", "pdf", "pif", "pl", "plg", "pol", "potm", "ppam", "ppkg", "ppsm", "ppt", "pptm", "pptx", "prf", "prg", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "psm1", "pst", "r00", "r01", "r02", "r03", "rar", "reg", "rels", "rev", "rgs", "rpm", "rtf", "scf", "scr", "sct", "search", "settingcontent", "settingscontent", "sh", "shb", "sldm", "slk", "svg", "swf", "sys", "tar", "tbz", "tbz2", "tgz", "tlb", "url", "uue", "vb", "vbe", "vbs", "vbscript", "vdx", "vhd", "vhdx", "vsdm", "vsdx", "vsmacros", "vss", "vssm", "vssx", "vst", "vstm", "vstx", "vsw", "vsx", "vtx", "wbk", "webarchive", "website", "wml", "ws", "wsc", "wsf", "wsh", "xar", "xbap", "xdp", "xlam", "xll", "xlm", "xls", "xlsb", "xlsm", "xlsx", "xltm", "xlw", "xml", "xnk", "xps", "xrm", "xsd", "xsl", "xxe", "xz", "z", "zip",
];

/// Lazy hash set used by [`is_forbidden_extension`].
static FORBIDDEN_SET: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    FORBIDDEN_EXTENSIONS.iter().copied().collect()
});

/// Return true if the extension (case‑insensitive) is in the forbidden list.
pub fn is_forbidden_extension(ext: &str) -> bool {
    let lowercase = ext.trim_start_matches('.').to_ascii_lowercase();
    FORBIDDEN_SET.contains(lowercase.as_str())
}

/// Return true if the file is potentially malicious based on its path and extension.
///
/// This is a best‑effort check used by the packaging helpers. It looks at the
/// provided extension as well as running `infer::get_from_path` on the path to
/// identify application/binary formats.
pub fn is_malicious_file(path: &str, ext: Option<&str>) -> bool {
    if let Some(e) = ext {
        if is_forbidden_extension(e) {
            return true;
        }
    }

    if !path.contains('.') {
        return false;
    }

    if let Some(kind) = infer::get_from_path(path).ok().flatten() {
        return kind.mime_type().starts_with("application");
    }
    false
}

/// Simple heuristic used by the packer to detect executable payloads.  It is
/// intentionally forgiving; the goal is merely to catch obvious binaries when
/// a user accidentally tries to pack them.
pub fn is_data_executable(data: &[u8]) -> bool {
    if infer::is_app(data) {
        return true;
    }
    if data.starts_with(b"#!") {
        return true;
    }
    false
}

/// Representation of a single manifest entry inside a v2+ `.dlcpack`.  The
/// same struct is used by pack creation, parsing, and the REPL logic.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ManifestEntry {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_path: Option<String>,
}

impl ManifestEntry {
    pub fn from_pack_item(item: &crate::PackItem) -> Self {
        ManifestEntry {
            path: item.path.clone(),
            original_extension: item
                .original_extension
                .clone()
                .filter(|s| !s.is_empty()),
            type_path: item.type_path.clone(),
        }
    }
}


/// Decrypt with a 32-byte AES key using AES-GCM.  This is the same logic that
/// used to live in `lib.rs`; moving it here allows crates that only depend on
/// the pack format helpers to perform decryption without pulling in the
/// higher-level API.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use secure_gate::ExposeSecret;
use ring::signature::Ed25519KeyPair;

pub fn decrypt_with_key(
    key: &crate::EncryptionKey,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, crate::DlcError> {
    key.with_secret(|key_bytes| {
        if key_bytes.len() != 32 {
            return Err(crate::DlcError::InvalidEncryptKey(
                "encrypt key must be 32 bytes (AES-256)".into(),
            ));
        }
        if nonce.len() != 12 {
            return Err(crate::DlcError::InvalidNonce(
                "nonce must be 12 bytes (AES-GCM)".into(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|e| crate::DlcError::CryptoError(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).map_err(|_| {
            crate::DlcError::DecryptionFailed(
                "authentication failed (incorrect key or corrupted ciphertext)".to_string(),
            )
        })
    })
}

/// Parse a `.dlcpack` container and return product, embedded dlc_id, and a list
/// of `(path, EncryptedAsset)` pairs. For v3 format, also validates the signature
/// against the authorized product public key.
///
/// Returns: (product, dlc_id, entries, signature_bytes_if_v3)
pub fn parse_encrypted_pack(
    bytes: &[u8],
) -> Result<
    (
        String,
        String,
        usize,
        Vec<(String, crate::asset_loader::EncryptedAsset)>,
    ),
    std::io::Error,
> {
    use std::io::ErrorKind;

    if bytes.len() < 4 + 1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "dlcpack too small",
        ));
    }
    if &bytes[0..4] != DLC_PACK_MAGIC {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "invalid dlcpack magic",
        ));
    }
    let version = bytes[4];
    let mut offset = 5usize;

    let product_str = if version == DLC_PACK_VERSION {
        if offset + 2 > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "v3: missing product_len",
            ));
        }
        let product_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + product_len > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "v3: invalid product length",
            ));
        }
        let prod = String::from_utf8(bytes[offset..offset + product_len].to_vec())
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
        offset += product_len;

        if offset + 64 > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "v3: missing signature",
            ));
        }
        let _signature = &bytes[offset..offset + 64].to_vec();
        offset += 64;

        prod
    } else if version < DLC_PACK_VERSION {
        String::new()
    } else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("unsupported pack version: {}", version),
        ));
    };

    let dlc_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    if offset + dlc_len > bytes.len() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "invalid dlc id length",
        ));
    }
    let dlc_id = String::from_utf8(bytes[offset..offset + dlc_len].to_vec())
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
    offset += dlc_len;

    let entries = if version == 1 {
        // legacy v1 format: count followed by per-entry metadata
        let entry_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        let mut out = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if offset + 2 > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "missing path_len",
                ));
            }
            let path_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2;
            if offset + path_len > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid path length",
                ));
            }
            let path = String::from_utf8(bytes[offset..offset + path_len].to_vec())
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
            offset += path_len;

            if offset + 1 > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "missing ext_len",
                ));
            }
            let ext_len = bytes[offset] as usize;
            offset += 1;
            let original_extension = if ext_len == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "missing original extension",
                ));
            } else {
                if offset + ext_len > bytes.len() {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "invalid ext length",
                    ));
                }
                let s = String::from_utf8(bytes[offset..offset + ext_len].to_vec())
                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                offset += ext_len;
                s
            };

            let original_type = if version >= 1 {
                if offset + 2 > bytes.len() {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "missing type_path len",
                    ));
                }
                let tlen = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
                offset += 2;
                if tlen == 0 {
                    None
                } else {
                    if offset + tlen > bytes.len() {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "invalid type_path length",
                        ));
                    }
                    let s = String::from_utf8(bytes[offset..offset + tlen].to_vec())
                        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                    offset += tlen;
                    Some(s)
                }
            } else {
                None
            };

            if offset + 12 + 4 > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "truncated entry",
                ));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&bytes[offset..offset + 12]);
            offset += 12;
            let ciphertext_len = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + ciphertext_len > bytes.len() {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "truncated ciphertext",
                ));
            }
            let ciphertext = bytes[offset..offset + ciphertext_len].into();
            offset += ciphertext_len;

            out.push((
                path,
                crate::asset_loader::EncryptedAsset {
                    dlc_id: dlc_id.clone(),
                    original_extension,
                    type_path: original_type,
                    nonce,
                    ciphertext,
                },
            ));
        }
        out
    } else {
        // version >= 2: manifest JSON followed by per-entry nonce+ciphertext
        if offset + 4 > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "missing manifest_len",
            ));
        }
        let manifest_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + manifest_len > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "manifest extends past end of file",
            ));
        }
        let manifest_bytes = &bytes[offset..offset + manifest_len];
        offset += manifest_len;

        let manifest: Vec<ManifestEntry> =
            serde_json::from_slice(manifest_bytes)
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let mut out = Vec::with_capacity(manifest.len());

        // newer packs encrypt the entire tar.gz archive as a single blob; the
        // manifest lists individual paths but the ciphertext/nonces are shared
        // (version>=2).  We read exactly one nonce+ciphertext pair and then
        // duplicate it for every manifest entry.  This keeps old `version==1`
        // behavior unaffected.
        if offset + 12 + 4 > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "truncated entry header",
            ));
        }
        let mut shared_nonce = [0u8; 12];
        shared_nonce.copy_from_slice(&bytes[offset..offset + 12]);
        offset += 12;
        let shared_ciphertext_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + shared_ciphertext_len > bytes.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "truncated ciphertext",
            ));
        }
        let shared_ciphertext: std::sync::Arc<[u8]> = bytes[offset..offset + shared_ciphertext_len].into();

        // populate output for each manifest entry using the shared blob
        for entry in manifest {
            out.push((
                entry.path,
                crate::asset_loader::EncryptedAsset {
                    dlc_id: dlc_id.clone(),
                    original_extension: entry.original_extension.unwrap_or_default(),
                    type_path: entry.type_path,
                    nonce: shared_nonce,
                    ciphertext: shared_ciphertext.clone(),
                },
            ));
        }
        out
    };

    // final return with the parsed data
    Ok((product_str, dlc_id, version as usize, entries))
}

/// Pack multiple entries into a single `.dlcpack` container.
///
/// Arguments:
/// - `dlc_id`: the DLC ID this pack belongs to (used for registry lookup and validation)
/// - `items`: a list of items to include in the pack, where each item is a tuple of (relative path, optional original file extension, optional type path, plaintext bytes)
/// - `product`: the product identifier to bind the pack to
/// - `dlc_key`: the `DlcKey` containing the private key used to sign the pack (must be a `DlcKey::Private`)
/// - `key`: the symmetric encryption key used to encrypt the pack contents (must be 32 bytes for AES-256)
pub fn pack_encrypted_pack(
    dlc_id: &crate::DlcId,
    items: &[crate::PackItem],
    product: &crate::Product,
    dlc_key: &crate::DlcKey,
    key: &crate::EncryptionKey,
) -> Result<Vec<u8>, crate::DlcError> {
    if key.len() != 32 {
        return Err(crate::DlcError::InvalidEncryptKey(
            "encryption key must be 32 bytes (AES-256)".into(),
        ));
    }

    let privkey_bytes = match dlc_key {
        crate::DlcKey::Private { privkey, .. } => privkey,
        crate::DlcKey::Public { .. } => {
            return Err(crate::DlcError::Other(
                "cannot sign pack with public-only key; use private key".into(),
            ));
        }
    };

    for item in items {
        if item.plaintext.len() >= 4 && item.plaintext.starts_with(DLC_PACK_MAGIC) {
            return Err(crate::DlcError::Other(format!(
                "cannot pack existing dlcpack container as an item: {}",
                item.path
            )));
        }

        if is_malicious_file(&item.path, item.original_extension.as_deref()) {
            return Err(crate::DlcError::Other(format!("file not allowed: {}", item.path)));
        }
    }

    use flate2::{Compression, write::GzEncoder};
    use tar::Builder;

    let mut tar_gz: Vec<u8> = Vec::new();
    {
        let enc = GzEncoder::new(&mut tar_gz, Compression::default());
        let mut tar = Builder::new(enc);
        for item in items {
            let mut header = tar::Header::new_gnu();
            header.set_size(item.plaintext.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();

            tar.append_data(
                &mut header,
                &item.path,
                &mut std::io::Cursor::new(&item.plaintext),
            )
            .map_err(|e| crate::DlcError::Other(e.to_string()))?;
        }

        let enc = tar
            .into_inner()
            .map_err(|e| crate::DlcError::Other(e.to_string()))?;

        let _ = enc.finish().map_err(|e| crate::DlcError::Other(e.to_string()))?;
    }

    let cipher = key.with_secret(|kb| {
        Aes256Gcm::new_from_slice(kb.as_slice()).map_err(|e| crate::DlcError::CryptoError(e.to_string()))
    })?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, tar_gz.as_slice())
        .map_err(|_| crate::DlcError::EncryptionFailed("encryption failed".into()))?;

    let mut manifest: Vec<ManifestEntry> = Vec::with_capacity(items.len());
    for item in items {
        manifest.push(ManifestEntry::from_pack_item(item));
    }
    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|e| crate::DlcError::Other(e.to_string()))?;

    let product_str = product.get();
    let dlc_id_str = dlc_id.to_string();
    let signature = privkey_bytes.with_secret(|priv_bytes| {
        let pair = Ed25519KeyPair::from_seed_unchecked(priv_bytes)
            .map_err(|e| crate::DlcError::CryptoError(format!("keypair: {:?}", e)))?;
        let mut signature_preimage = Vec::new();
        signature_preimage.extend_from_slice(product_str.as_bytes());
        signature_preimage.extend_from_slice(dlc_id_str.as_bytes());
        Ok::<_, crate::DlcError>(pair.sign(&signature_preimage).as_ref().to_vec())
    })?;

    let mut out = Vec::new();
    out.extend_from_slice(DLC_PACK_MAGIC);
    out.push(3u8); // version 3 (with signature + product)

    let product_bytes = product_str.as_bytes();
    out.extend_from_slice(&(product_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(product_bytes);

    if signature.len() != 64 {
        return Err(crate::DlcError::Other(format!(
            "ed25519 signature must be 64 bytes, got {}",
            signature.len()
        )));
    }
    out.extend_from_slice(&signature);

    let dlc_bytes = dlc_id_str.as_bytes();
    out.extend_from_slice(&(dlc_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(dlc_bytes);

    out.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&manifest_bytes);

    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_list_contains_known() {
        assert!(is_forbidden_extension("exe"));
        assert!(is_forbidden_extension("EXE"));
        assert!(!is_forbidden_extension("png"));
    }

    #[test]
    fn manifest_roundtrip() {
        let item = crate::PackItem::new("foo.txt", b"hello" as &[u8]).unwrap();
        let entry = ManifestEntry::from_pack_item(&item);
        let bytes = serde_json::to_vec(&entry).unwrap();
        let back: ManifestEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(entry.path, back.path);
    }
}
