use once_cell::sync::Lazy;
use std::collections::HashSet;

/// .dlcpack container magic header (4 bytes) used to identify encrypted pack containers.
pub const DLC_PACK_MAGIC: &[u8; 4] = b"BDLP";

/// Current supported .dlcpack format version. This is stored in the container header and used to determine how to parse the contents.
pub const DLC_PACK_VERSION_LATEST: u8 = 3;

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

/// Representation of a single manifest entry inside a v2+ `.dlcpack`.
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

/// Internal helper for binary parsing with offset management.
struct PackReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PackReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn check_len(&self, len: usize) -> std::io::Result<()> {
        if self.offset + len > self.bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected end of dlcpack (truncated data)",
            ));
        }
        Ok(())
    }

    fn read_u8(&mut self) -> std::io::Result<u8> {
        self.check_len(1)?;
        let val = self.bytes[self.offset];
        self.offset += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> std::io::Result<u16> {
        self.check_len(2)?;
        let val = u16::from_be_bytes([self.bytes[self.offset], self.bytes[self.offset + 1]]);
        self.offset += 2;
        Ok(val)
    }

    fn read_u32(&mut self) -> std::io::Result<u32> {
        self.check_len(4)?;
        let val = u32::from_be_bytes([
            self.bytes[self.offset],
            self.bytes[self.offset + 1],
            self.bytes[self.offset + 2],
            self.bytes[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(val)
    }

    fn read_bytes(&mut self, len: usize) -> std::io::Result<&'a [u8]> {
        self.check_len(len)?;
        let data = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(data)
    }

    fn read_string_u16(&mut self) -> std::io::Result<String> {
        let len = self.read_u16()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn read_string_u8(&mut self) -> std::io::Result<String> {
        let len = self.read_u8()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn read_nonce(&mut self) -> std::io::Result<[u8; 12]> {
        let bytes = self.read_bytes(12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(bytes);
        Ok(nonce)
    }
}

/// Internal helper for binary packing.
struct PackWriter {
    buf: Vec<u8>,
}

impl PackWriter {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    fn write_u16(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn write_string_u16(&mut self, s: &str) {
        let bytes = s.as_bytes();
        self.write_u16(bytes.len() as u16);
        self.write_bytes(bytes);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Represents the header of any version of a `.dlcpack`.
struct PackHeader {
    version: u8,
    product: String,
    signature: Option<[u8; 64]>,
    dlc_id: String,
}

impl PackHeader {
    fn read(reader: &mut PackReader) -> std::io::Result<Self> {
        let magic = reader.read_bytes(4)?;
        if magic != DLC_PACK_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid dlcpack magic",
            ));
        }

        let version = reader.read_u8()?;
        let mut product = String::new();
        let mut signature = None;

        if version == 3 {
            product = reader.read_string_u16()?;
            let sig_bytes = reader.read_bytes(64)?;
            let mut sig = [0u8; 64];
            sig.copy_from_slice(sig_bytes);
            signature = Some(sig);
        } else if version > 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported pack version: {}", version),
            ));
        }

        let dlc_id = reader.read_string_u16()?;

        Ok(PackHeader {
            version,
            product,
            signature,
            dlc_id,
        })
    }

    fn write(&self, writer: &mut PackWriter) {
        writer.write_bytes(DLC_PACK_MAGIC);
        writer.write_u8(self.version);

        if self.version == 3 {
            writer.write_string_u16(&self.product);
            if let Some(sig) = self.signature {
                writer.write_bytes(&sig);
            }
        }

        writer.write_string_u16(&self.dlc_id);
    }
}

/// Decrypt with a 32-byte AES key using AES-GCM.  This is the same logic that
/// used to live in `lib.rs`; moving it here allows crates that only depend on
/// the pack format helpers to perform decryption without pulling in the
/// higher-level API.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use secure_gate::ExposeSecret;
use ring::signature::Ed25519KeyPair;

use crate::{DlcError, DlcId, DlcKey, EncryptionKey, PackItem, Product};

pub fn decrypt_with_key(
    key: &crate::EncryptionKey,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, DlcError> {
    key.with_secret(|key_bytes| {
        if key_bytes.len() != 32 {
            return Err(DlcError::InvalidEncryptKey(
                "encrypt key must be 32 bytes (AES-256)".into(),
            ));
        }
        if nonce.len() != 12 {
            return Err(DlcError::InvalidNonce(
                "nonce must be 12 bytes (AES-GCM)".into(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|e| DlcError::CryptoError(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).map_err(|_| {
            DlcError::DecryptionFailed(
                "authentication failed (incorrect key or corrupted ciphertext)".to_string(),
            )
        })
    })
}

/// Returns: (product, dlc_id, version, entries)
pub fn parse_encrypted_pack(
    bytes: &[u8],
) -> Result<
    (
        Product,
        DlcId,
        usize,
        Vec<(String, crate::asset_loader::EncryptedAsset)>,
    ),
    std::io::Error,
> {
    use std::io::ErrorKind;

    let mut reader = PackReader::new(bytes);
    let header = PackHeader::read(&mut reader)?;

    let entries = if header.version == 1 {
        // legacy v1 format: each entry has its own metadata and ciphertext
        let entry_count = reader.read_u16()? as usize;
        let mut out = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let path = reader.read_string_u16()?;
            let original_extension = reader.read_string_u8()?;
            
            // v1: optional type_path
            let tlen = reader.read_u16()? as usize;
            let type_path = if tlen == 0 {
                None
            } else {
                let s = String::from_utf8(reader.read_bytes(tlen)?.to_vec())
                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
                Some(s)
            };

            let nonce = reader.read_nonce()?;
            let ciphertext_len = reader.read_u32()? as usize;
            let ciphertext = reader.read_bytes(ciphertext_len)?.into();

            out.push((
                path,
                crate::asset_loader::EncryptedAsset {
                    dlc_id: header.dlc_id.clone(),
                    original_extension,
                    type_path,
                    nonce,
                    ciphertext,
                },
            ));
        }
        out
    } else {
        // version 2+: manifest JSON followed by shared nonce and ciphertext
        let manifest_len = reader.read_u32()? as usize;
        let manifest_bytes = reader.read_bytes(manifest_len)?;
        let manifest: Vec<ManifestEntry> = serde_json::from_slice(manifest_bytes)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let mut out = Vec::with_capacity(manifest.len());

        let shared_nonce = reader.read_nonce()?;
        let shared_ciphertext_len = reader.read_u32()? as usize;
        let shared_ciphertext: std::sync::Arc<[u8]> = reader.read_bytes(shared_ciphertext_len)?.into();

        for entry in manifest {
            out.push((
                entry.path,
                crate::asset_loader::EncryptedAsset {
                    dlc_id: header.dlc_id.clone(),
                    original_extension: entry.original_extension.unwrap_or_default(),
                    type_path: entry.type_path,
                    nonce: shared_nonce,
                    ciphertext: shared_ciphertext.clone(),
                },
            ));
        }
        out
    };

    Ok((
        Product::from(header.product),
        DlcId::from(header.dlc_id),
        header.version as usize,
        entries,
    ))
}

/// Pack multiple entries into a single `.dlcpack` container.
///
/// Arguments:
/// - `dlc_id`: the DLC ID this pack belongs to (used for registry lookup and validation)
/// - `items`: a list of [PackItem]s containing the plaintext data to be packed
/// - `product`: the product identifier to bind the pack to
/// - `dlc_key`: the `DlcKey` containing the private key used to sign the pack (must be a `DlcKey::Private`)
/// - `key`: the symmetric encryption key used to encrypt the pack contents (must be 32 bytes for AES-256)
pub fn pack_encrypted_pack(
    dlc_id: &DlcId,
    items: &[PackItem],
    product: &Product,
    dlc_key: &DlcKey,
    key: &EncryptionKey,
) -> Result<Vec<u8>, DlcError> {
    if key.len() != 32 {
        return Err(DlcError::InvalidEncryptKey(
            "encryption key must be 32 bytes (AES-256)".into(),
        ));
    }

    let (privkey_bytes, pubkey_bytes) = match dlc_key {
        DlcKey::Private { privkey, pubkey } => (privkey, pubkey.0),
        DlcKey::Public { .. } => {
            return Err(DlcError::Other(
                "cannot sign pack with public-only key; use private key".into(),
            ));
        }
    };

    for item in items {
        if item.plaintext.len() >= 4 && item.plaintext.starts_with(DLC_PACK_MAGIC) {
            return Err(DlcError::Other(format!(
                "cannot pack existing dlcpack container as an item: {}",
                item.path
            )));
        }

        if is_malicious_file(&item.path, item.original_extension.as_deref()) {
            return Err(DlcError::Other(format!("file not allowed: {}", item.path)));
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
            .map_err(|e| DlcError::Other(e.to_string()))?;
        }

        let enc = tar
            .into_inner()
            .map_err(|e| DlcError::Other(e.to_string()))?;

        let _ = enc.finish().map_err(|e| DlcError::Other(e.to_string()))?;
    }

    let cipher = key.with_secret(|kb| {
        Aes256Gcm::new_from_slice(kb.as_slice()).map_err(|e| DlcError::CryptoError(e.to_string()))
    })?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, tar_gz.as_slice())
        .map_err(|_| DlcError::EncryptionFailed("encryption failed".into()))?;

    let mut manifest: Vec<ManifestEntry> = Vec::with_capacity(items.len());
    for item in items {
        manifest.push(ManifestEntry::from_pack_item(item));
    }
    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|e| DlcError::Other(e.to_string()))?;

    let product_str = product.as_ref();
    let dlc_id_str = dlc_id.to_string();
    let signature = privkey_bytes.with_secret(|priv_bytes| {
        let pair = Ed25519KeyPair::from_seed_and_public_key(priv_bytes, &pubkey_bytes)
            .map_err(|e| DlcError::CryptoError(format!("keypair: {:?}", e)))?;
        let mut signature_preimage = Vec::new();
        signature_preimage.extend_from_slice(product_str.as_bytes());
        signature_preimage.extend_from_slice(dlc_id_str.as_bytes());
        Ok::<_, DlcError>(pair.sign(&signature_preimage).as_ref().to_vec())
    })?;

    let sig_fixed: [u8; 64] = signature.try_into().map_err(|_| {
        DlcError::Other("ed25519 signature must be exactly 64 bytes".into())
    })?;

    let mut writer = PackWriter::new();
    let header = PackHeader {
        version: DLC_PACK_VERSION_LATEST,
        product: product_str.to_string(),
        signature: Some(sig_fixed),
        dlc_id: dlc_id_str.to_string(),
    };
    header.write(&mut writer);

    // Write body
    writer.write_u32(manifest_bytes.len() as u32);
    writer.write_bytes(&manifest_bytes);
    writer.write_bytes(&nonce_bytes);
    writer.write_u32(ciphertext.len() as u32);
    writer.write_bytes(&ciphertext);

    Ok(writer.finish())
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
