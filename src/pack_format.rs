use once_cell::sync::Lazy;
use std::collections::HashSet;

/// .dlcpack container magic header (4 bytes) used to identify encrypted pack containers.
pub const DLC_PACK_MAGIC: &[u8; 4] = b"BDLP";

/// Current supported .dlcpack format version. This is stored in the container header and used to determine how to parse the contents.
pub const DLC_PACK_VERSION_LATEST: u8 = 4;

/// Default block size for v4 hybrid format (10 MB). Blocks are individually encrypted tar.gz chunks.
pub const DEFAULT_BLOCK_SIZE: usize = 10 * 1024 * 1024;

/// List of file extensions that are never allowed to be packed.  These are
/// taken from the same array that used to live in [lib.rs]; we keep the
/// array for deterministic build and the hash set for fast membership tests.
pub const FORBIDDEN_EXTENSIONS: &[&str] = &[
    "7z", "accda", "accdb", "accde", "accdr", "ace", "ade", "adp", "app", "appinstaller", "application", "appref", "appx", "appxbundle", "arj", "asax", "asd", "ashx", "asp", "aspx", "b64", "bas", "bat", "bgi", "bin", "btm", "bz", "bz2", "bzip", "bzip2", "cab", "cer", "cfg", "chi", "chm", "cla", "class", "cmd", "com", "cpi", "cpio", "cpl", "crt", "crx", "csh", "der", "desktopthemefile", "diagcab", "diagcfg", "diagpkg", "dll", "dmg", "doc", "docm", "docx", "dotm", "drv", "eml", "exe", "fon", "fxp", "gadget", "grp", "gz", "gzip", "hlp", "hta", "htc", "htm", "html", "htt", "ics", "img", "ini", "ins", "inx", "iqy", "iso", "isp", "isu", "jar", "jnlp", "job", "js", "jse", "ksh", "lha", "lnk", "local", "lz", "lzh", "lzma", "mad", "maf", "mag", "mam", "manifest", "maq", "mar", "mas", "mat", "mav", "maw", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mmc", "msc", "msg", "msh", "msh1", "msh1xml", "msh2", "msh2xml", "mshxml", "msi", "msix", "msixbundle", "msm", "msp", "mst", "msu", "ocx", "odt", "one", "onepkg", "onetoc", "onetoc2", "ops", "oxps", "oxt", "paf", "partial", "pcd", "pdf", "pif", "pl", "plg", "pol", "potm", "ppam", "ppkg", "ppsm", "ppt", "pptm", "pptx", "prf", "prg", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "psm1", "pst", "r00", "r01", "r02", "r03", "rar", "reg", "rels", "rev", "rgs", "rpm", "rtf", "scf", "scr", "sct", "search", "settingcontent", "settingscontent", "sh", "shb", "sldm", "slk", "svg", "swf", "sys", "tar", "tbz", "tbz2", "tgz", "tlb", "url", "uue", "vb", "vbe", "vbs", "vbscript", "vdx", "vhd", "vhdx", "vsmacros", "vss", "vssm", "vssx", "vst", "vstm", "vstx", "vsw", "vsx", "vtx", "wbk", "webarchive", "website", "wml", "ws", "wsc", "wsf", "wsh", "xar", "xbap", "xdp", "xlam", "xll", "xlm", "xls", "xlsb", "xlsm", "xlsx", "xltm", "xlw", "xml", "xnk", "xps", "xrm", "xsd", "xsl", "xxe", "xz", "z", "zip",
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

/// V4 manifest entry: binary-serializable format for faster parsing.
/// Format: path_len(u32) + path(utf8) + ext_len(u8) + ext(utf8) + type_len(u16) + type(utf8) + block_id(u32) + block_offset(u32) + size(u32)
#[derive(Clone, Debug)]
pub struct V4ManifestEntry {
    pub path: String,
    pub original_extension: String,
    pub type_path: Option<String>,
    /// Which block contains this asset
    pub block_id: u32,
    /// Offset within the decompressed block's tar archive
    pub block_offset: u32,
    /// Uncompressed size (for progress/buffer allocation)
    pub size: u32,
}

impl V4ManifestEntry {
    pub fn from_pack_item(item: &crate::PackItem, block_id: u32, block_offset: u32) -> Self {
        V4ManifestEntry {
            path: item.path.clone(),
            original_extension: item.original_extension.clone().unwrap_or_default(),
            type_path: item.type_path.clone(),
            block_id,
            block_offset,
            size: item.plaintext.len() as u32,
        }
    }

    /// Write this entry in binary format (used by v4 format conversion)
    #[allow(dead_code)]
    fn write_binary<W: std::io::Write>(&self, writer: &mut PackWriter<W>) -> std::io::Result<()> {
        writer.write_u32(self.path.len() as u32)?;
        writer.write_bytes(self.path.as_bytes())?;

        writer.write_u8(self.original_extension.len() as u8)?;
        writer.write_bytes(self.original_extension.as_bytes())?;

        if let Some(ref tp) = self.type_path {
            writer.write_u16(tp.len() as u16)?;
            writer.write_bytes(tp.as_bytes())?;
        } else {
            writer.write_u16(0)?;
        }

        writer.write_u32(self.block_id)?;
        writer.write_u32(self.block_offset)?;
        writer.write_u32(self.size)
    }

    /// Read binary format from reader (used by v4 format parsing)
    #[allow(dead_code)]
    fn read_binary<R: std::io::Read>(reader: &mut PackReader<R>) -> std::io::Result<Self> {
        let path_len = reader.read_u32()? as usize;
        let path = String::from_utf8(reader.read_bytes(path_len)?)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let ext_len = reader.read_u8()? as usize;
        let original_extension = if ext_len > 0 {
            String::from_utf8(reader.read_bytes(ext_len)?)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        } else {
            String::new()
        };

        let type_len = reader.read_u16()? as usize;
        let type_path = if type_len > 0 {
            let tp = String::from_utf8(reader.read_bytes(type_len)?)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Some(tp)
        } else {
            None
        };

        let block_id = reader.read_u32()?;
        let block_offset = reader.read_u32()?;
        let size = reader.read_u32()?;

        Ok(V4ManifestEntry {
            path,
            original_extension,
            type_path,
            block_id,
            block_offset,
            size,
        })
    }
}

/// V4 block metadata: stores information about a tar-gz block within the pack file
#[derive(Clone, Debug)]
pub struct BlockMetadata {
    pub block_id: u32,
    pub file_offset: u64,      // Where this block starts in the file
    pub encrypted_size: u32,   // Size of encrypted ciphertext
    pub uncompressed_size: u32, // Size after decompression (for buffer allocation)
    pub nonce: [u8; 12],       // Per-block nonce
    pub crc32: u32,            // CRC32 checksum for integrity
}

impl BlockMetadata {
    #[allow(dead_code)]
    fn write_binary<W: std::io::Write>(&self, writer: &mut PackWriter<W>) -> std::io::Result<()> {
        writer.write_u32(self.block_id)?;
        writer.write_u64(self.file_offset)?;
        writer.write_u32(self.encrypted_size)?;
        writer.write_u32(self.uncompressed_size)?;
        writer.write_bytes(&self.nonce)?;
        writer.write_u32(self.crc32)
    }

    #[allow(dead_code)]
    fn read_binary<R: std::io::Read>(reader: &mut PackReader<R>) -> std::io::Result<Self> {
        let block_id = reader.read_u32()?;
        let file_offset = reader.read_u64()?;
        let encrypted_size = reader.read_u32()?;
        let uncompressed_size = reader.read_u32()?;
        let nonce = reader.read_nonce()?;
        let crc32 = reader.read_u32()?;

        Ok(BlockMetadata {
            block_id,
            file_offset,
            encrypted_size,
            uncompressed_size,
            nonce,
            crc32,
        })
    }
}

// converters and migration helpers have been removed – the crate
// now only supports v4 packs.  The old `PackConverter` trait, the
// `V3toV4Converter` implementation and the `PackConverterRegistry` type
// were used to upgrade on‑disk packs to the latest format; they are
// retained in history if needed but no longer compiled.

/// Internal helper for binary parsing with offset management.
pub(crate) struct PackReader<R: std::io::Read> {
    inner: R,
}

impl<R: std::io::Read> PackReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Read a byte.
    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0u8; 1];
        self.inner.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    /// Convenience method: read `len` bytes and immediately decrypt them with
    /// the provided AES-GCM key/nonce.
    #[allow(dead_code)]
    pub fn read_and_decrypt(
        &mut self,
        key: &crate::EncryptionKey,
        len: usize,
        nonce: &[u8],
    ) -> Result<Vec<u8>, DlcError> {
        let ciphertext = self.read_bytes(len)?;

        let cursor = std::io::Cursor::new(ciphertext);
        crate::pack_format::decrypt_with_key(key, cursor, nonce)
    }

    pub fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buf = [0u8; 2];
        self.inner.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    pub fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0u8; 4];
        self.inner.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    #[allow(dead_code)]
    pub fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut buf = [0u8; 8];
        self.inner.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    pub fn read_bytes(&mut self, len: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn read_string_u16(&mut self) -> std::io::Result<String> {
        let len = self.read_u16()? as usize;
        self.read_string_internal(len)
    }

    pub fn read_string_u8(&mut self) -> std::io::Result<String> {
        let len = self.read_u8()? as usize;
        self.read_string_internal(len)
    }

    fn read_string_internal(&mut self, len: usize) -> std::io::Result<String> {
        let bytes = self.read_bytes(len)?;
        // Avoid allocation for UTF-8 validation by using from_utf8_lossy internally,
        // but preserve error semantics for actual validation
        String::from_utf8(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn read_nonce(&mut self) -> std::io::Result<[u8; 12]> {
        let mut nonce = [0u8; 12];
        self.inner.read_exact(&mut nonce)?;
        Ok(nonce)
    }
}

// additional helpers available when the inner reader also implements `Seek`
impl<R: std::io::Read + std::io::Seek> PackReader<R> {
    /// Seek the underlying reader to `pos` and return the new position.
    pub fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Internal helper for binary packing.
pub(crate) struct PackWriter<W: std::io::Write> {
    inner: W,
}

impl<W: std::io::Write> PackWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Encrypt `plaintext` with the provided key/nonce and write the
    /// resulting ciphertext to the underlying writer.
    #[allow(dead_code)]
    pub fn write_encrypted(
        &mut self,
        key: &crate::EncryptionKey,
        nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<(), DlcError> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        let cipher = key.with_secret(|kb| {
            Aes256Gcm::new_from_slice(kb).map_err(|e| DlcError::CryptoError(e.to_string()))
        })?;
        let ct = cipher
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .map_err(|_| DlcError::EncryptionFailed("block encryption failed".into()))?;
        self.write_bytes(&ct).map_err(|e| DlcError::Other(e.to_string()))
    }

    pub fn write_u8(&mut self, val: u8) -> std::io::Result<()> {
        self.inner.write_all(&[val])
    }

    pub fn write_u16(&mut self, val: u16) -> std::io::Result<()> {
        self.inner.write_all(&val.to_be_bytes())
    }

    pub fn write_u32(&mut self, val: u32) -> std::io::Result<()> {
        self.inner.write_all(&val.to_be_bytes())
    }

    pub fn write_u64(&mut self, val: u64) -> std::io::Result<()> {
        self.inner.write_all(&val.to_be_bytes())
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(bytes)
    }

    pub fn write_string_u16(&mut self, s: &str) -> std::io::Result<()> {
        let bytes = s.as_bytes();
        self.write_u16(bytes.len() as u16)?;
        self.write_bytes(bytes)
    }

    pub fn finish(mut self) -> std::io::Result<W> {
        self.inner.flush()?;
        Ok(self.inner)
    }
}

/// Represents the header of any version of a `.dlcpack`.
struct PackHeader {
    version: u8,
    product: String,
    dlc_id: String,
}

impl PackHeader {
    fn read<R: std::io::Read>(reader: &mut PackReader<R>) -> std::io::Result<Self> {
        let magic = reader.read_bytes(4)?;
        if magic != DLC_PACK_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid dlcpack magic",
            ));
        }

        let version = reader.read_u8()?;
        let mut product = String::new();

        if version == 3 || version == 4 {
            product = reader.read_string_u16()?;
        } else if version > 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported pack version: {}", version),
            ));
        }

        let dlc_id = reader.read_string_u16()?;

        Ok(PackHeader {
            version,
            product,
            dlc_id,
        })
    }

    fn write<W: std::io::Write>(&self, writer: &mut PackWriter<W>) -> std::io::Result<()> {
        writer.write_bytes(DLC_PACK_MAGIC)?;
        writer.write_u8(self.version)?;

        if self.version == 3 || self.version == 4 {
            writer.write_string_u16(&self.product)?;
        }

        writer.write_string_u16(&self.dlc_id)
    }
}

/// Decrypt with a 32-byte AES key using AES-GCM.  This is the same logic that
/// used to live in `lib.rs`; moving it here allows crates that only depend on
/// the pack format helpers to perform decryption without pulling in the
/// higher-level API.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use secure_gate::ExposeSecret;

use crate::{DlcError, DlcId, EncryptionKey, PackItem, Product};

pub(crate) fn decrypt_with_key<R: std::io::Read>(
    key: &crate::EncryptionKey,
    mut reader: R,
    nonce: &[u8],
) -> Result<Vec<u8>, DlcError> {
    // read ciphertext into a single buffer; decrypt it in-place to avoid
    // allocating a second plaintext buffer.
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| DlcError::Other(e.to_string()))?;

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
        // decrypt in-place; `buf` will be overwritten with plaintext
        cipher
            .decrypt_in_place(nonce, &[], &mut buf)
            .map_err(|_|
                DlcError::DecryptionFailed(
                    "authentication failed (incorrect key or corrupted ciphertext)".to_string(),
                )
            )
    })?;
    Ok(buf)
}

/// Compression level for packing. Controls the trade-off between pack size and packing time.
/// Higher levels produce smaller files but take longer to create.
#[derive(Debug, Clone, Copy)]
pub enum CompressionLevel {
    /// Fast compression (level 1), suitable for rapid iterations
    Fast,
    /// Balanced compression (level 6, default), good trade-off
    Default,
    /// Best compression (level 9), smallest file size for distribution
    Best,
}

impl From<CompressionLevel> for flate2::Compression {
    fn from(level: CompressionLevel) -> Self {
        match level {
            CompressionLevel::Fast => flate2::Compression::fast(),
            CompressionLevel::Default => flate2::Compression::default(),
            CompressionLevel::Best => flate2::Compression::best(),
        }
    }
}

/// Pack multiple entries into a v4 hybrid format `.dlcpack` container.
pub fn pack_encrypted_pack_v4(
    dlc_id: &DlcId,
    items: &[PackItem],
    product: &Product,
    key: &EncryptionKey,
    block_size: usize,
) -> Result<Vec<u8>, DlcError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    let cipher = key.with_secret(|kb| {
        Aes256Gcm::new_from_slice(kb.as_slice()).map_err(|e| DlcError::CryptoError(e.to_string()))
    })?;

    // 1. Group items into blocks
    let mut blocks: Vec<Vec<&PackItem>> = Vec::new();
    let mut current_block = Vec::new();
    let mut current_size = 0;

    for item in items {
        if !current_block.is_empty() && current_size + item.plaintext.len() > block_size {
            blocks.push(std::mem::take(&mut current_block));
            current_size = 0;
        }
        current_size += item.plaintext.len();
        current_block.push(item);
    }
    if !current_block.is_empty() {
        blocks.push(current_block);
    }

    // 2. Build blocks and track offsets
    let mut encrypted_blocks = Vec::new();
    let mut manifest_entries = Vec::new();
    let mut block_metadatas = Vec::new();

    for (block_id, block_items) in blocks.into_iter().enumerate() {
        let block_id = block_id as u32;
        let mut tar_gz = Vec::new();
        let mut uncompressed_size = 0;
        {
            let mut gz = GzEncoder::new(&mut tar_gz, Compression::default());
            {
                let mut tar = Builder::new(&mut gz);
                let mut offset = 0;

                for item in block_items {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(item.plaintext.len() as u64);
                    header.set_mode(0o644);
                    header.set_cksum();

                    let path_str = item.path.clone();
                    manifest_entries.push(V4ManifestEntry {
                        path: path_str,
                        original_extension: item.original_extension.clone().unwrap_or_default(),
                        type_path: item.type_path.clone(),
                        block_id,
                        block_offset: offset,
                        size: item.plaintext.len() as u32,
                    });

                    tar.append_data(&mut header, &item.path, &item.plaintext[..])
                        .map_err(|e| DlcError::Other(e.to_string()))?;

                    // tar header is 512, plus data (padded to 512)
                    let data_len = item.plaintext.len() as u32;
                    let padded_len = (data_len + 511) & !511;
                    offset += 512 + padded_len;
                    uncompressed_size += data_len;
                }
                tar.finish().map_err(|e| DlcError::Other(e.to_string()))?;
            }
            gz.finish().map_err(|e| DlcError::Other(e.to_string()))?;
        }

        // Encrypt block
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, tar_gz.as_slice())
            .map_err(|_| DlcError::EncryptionFailed("block encryption failed".into()))?;

        let crc32 = crc32fast::hash(&ciphertext);

        block_metadatas.push(BlockMetadata {
            block_id,
            file_offset: 0, // Fill later
            encrypted_size: ciphertext.len() as u32,
            uncompressed_size,
            nonce: nonce_bytes,
            crc32,
        });

        encrypted_blocks.push(ciphertext);
    }

    // 3. Assemble final binary
    let product_str = product.as_ref();
    let dlc_id_str = dlc_id.to_string();

    let mut out = Vec::new();
    {
        let mut writer = PackWriter::new(&mut out);

        let header = PackHeader {
            version: 4,
            product: product_str.to_string(),
            dlc_id: dlc_id_str.clone(),
        };
        header.write(&mut writer).map_err(|e| DlcError::Other(e.to_string()))?;

        // Manifest
        writer.write_u32(manifest_entries.len() as u32).map_err(|e| DlcError::Other(e.to_string()))?;
        for entry in &manifest_entries {
            entry.write_binary(&mut writer).map_err(|e| DlcError::Other(e.to_string()))?;
        }

        // Block Metadata placeholder
        writer.write_u32(block_metadatas.len() as u32).map_err(|e| DlcError::Other(e.to_string()))?;
        writer.finish().map_err(|e| DlcError::Other(e.to_string()))?;
    }
    let metadata_start_pos = out.len();
    {
        let mut writer = PackWriter::new(&mut out);
        for meta in &block_metadatas {
            meta.write_binary(&mut writer).map_err(|e| DlcError::Other(e.to_string()))?;
        }
        writer.finish().map_err(|e| DlcError::Other(e.to_string()))?;
    }

    // Encrypted Blocks
    for (i, block) in encrypted_blocks.into_iter().enumerate() {
        let pos = out.len() as u64;
        block_metadatas[i].file_offset = pos;
        out.extend_from_slice(&block);
    }

    // Rewrite block metadatas with correct file_offsets
    {
        let mut writer_fixed = PackWriter::new(&mut out[metadata_start_pos..]);
        for meta in &block_metadatas {
            meta.write_binary(&mut writer_fixed).map_err(|e| DlcError::Other(e.to_string()))?;
        }
        writer_fixed.finish().map_err(|e| DlcError::Other(e.to_string()))?;
    }

    Ok(out)
}

/// Returns: (product, dlc_id, version, entries)
pub fn parse_encrypted_pack<R: std::io::Read>(
    reader: R,
) -> Result<
    (
        Product,
        DlcId,
        usize,
        Vec<(String, crate::asset_loader::EncryptedAsset)>,
        Vec<BlockMetadata>,
    ),
    std::io::Error,
> {
    use std::io::ErrorKind;

    let mut reader = PackReader::new(reader);
    let header = PackHeader::read(&mut reader)?;
    let mut block_metadatas = Vec::new();

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
                let bytes = reader.read_bytes(tlen)?;
                let s = String::from_utf8(bytes)
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
                    block_id: 0,
                    block_offset: 0,
                    size: 0,
                },
            ));
        }
        out
    } else if header.version == 4 {
        // version 4: hybrid multi-block format
        let manifest_count = reader.read_u32()? as usize;
        let mut manifest: Vec<V4ManifestEntry> = Vec::with_capacity(manifest_count);
        for _ in 0..manifest_count {
            manifest.push(V4ManifestEntry::read_binary(&mut reader)?);
        }

        let block_count = reader.read_u32()? as usize;
        block_metadatas = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            block_metadatas.push(BlockMetadata::read_binary(&mut reader)?);
        }

        let mut out = Vec::with_capacity(manifest.len());
        for entry in manifest {
            out.push((
                entry.path,
                crate::asset_loader::EncryptedAsset {
                    dlc_id: header.dlc_id.clone(),
                    original_extension: entry.original_extension,
                    type_path: entry.type_path,
                    nonce: [0u8; 12],
                    ciphertext: std::sync::Arc::new([]),
                    block_id: entry.block_id,
                    block_offset: entry.block_offset,
                    size: entry.size,
                },
            ));
        }
        out
    } else {
        // version 2/3: manifest JSON followed by shared nonce and ciphertext
        let manifest_len = reader.read_u32()? as usize;
        let manifest_bytes = reader.read_bytes(manifest_len)?;
        let manifest: Vec<ManifestEntry> = serde_json::from_slice(&manifest_bytes)
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
                    block_id: 0,
                    block_offset: 0,
                    size: shared_ciphertext.len() as u32,
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
        block_metadatas,
    ))
}

/// Pack multiple entries into a single `.dlcpack` container.
///
/// Arguments:
/// - `dlc_id`: the [DlcId] this pack belongs to (used for registry lookup and validation)
/// - `items`: a list of [PackItem]s containing the plaintext data to be packed
/// - `product`: the [Product] identifier to bind the pack to
/// - `key`: the symmetric encryption key used to encrypt the pack contents (must be 32 bytes for AES-256)
pub fn pack_encrypted_pack(
    dlc_id: &DlcId,
    items: &[PackItem],
    product: &Product,
    key: &EncryptionKey,
) -> Result<Vec<u8>, DlcError> {
    pack_encrypted_pack_v4(dlc_id, items, product, key, DEFAULT_BLOCK_SIZE)
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
