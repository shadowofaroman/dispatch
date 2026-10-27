use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::error::{DispatchError, Result};
use crate::protocol::TransferId;

const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SidecarMetadata {
    pub transfer_id: TransferId,
    pub file_name: String,
    pub file_size: u64,
    pub block_size: u32,
    pub verified_blocks: HashMap<u32, [u8; 32]>,
}

pub struct StorageManager {
    base_dir: PathBuf,
}

impl StorageManager {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self { base_dir: dir })
    }

    /// Sanitizes file name and rejects path traversals, null bytes, and Windows reserved names
    pub fn sanitize_file_name(&self, raw_name: &str) -> Result<String> {
        let trimmed = raw_name.trim();
        if trimmed.is_empty() {
            return Err(DispatchError::InvalidFileName("Empty file name".into()));
        }

        if trimmed.contains('\0') {
            return Err(DispatchError::InvalidFileName("File name contains null byte".into()));
        }

        // Check for path traversal components
        if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") {
            return Err(DispatchError::InvalidFileName(
                "File name contains path separators or parent directory traversal".into(),
            ));
        }

        // Clean out path separators using Path basename
        let path = Path::new(trimmed);
        let base_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| DispatchError::InvalidFileName("Invalid file name component".into()))?;

        // Check Windows reserved names (ignoring extension)
        let stem = Path::new(base_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(base_name)
            .to_uppercase();

        for reserved in WINDOWS_RESERVED_NAMES {
            if stem == *reserved {
                return Err(DispatchError::InvalidFileName(format!(
                    "File name uses reserved system name: {base_name}"
                )));
            }
        }

        Ok(base_name.to_string())
    }

    /// Checks that available disk space is greater than or equal to file size + safety buffer
    pub fn check_free_space(&self, required_bytes: u64) -> Result<()> {
        let free_space = fs2::available_space(&self.base_dir).unwrap_or(u64::MAX);
        // 10 MiB safety buffer
        let needed = required_bytes.saturating_add(10 * 1024 * 1024);

        if free_space < needed {
            return Err(DispatchError::InsufficientDiskSpace {
                available: free_space,
                required: needed,
            });
        }
        Ok(())
    }

    pub fn get_part_path(&self, sanitized_name: &str) -> PathBuf {
        self.base_dir.join(format!("{sanitized_name}.dispatch-part"))
    }

    pub fn get_meta_path(&self, sanitized_name: &str) -> PathBuf {
        self.base_dir.join(format!("{sanitized_name}.dispatch-meta"))
    }

    /// Loads existing sidecar metadata if valid and matches transfer parameters
    pub fn load_sidecar(
        &self,
        sanitized_name: &str,
        transfer_id: &TransferId,
        file_size: u64,
    ) -> Option<SidecarMetadata> {
        let meta_path = self.get_meta_path(sanitized_name);
        if !meta_path.exists() {
            return None;
        }

        let content = fs::read_to_string(&meta_path).ok()?;
        let meta: SidecarMetadata = serde_json::from_str(&content).ok()?;

        if meta.transfer_id == *transfer_id && meta.file_size == file_size {
            Some(meta)
        } else {
            None
        }
    }

    /// Saves sidecar metadata to disk
    pub fn save_sidecar(&self, sanitized_name: &str, meta: &SidecarMetadata) -> Result<()> {
        let meta_path = self.get_meta_path(sanitized_name);
        let content = serde_json::to_string_pretty(meta)
            .map_err(|e| DispatchError::Serialization(e.to_string()))?;
        fs::write(&meta_path, content)?;
        Ok(())
    }

    /// Pre-allocates or opens the part file
    pub fn open_part_file(&self, sanitized_name: &str, file_size: u64) -> Result<File> {
        let part_path = self.get_part_path(sanitized_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&part_path)?;

        let current_len = file.metadata()?.len();
        if current_len < file_size {
            file.set_len(file_size)?;
        }

        Ok(file)
    }

    /// Writes a chunk of data to the part file at the given absolute offset
    pub fn write_chunk(&self, file: &mut File, offset: u64, data: &[u8]) -> Result<()> {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        Ok(())
    }

    /// Reads and computes the BLAKE3 hash for a 4 MiB block in the part file
    pub fn verify_block_hash(&self, file: &mut File, block_index: u32, block_size: u32, file_size: u64) -> Result<[u8; 32]> {
        let offset = block_index as u64 * block_size as u64;
        let remaining = file_size.saturating_sub(offset);
        let this_block_len = (block_size as u64).min(remaining) as usize;

        file.seek(SeekFrom::Start(offset))?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut read_total = 0;

        while read_total < this_block_len {
            let to_read = (this_block_len - read_total).min(buffer.len());
            let n = file.read(&mut buffer[..to_read])?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            read_total += n;
        }

        Ok(*hasher.finalize().as_bytes())
    }

    /// Computes whole-file BLAKE3 hash from the part file
    pub fn compute_whole_file_hash(&self, file: &mut File, file_size: u64) -> Result<[u8; 32]> {
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 128 * 1024];
        let mut total_read = 0;

        while total_read < file_size {
            let to_read = (file_size - total_read).min(buffer.len() as u64) as usize;
            let n = file.read(&mut buffer[..to_read])?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            total_read += n as u64;
        }

        Ok(*hasher.finalize().as_bytes())
    }

    /// Atomically renames part file to final name, adding (1), (2) on collision
    pub fn finalize_transfer(&self, sanitized_name: &str) -> Result<PathBuf> {
        let part_path = self.get_part_path(sanitized_name);
        let meta_path = self.get_meta_path(sanitized_name);

        let final_path = self.resolve_non_colliding_path(sanitized_name);
        fs::rename(&part_path, &final_path)?;

        // Remove sidecar
        if meta_path.exists() {
            let _ = fs::remove_file(meta_path);
        }

        Ok(final_path)
    }

    fn resolve_non_colliding_path(&self, name: &str) -> PathBuf {
        let target = self.base_dir.join(name);
        if !target.exists() {
            return target;
        }

        let path = Path::new(name);
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
        let ext = path.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();

        let mut counter = 1;
        loop {
            let candidate_name = format!("{stem} ({counter}){ext}");
            let candidate_path = self.base_dir.join(&candidate_name);
            if !candidate_path.exists() {
                return candidate_path;
            }
            counter += 1;
        }
    }
}
