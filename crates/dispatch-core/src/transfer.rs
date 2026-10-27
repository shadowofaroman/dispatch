use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::sync::mpsc;

use crate::channel::SecureChannel;
use crate::error::{DispatchError, Result};
use crate::protocol::{
    ErrorCode, RejectReason, TransferId, TransferMessage, BLOCK_SIZE, CHUNK_SIZE,
};
use crate::storage::{SidecarMetadata, StorageManager};

#[derive(Clone, Debug)]
pub enum TransferProgress {
    Started {
        transfer_id: TransferId,
        file_name: String,
        file_size: u64,
        total_blocks: u32,
    },
    Progress {
        transfer_id: TransferId,
        transferred_bytes: u64,
        total_bytes: u64,
        bytes_per_sec: f64,
    },
    BlockDone {
        transfer_id: TransferId,
        block_index: u32,
        total_blocks: u32,
    },
    Completed {
        transfer_id: TransferId,
        file_name: String,
        file_size: u64,
        duration_secs: f64,
        average_speed_mbps: f64,
    },
}

pub struct TransferEngine;

impl TransferEngine {
    /// Sends a file to the connected peer over the secure channel
    pub async fn send_file<P: AsRef<Path>>(
        channel: &mut SecureChannel,
        file_path: P,
        progress_tx: Option<mpsc::UnboundedSender<TransferProgress>>,
    ) -> Result<()> {
        let path = file_path.as_ref();
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len();

        let raw_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| DispatchError::InvalidFileName("Invalid source path".into()))?;

        let total_blocks = if file_size == 0 {
            1
        } else {
            ((file_size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64) as u32
        };

        let mut transfer_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut transfer_id);

        // 1. Send Offer
        channel
            .send_message(&TransferMessage::Offer {
                transfer_id,
                file_name: raw_name.to_string(),
                file_size,
                block_size: BLOCK_SIZE,
                total_blocks,
            })
            .await?;

        // 2. Receive Accept or Reject
        let response = channel.recv_message().await?;
        let have_blocks_set: HashSet<u32> = match response {
            TransferMessage::Accept {
                transfer_id: resp_id,
                have_blocks,
            } => {
                if resp_id != transfer_id {
                    return Err(DispatchError::ProtocolViolation("Transfer ID mismatch".into()));
                }
                have_blocks.into_iter().collect()
            }
            TransferMessage::Reject { reason, .. } => {
                return Err(DispatchError::TransferRejected(reason));
            }
            other => {
                return Err(DispatchError::ProtocolViolation(format!(
                    "Expected Accept or Reject, received {other:?}"
                )));
            }
        };

        if let Some(ref tx) = progress_tx {
            let _ = tx.send(TransferProgress::Started {
                transfer_id,
                file_name: raw_name.to_string(),
                file_size,
                total_blocks,
            });
        }

        let start_time = Instant::now();
        let mut transferred_bytes = 0u64;
        let mut last_progress_report = Instant::now();
        let mut whole_hasher = blake3::Hasher::new();

        // 3. Stream blocks
        let mut chunk_buffer = vec![0u8; CHUNK_SIZE as usize];

        for block_idx in 0..total_blocks {
            let block_offset = block_idx as u64 * BLOCK_SIZE as u64;
            let block_len = if block_offset >= file_size {
                0
            } else {
                (file_size - block_offset).min(BLOCK_SIZE as u64) as usize
            };

            // If receiver already has this block verified, skip sending data
            if have_blocks_set.contains(&block_idx) {
                // Read from file only to update whole_hasher
                file.seek(SeekFrom::Start(block_offset))?;
                let mut remaining_to_hash = block_len;
                while remaining_to_hash > 0 {
                    let to_read = remaining_to_hash.min(chunk_buffer.len());
                    let n = file.read(&mut chunk_buffer[..to_read])?;
                    if n == 0 {
                        break;
                    }
                    whole_hasher.update(&chunk_buffer[..n]);
                    remaining_to_hash -= n;
                }
                transferred_bytes += block_len as u64;
                continue;
            }

            file.seek(SeekFrom::Start(block_offset))?;
            let mut block_hasher = blake3::Hasher::new();
            let mut block_bytes_read = 0usize;

            while block_bytes_read < block_len {
                let to_read = (block_len - block_bytes_read).min(CHUNK_SIZE as usize);
                let n = file.read(&mut chunk_buffer[..to_read])?;
                if n == 0 {
                    break;
                }

                let slice = &chunk_buffer[..n];
                block_hasher.update(slice);
                whole_hasher.update(slice);

                channel
                    .send_message(&TransferMessage::DataChunk {
                        transfer_id,
                        block_index: block_idx,
                        offset_in_block: block_bytes_read as u32,
                        payload: slice.to_vec(),
                    })
                    .await?;

                block_bytes_read += n;
                transferred_bytes += n as u64;

                let now = Instant::now();
                if now.duration_since(last_progress_report).as_millis() >= 150 {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let bps = if elapsed > 0.0 {
                        transferred_bytes as f64 / elapsed
                    } else {
                        0.0
                    };

                    if let Some(ref tx) = progress_tx {
                        let _ = tx.send(TransferProgress::Progress {
                            transfer_id,
                            transferred_bytes,
                            total_bytes: file_size,
                            bytes_per_sec: bps,
                        });
                    }
                    last_progress_report = now;
                }
            }

            // Send BlockDone
            let block_hash = *block_hasher.finalize().as_bytes();
            channel
                .send_message(&TransferMessage::BlockDone {
                    transfer_id,
                    block_index: block_idx,
                    block_hash,
                })
                .await?;

            if let Some(ref tx) = progress_tx {
                let _ = tx.send(TransferProgress::BlockDone {
                    transfer_id,
                    block_index: block_idx,
                    total_blocks,
                });
            }
        }

        // 4. Send Complete with full-file BLAKE3 hash
        let whole_file_hash = *whole_hasher.finalize().as_bytes();
        channel
            .send_message(&TransferMessage::Complete {
                transfer_id,
                whole_file_hash,
            })
            .await?;

        // 5. Await Verified confirmation from receiver
        let final_resp = channel.recv_message().await?;
        match final_resp {
            TransferMessage::Verified {
                transfer_id: resp_id,
            } => {
                if resp_id != transfer_id {
                    return Err(DispatchError::ProtocolViolation("Transfer ID mismatch in Verified".into()));
                }
            }
            TransferMessage::Error { code, message, .. } => {
                return Err(DispatchError::ProtocolViolation(format!(
                    "Peer error {:?}: {}",
                    code, message
                )));
            }
            other => {
                return Err(DispatchError::ProtocolViolation(format!(
                    "Expected Verified, received {other:?}"
                )));
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let speed_mbps = if elapsed > 0.0 {
            (file_size as f64 / (1024.0 * 1024.0)) / elapsed
        } else {
            0.0
        };

        if let Some(ref tx) = progress_tx {
            let _ = tx.send(TransferProgress::Completed {
                transfer_id,
                file_name: raw_name.to_string(),
                file_size,
                duration_secs: elapsed,
                average_speed_mbps: speed_mbps,
            });
        }

        Ok(())
    }

    /// Receives a file from the connected peer over the secure channel
    pub async fn receive_file<F>(
        channel: &mut SecureChannel,
        storage: &StorageManager,
        confirm_fn: F,
        progress_tx: Option<mpsc::UnboundedSender<TransferProgress>>,
    ) -> Result<PathBuf>
    where
        F: FnOnce(&str, u64) -> bool,
    {
        // 1. Receive Offer
        let offer = channel.recv_message().await?;
        let (transfer_id, raw_name, file_size, block_size, total_blocks) = match offer {
            TransferMessage::Offer {
                transfer_id,
                file_name,
                file_size,
                block_size,
                total_blocks,
            } => (transfer_id, file_name, file_size, block_size, total_blocks),
            other => {
                return Err(DispatchError::ProtocolViolation(format!(
                    "Expected Offer, received {other:?}"
                )));
            }
        };

        // 2. Sanitize file name
        let sanitized_name = match storage.sanitize_file_name(&raw_name) {
            Ok(name) => name,
            Err(e) => {
                let _ = channel
                    .send_message(&TransferMessage::Reject {
                        transfer_id,
                        reason: RejectReason::InvalidFileName,
                    })
                    .await;
                return Err(e);
            }
        };

        // 3. User interactive confirmation callback
        if !confirm_fn(&sanitized_name, file_size) {
            let _ = channel
                .send_message(&TransferMessage::Reject {
                    transfer_id,
                    reason: RejectReason::UserDeclined,
                })
                .await;
            return Err(DispatchError::Cancelled("User declined transfer".into()));
        }

        // 4. Verify free disk space
        if let Err(e) = storage.check_free_space(file_size) {
            if let DispatchError::InsufficientDiskSpace { available, required } = e {
                let _ = channel
                    .send_message(&TransferMessage::Reject {
                        transfer_id,
                        reason: RejectReason::InsufficientDiskSpace {
                            available,
                            required,
                        },
                    })
                    .await;
            }
            return Err(e);
        }

        // 5. Check resume sidecar
        let mut sidecar = storage
            .load_sidecar(&sanitized_name, &transfer_id, file_size)
            .unwrap_or_else(|| SidecarMetadata {
                transfer_id,
                file_name: sanitized_name.clone(),
                file_size,
                block_size,
                verified_blocks: HashMap::new(),
            });

        let have_blocks: Vec<u32> = sidecar.verified_blocks.keys().cloned().collect();

        // 6. Send Accept
        channel
            .send_message(&TransferMessage::Accept {
                transfer_id,
                have_blocks,
            })
            .await?;

        // Open/pre-allocate part file
        let mut part_file = storage.open_part_file(&sanitized_name, file_size)?;

        if let Some(ref tx) = progress_tx {
            let _ = tx.send(TransferProgress::Started {
                transfer_id,
                file_name: sanitized_name.clone(),
                file_size,
                total_blocks,
            });
        }

        let start_time = Instant::now();
        let mut received_bytes = sidecar.verified_blocks.len() as u64 * block_size as u64;
        let mut last_progress_report = Instant::now();

        // 7. Receive data frames until Complete
        loop {
            let msg = channel.recv_message().await?;
            match msg {
                TransferMessage::DataChunk {
                    transfer_id: msg_id,
                    block_index,
                    offset_in_block,
                    payload,
                } => {
                    if msg_id != transfer_id {
                        return Err(DispatchError::ProtocolViolation("Transfer ID mismatch".into()));
                    }

                    let abs_offset = block_index as u64 * block_size as u64 + offset_in_block as u64;
                    storage.write_chunk(&mut part_file, abs_offset, &payload)?;
                    received_bytes += payload.len() as u64;

                    let now = Instant::now();
                    if now.duration_since(last_progress_report).as_millis() >= 150 {
                        let elapsed = start_time.elapsed().as_secs_f64();
                        let bps = if elapsed > 0.0 {
                            received_bytes as f64 / elapsed
                        } else {
                            0.0
                        };

                        if let Some(ref tx) = progress_tx {
                            let _ = tx.send(TransferProgress::Progress {
                                transfer_id,
                                transferred_bytes: received_bytes.min(file_size),
                                total_bytes: file_size,
                                bytes_per_sec: bps,
                            });
                        }
                        last_progress_report = now;
                    }
                }
                TransferMessage::BlockDone {
                    transfer_id: msg_id,
                    block_index,
                    block_hash,
                } => {
                    if msg_id != transfer_id {
                        return Err(DispatchError::ProtocolViolation("Transfer ID mismatch".into()));
                    }

                    let computed_hash = storage.verify_block_hash(
                        &mut part_file,
                        block_index,
                        block_size,
                        file_size,
                    )?;

                    if computed_hash != block_hash {
                        let _ = channel
                            .send_message(&TransferMessage::Error {
                                transfer_id: Some(transfer_id),
                                code: ErrorCode::BlockIntegrityFailed,
                                message: format!("Block {block_index} hash verification failed"),
                            })
                            .await;
                        return Err(DispatchError::BlockIntegrityFailed { block_index });
                    }

                    sidecar.verified_blocks.insert(block_index, block_hash);
                    let _ = storage.save_sidecar(&sanitized_name, &sidecar);

                    if let Some(ref tx) = progress_tx {
                        let _ = tx.send(TransferProgress::BlockDone {
                            transfer_id,
                            block_index,
                            total_blocks,
                        });
                    }
                }
                TransferMessage::Complete {
                    transfer_id: msg_id,
                    whole_file_hash,
                } => {
                    if msg_id != transfer_id {
                        return Err(DispatchError::ProtocolViolation("Transfer ID mismatch".into()));
                    }

                    // Verify whole-file hash
                    let computed_file_hash = storage.compute_whole_file_hash(&mut part_file, file_size)?;
                    if computed_file_hash != whole_file_hash {
                        let _ = channel
                            .send_message(&TransferMessage::Error {
                                transfer_id: Some(transfer_id),
                                code: ErrorCode::WholeFileIntegrityFailed,
                                message: "Whole-file hash mismatch".into(),
                            })
                            .await;
                        return Err(DispatchError::WholeFileIntegrityFailed);
                    }

                    // Atomic finalize
                    let final_path = storage.finalize_transfer(&sanitized_name)?;

                    // Send Verified
                    channel
                        .send_message(&TransferMessage::Verified { transfer_id })
                        .await?;

                    let elapsed = start_time.elapsed().as_secs_f64();
                    let speed_mbps = if elapsed > 0.0 {
                        (file_size as f64 / (1024.0 * 1024.0)) / elapsed
                    } else {
                        0.0
                    };

                    if let Some(ref tx) = progress_tx {
                        let _ = tx.send(TransferProgress::Completed {
                            transfer_id,
                            file_name: sanitized_name,
                            file_size,
                            duration_secs: elapsed,
                            average_speed_mbps: speed_mbps,
                        });
                    }

                    return Ok(final_path);
                }
                TransferMessage::Cancel { reason, .. } => {
                    return Err(DispatchError::Cancelled(reason));
                }
                TransferMessage::Error { code, message, .. } => {
                    return Err(DispatchError::ProtocolViolation(format!(
                        "Sender reported error {:?}: {}",
                        code, message
                    )));
                }
                other => {
                    return Err(DispatchError::ProtocolViolation(format!(
                        "Unexpected message during transfer: {other:?}"
                    )));
                }
            }
        }
    }
}
