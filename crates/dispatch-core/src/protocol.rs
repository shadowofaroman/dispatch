use serde::{Deserialize, Serialize};

pub const DEFAULT_UDP_PORT: u16 = 47600;
pub const PROTOCOL_VERSION: u16 = 1;
pub const BLOCK_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB
pub const CHUNK_SIZE: u32 = 32 * 1024;       // 32 KiB chunks inside 64 KiB Noise frames
pub const MAX_FRAME_PAYLOAD: usize = 65535 - 16; // 65519 bytes plaintext limit for Poly1305 MAC

pub type TransferId = [u8; 16];
pub type DeviceId = [u8; 16];

/// Discovery datagram packet over UDP
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryPacket {
    Announce {
        version: u16,
        device_id: DeviceId,
        device_name: String,
        tcp_port: u16,
    },
    Probe {
        version: u16,
        device_id: DeviceId,
    },
}

/// Encrypted application wire messages
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TransferMessage {
    /// Sender proposes a file transfer
    Offer {
        transfer_id: TransferId,
        file_name: String,
        file_size: u64,
        block_size: u32,
        total_blocks: u32,
    },

    /// Receiver accepts and provides already verified blocks
    Accept {
        transfer_id: TransferId,
        have_blocks: Vec<u32>,
    },

    /// Receiver rejects transfer
    Reject {
        transfer_id: TransferId,
        reason: RejectReason,
    },

    /// Slice of a 4 MiB block
    DataChunk {
        transfer_id: TransferId,
        block_index: u32,
        offset_in_block: u32,
        payload: Vec<u8>,
    },

    /// Block transfer completed; supplies the block's BLAKE3 hash
    BlockDone {
        transfer_id: TransferId,
        block_index: u32,
        block_hash: [u8; 32],
    },

    /// Whole-file transfer completed; supplies root BLAKE3 hash
    Complete {
        transfer_id: TransferId,
        whole_file_hash: [u8; 32],
    },

    /// Receiver confirms whole-file hash matched and file is saved
    Verified {
        transfer_id: TransferId,
    },

    /// Transfer cancellation
    Cancel {
        transfer_id: TransferId,
        reason: String,
    },

    /// Protocol or I/O error notification
    Error {
        transfer_id: Option<TransferId>,
        code: ErrorCode,
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    UserDeclined,
    InsufficientDiskSpace { available: u64, required: u64 },
    InvalidFileName,
    MaxConcurrentTransfersReached,
    PeerNotTrusted,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    ProtocolViolation,
    BlockIntegrityFailed,
    WholeFileIntegrityFailed,
    DiskIoError,
    Timeout,
}
