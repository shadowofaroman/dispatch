use thiserror::Error;

#[derive(Error, Debug)]
pub enum DispatchError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Framing error: message exceeds 65535 bytes or frame is corrupted: {0}")]
    Framing(String),

    #[error("Noise handshake error: {0}")]
    Handshake(String),

    #[error("Peer identity rejected: {0}")]
    PeerRejected(String),

    #[error("Peer key mismatch: possible Man-In-The-Middle attack! Expected key for device {device_id} differs from received key.")]
    KeyMismatch { device_id: String },

    #[error("Transfer rejected by receiver: {0:?}")]
    TransferRejected(crate::protocol::RejectReason),

    #[error("Insufficient free disk space: available {available} bytes, required {required} bytes")]
    InsufficientDiskSpace { available: u64, required: u64 },

    #[error("Invalid file name: {0}")]
    InvalidFileName(String),

    #[error("Integrity check failed for block {block_index}")]
    BlockIntegrityFailed { block_index: u32 },

    #[error("Whole-file integrity check failed: expected hash does not match computed hash")]
    WholeFileIntegrityFailed,

    #[error("Transfer cancelled: {0}")]
    Cancelled(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Config path error: {0}")]
    ConfigPath(String),

    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
}

pub type Result<T> = std::result::Result<T, DispatchError>;
