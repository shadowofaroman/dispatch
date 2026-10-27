//! Dispatch Core
//! High-throughput encrypted PC-to-PC LAN file transfer library.
//!
//! Provides headless, async primitives with zero direct standard output:
//! - Curve25519 device identities and trust-on-first-use store
//! - Custom UDP broadcast peer discovery
//! - Noise_XX secure channels with 6-digit Short Authentication String (SAS)
//! - 4 MiB block pipelining with BLAKE3 verification and sidecar resume
//! - Path traversal prevention and Windows-safe storage

pub mod channel;
pub mod discovery;
pub mod error;
pub mod framing;
pub mod identity;
pub mod protocol;
pub mod storage;
pub mod transfer;

pub use channel::{compute_verification_code, SecureChannel};
pub use discovery::{DiscoveredPeer, DiscoveryEngine};
pub use error::{DispatchError, Result};
pub use identity::{
    compute_device_id, format_device_id_compact, format_device_id_grouped, DeviceIdentity,
    TrustStatus,
};
pub use protocol::{
    DeviceId, DiscoveryPacket, ErrorCode, RejectReason, TransferId, TransferMessage, BLOCK_SIZE,
    CHUNK_SIZE, DEFAULT_UDP_PORT, PROTOCOL_VERSION,
};
pub use storage::{SidecarMetadata, StorageManager};
pub use transfer::{TransferEngine, TransferProgress};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};

/// Configures high-performance socket options: TCP_NODELAY and 2 MiB send/receive buffers
pub fn configure_high_throughput_socket(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let sock2 = socket2::SockRef::from(stream);
        let buffer_size = 2 * 1024 * 1024; // 2 MiB
        let _ = sock2.set_recv_buffer_size(buffer_size);
        let _ = sock2.set_send_buffer_size(buffer_size);
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        let sock2 = socket2::SockRef::from(stream);
        let buffer_size = 2 * 1024 * 1024; // 2 MiB
        let _ = sock2.set_recv_buffer_size(buffer_size);
        let _ = sock2.set_send_buffer_size(buffer_size);
    }

    Ok(())
}

/// Binds a TCP listener on the requested port (or OS assigned if 0)
pub async fn bind_listener(port: u16) -> Result<TcpListener> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let listener = TcpListener::bind(addr).await?;
    Ok(listener)
}
