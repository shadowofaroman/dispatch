use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use network_interface::{NetworkInterface, NetworkInterfaceConfig, V4IfAddr};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use tracing::debug;

use crate::error::{DispatchError, Result};
use crate::identity::{format_device_id_compact, DeviceIdentity};
use crate::protocol::{DiscoveryPacket, DeviceId, PROTOCOL_VERSION};

#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub device_id: DeviceId,
    pub device_name: String,
    pub ip: IpAddr,
    pub tcp_port: u16,
    pub last_seen: Instant,
}

pub struct DiscoveryEngine {
    socket: Arc<UdpSocket>,
    peers: Arc<Mutex<HashMap<String, DiscoveredPeer>>>,
    identity: Arc<DeviceIdentity>,
    tcp_port: u16,
    udp_port: u16,
    stale_timeout: Duration,
}

impl DiscoveryEngine {
    pub async fn new(
        identity: Arc<DeviceIdentity>,
        tcp_port: u16,
        udp_port: u16,
    ) -> Result<Self> {
        let sock2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock2.set_broadcast(true)?;
        sock2.set_reuse_address(true)?;

        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        {
            let _ = sock2.set_reuse_port(true);
        }

        sock2.set_nonblocking(true)?;
        let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), udp_port);
        sock2.bind(&bind_addr.into())?;

        let std_sock: std::net::UdpSocket = sock2.into();
        let socket = Arc::new(UdpSocket::from_std(std_sock)?);

        Ok(Self {
            socket,
            peers: Arc::new(Mutex::new(HashMap::new())),
            identity,
            tcp_port,
            udp_port,
            stale_timeout: Duration::from_secs(12),
        })
    }

    /// Broadcasts an announce message on all active interfaces + 255.255.255.255
    pub async fn broadcast_announce(&self) -> Result<()> {
        let packet = DiscoveryPacket::Announce {
            version: PROTOCOL_VERSION,
            device_id: self.identity.device_id,
            device_name: self.identity.device_name.clone(),
            tcp_port: self.tcp_port,
        };
        let bytes = postcard::to_allocvec(&packet)
            .map_err(|e| DispatchError::Serialization(e.to_string()))?;

        self.send_to_all_interfaces(&bytes).await
    }

    /// Broadcasts a probe requesting immediate peer replies
    pub async fn broadcast_probe(&self) -> Result<()> {
        let packet = DiscoveryPacket::Probe {
            version: PROTOCOL_VERSION,
            device_id: self.identity.device_id,
        };
        let bytes = postcard::to_allocvec(&packet)
            .map_err(|e| DispatchError::Serialization(e.to_string()))?;

        self.send_to_all_interfaces(&bytes).await
    }

    async fn send_to_all_interfaces(&self, bytes: &[u8]) -> Result<()> {
        let mut targets = Vec::new();
        // Global broadcast
        targets.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), self.udp_port));

        // Enumerate active network interfaces
        if let Ok(interfaces) = NetworkInterface::show() {
            for iface in interfaces {
                for addr in iface.addr {
                    if let network_interface::Addr::V4(V4IfAddr { ip, broadcast: Some(bcast), .. }) = addr {
                        if !ip.is_loopback() {
                            targets.push(SocketAddr::new(IpAddr::V4(bcast), self.udp_port));
                        }
                    }
                }
            }
        }

        // De-duplicate targets
        targets.sort();
        targets.dedup();

        for target in targets {
            let _ = self.socket.send_to(bytes, target).await;
        }

        Ok(())
    }

    /// Runs the receive loop handling incoming packets, unicast replies, and peer table pruning
    pub async fn run_receiver(&self, mut stop_rx: broadcast::Receiver<()>) {
        let mut buf = [0u8; 2048];

        loop {
            tokio::select! {
                _ = stop_rx.recv() => {
                    break;
                }
                res = self.socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, peer_addr)) => {
                            if let Ok(packet) = postcard::from_bytes::<DiscoveryPacket>(&buf[..len]) {
                                self.handle_packet(packet, peer_addr).await;
                            }
                        }
                        Err(e) => {
                            debug!("UDP discovery receive error: {e}");
                        }
                    }
                }
            }
        }
    }

    async fn handle_packet(&self, packet: DiscoveryPacket, peer_addr: SocketAddr) {
        match packet {
            DiscoveryPacket::Announce { version, device_id, device_name, tcp_port } => {
                if version != PROTOCOL_VERSION || device_id == self.identity.device_id {
                    return;
                }

                let id_hex = format_device_id_compact(&device_id);
                let peer = DiscoveredPeer {
                    device_id,
                    device_name,
                    ip: peer_addr.ip(),
                    tcp_port,
                    last_seen: Instant::now(),
                };

                let mut lock = self.peers.lock().await;
                lock.insert(id_hex, peer);
            }
            DiscoveryPacket::Probe { version, device_id } => {
                if version != PROTOCOL_VERSION || device_id == self.identity.device_id {
                    return;
                }

                // Send unicast announce reply
                let reply = DiscoveryPacket::Announce {
                    version: PROTOCOL_VERSION,
                    device_id: self.identity.device_id,
                    device_name: self.identity.device_name.clone(),
                    tcp_port: self.tcp_port,
                };

                if let Ok(bytes) = postcard::to_allocvec(&reply) {
                    let _ = self.socket.send_to(&bytes, peer_addr).await;
                }
            }
        }
    }

    /// Gets all active (non-stale) peers
    pub async fn get_peers(&self) -> Vec<DiscoveredPeer> {
        let mut lock = self.peers.lock().await;
        let now = Instant::now();
        let timeout = self.stale_timeout;

        lock.retain(|_, peer| now.duration_since(peer.last_seen) < timeout);
        lock.values().cloned().collect()
    }

    /// Finds a peer by exact/prefix name or device ID prefix
    pub async fn find_peer(&self, query: &str) -> Option<DiscoveredPeer> {
        let peers = self.get_peers().await;
        let query_lower = query.to_lowercase();

        // 1. Exact name match
        for peer in &peers {
            if peer.device_name.to_lowercase() == query_lower {
                return Some(peer.clone());
            }
        }

        // 2. Exact or prefix device ID match
        for peer in &peers {
            let id_compact = format_device_id_compact(&peer.device_id);
            if id_compact.starts_with(&query_lower) {
                return Some(peer.clone());
            }
        }

        // 3. Name contains query
        for peer in &peers {
            if peer.device_name.to_lowercase().contains(&query_lower) {
                return Some(peer.clone());
            }
        }

        None
    }
}
