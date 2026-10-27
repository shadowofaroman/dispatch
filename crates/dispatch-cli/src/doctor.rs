use console::style;
use network_interface::{NetworkInterface, NetworkInterfaceConfig, V4IfAddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

use dispatch_core::{
    identity::DeviceIdentity,
    discovery::DiscoveryEngine,
    DEFAULT_UDP_PORT,
};

pub async fn run_doctor(udp_port: u16) {
    println!("{}", style("=== Dispatch LAN Diagnostics (Doctor) ===").bold().cyan());
    println!();

    // 1. Device identity & config paths
    println!("{}", style("[1/4] Checking Identity & Storage:").bold());
    match DeviceIdentity::load_or_generate() {
        Ok(id) => {
            println!("  ✓ Identity loaded: {}", style(&id.device_name).green().bold());
            println!("  ✓ Config directory: {}", id.config_dir.display());
            println!("  ✓ Trusted devices stored: {}", id.trust_store.devices.len());
        }
        Err(e) => {
            println!("  ✗ Failed to load identity: {}", style(e).red());
        }
    }
    println!();

    // 2. Active network interfaces
    println!("{}", style("[2/4] Enumerating Network Interfaces:").bold());
    match NetworkInterface::show() {
        Ok(interfaces) => {
            let mut active_count = 0;
            for iface in interfaces {
                for addr in iface.addr {
                    if let network_interface::Addr::V4(V4IfAddr { ip, broadcast, netmask }) = addr {
                        let is_loopback = ip.is_loopback();
                        let is_link_local = ip.octets()[0] == 169 && ip.octets()[1] == 254;
                        active_count += 1;

                        let tag = if is_loopback {
                            style("(loopback)").dim()
                        } else if is_link_local {
                            style("(link-local / direct cable)").yellow()
                        } else {
                            style("(LAN)").green()
                        };

                        println!(
                            "  • Interface: {} -> IP: {} Netmask: {:?} Broadcast: {:?} {}",
                            style(&iface.name).cyan(),
                            style(ip).bold(),
                            netmask,
                            broadcast,
                            tag
                        );
                    }
                }
            }

            if active_count == 0 {
                println!("  {} No active IPv4 network interfaces found!", style("WARNING:").yellow().bold());
            }
        }
        Err(e) => {
            println!("  ✗ Failed to inspect network interfaces: {}", style(e).red());
        }
    }
    println!();

    // 3. Port binding tests
    println!("{}", style("[3/4] Testing Port Bindings:").bold());
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), udp_port);
    match UdpSocket::bind(bind_addr).await {
        Ok(_) => {
            println!("  ✓ UDP discovery port {} is AVAILABLE and bound successfully.", udp_port);
        }
        Err(e) => {
            println!(
                "  ✗ UDP discovery port {} BIND FAILED: {}. Another Dispatch instance may be running.",
                udp_port, style(e).red()
            );
        }
    }

    match tokio::net::TcpListener::bind("0.0.0.0:0").await {
        Ok(listener) => {
            let local_port = listener.local_addr().unwrap().port();
            println!("  ✓ Dynamic TCP transfer socket binding OK (tested port {}).", local_port);
        }
        Err(e) => {
            println!("  ✗ TCP transfer socket binding FAILED: {}", style(e).red());
        }
    }
    println!();

    // 4. Peer discovery probe test
    println!("{}", style("[4/4] Sending Broadcast Probe for Peers:").bold());
    match DeviceIdentity::load_or_generate() {
        Ok(identity) => {
            let id_arc = Arc::new(identity);
            match DiscoveryEngine::new(id_arc, 47601, udp_port).await {
                Ok(engine) => {
                    let engine_arc = Arc::new(engine);
                    let (stop_tx, stop_rx) = broadcast::channel(1);

                    let eng_recv = engine_arc.clone();
                    let recv_handle = tokio::spawn(async move {
                        eng_recv.run_receiver(stop_rx).await;
                    });

                    // Broadcast probe
                    let _ = engine_arc.broadcast_probe().await;
                    print!("  Probing local subnet (waiting 2.5s)... ");
                    tokio::time::sleep(Duration::from_millis(2500)).await;

                    let peers = engine_arc.get_peers().await;
                    let _ = stop_tx.send(());
                    let _ = recv_handle.await;

                    if peers.is_empty() {
                        println!("{}", style("No peers responded.").yellow());
                        println!("    Note: This is normal if no other Dispatch instances are active on the LAN.");
                    } else {
                        println!("{}", style(format!("Found {} peer(s)!", peers.len())).green().bold());
                        for peer in peers {
                            println!(
                                "    - {} ({}) at {}:{}",
                                style(&peer.device_name).bold(),
                                hex::encode(&peer.device_id[..4]),
                                peer.ip,
                                peer.tcp_port
                            );
                        }
                    }
                }
                Err(e) => {
                    println!("  ✗ Could not initialize discovery probe: {}", style(e).red());
                }
            }
        }
        Err(_) => {}
    }

    println!();
    println!("{}", style("=== Platform & Firewall Guidance ===").bold().cyan());
    #[cfg(windows)]
    {
        println!("  • Windows Firewall: Ensure your connection profile is set to 'Private'.");
        println!("    If prompted by Windows Defender Firewall, check 'Private networks' to allow Dispatch.");
        println!("  • Direct PC-to-PC cable: Link-local 169.254.x.x addresses work automatically without a router.");
    }
    #[cfg(unix)]
    {
        println!("  • Linux/macOS: Socket reuse and directed broadcast configured across all active NICs.");
        println!("  • If iptables/ufw is active, ensure UDP {} and incoming TCP ports are permitted.", udp_port);
    }
    println!();
}
