use clap::Parser;
use console::style;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

mod args;
mod doctor;
mod progress;

use args::{Cli, Commands, TrustAction};
use dispatch_core::{
    bind_listener, compute_device_id, configure_high_throughput_socket,
    format_device_id_compact, format_device_id_grouped,
    DeviceIdentity, DiscoveryEngine, SecureChannel, StorageManager,
    TransferEngine, TrustStatus,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Id => {
            let identity = DeviceIdentity::load_or_generate()?;
            println!("{}", style("=== Dispatch Device Identity ===").bold().cyan());
            println!("  Device Name: {}", style(&identity.device_name).bold().green());
            println!(
                "  Device ID:   {}",
                style(format_device_id_grouped(&identity.device_id)).bold().yellow()
            );
            println!(
                "  Public Key:  {} (Curve25519)",
                hex::encode(&identity.public_key)
            );
            println!("  Config Dir:  {}", identity.config_dir.display());
        }

        Commands::Name { new_name } => {
            let mut identity = DeviceIdentity::load_or_generate()?;
            identity.set_name(new_name.clone())?;
            println!(
                "{} Device name updated to: {}",
                style("✓").green().bold(),
                style(new_name).bold()
            );
        }

        Commands::Peers { watch } => {
            let identity = Arc::new(DeviceIdentity::load_or_generate()?);
            let engine = Arc::new(DiscoveryEngine::new(identity, 47601, 47600).await?);
            let (stop_tx, stop_rx) = broadcast::channel(1);

            let eng_recv = engine.clone();
            let recv_handle = tokio::spawn(async move {
                eng_recv.run_receiver(stop_rx).await;
            });

            // Initial probe
            let _ = engine.broadcast_probe().await;

            if !watch {
                print!("Scanning local network for Dispatch peers... ");
                io::stdout().flush()?;
                tokio::time::sleep(Duration::from_millis(2200)).await;

                let peers = engine.get_peers().await;
                let _ = stop_tx.send(());
                let _ = recv_handle.await;

                println!();
                if peers.is_empty() {
                    println!("{}", style("No peers discovered on local network.").yellow());
                    println!("Tip: Make sure the other PC is running 'dispatch listen' on the same network.");
                } else {
                    println!("{:<20} {:<24} {:<18} STATUS", "PEER NAME", "DEVICE ID", "ADDRESS");
                    println!("{:-<70}", "");
                    for p in peers {
                        let id_short = format!("{:.16}...", format_device_id_grouped(&p.device_id));
                        let addr = format!("{}:{}", p.ip, p.tcp_port);
                        println!(
                            "{:<20} {:<24} {:<18} {}",
                            style(&p.device_name).bold(),
                            id_short,
                            addr,
                            style("active").green()
                        );
                    }
                }
            } else {
                println!("{}", style("Watching for LAN peers (Ctrl+C to quit)...").cyan());
                loop {
                    let _ = engine.broadcast_probe().await;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let peers = engine.get_peers().await;

                    // Clear line / display
                    print!("\x1B[2J\x1B[1;1H");
                    println!("{}", style("=== Active Dispatch LAN Peers (Live) ===").bold().cyan());
                    println!("{:<20} {:<24} {:<18} STATUS", "PEER NAME", "DEVICE ID", "ADDRESS");
                    println!("{:-<70}", "");
                    for p in peers {
                        let id_short = format!("{:.16}...", format_device_id_grouped(&p.device_id));
                        let addr = format!("{}:{}", p.ip, p.tcp_port);
                        println!(
                            "{:<20} {:<24} {:<18} {}",
                            style(&p.device_name).bold(),
                            id_short,
                            addr,
                            style("active").green()
                        );
                    }
                }
            }
        }

        Commands::Listen { dir, port, udp_port } => {
            let target_dir = dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let storage = StorageManager::new(&target_dir)?;

            let mut identity = DeviceIdentity::load_or_generate()?;
            let listener = bind_listener(port).await?;
            let actual_port = listener.local_addr()?.port();

            println!("{}", style("=== Dispatch Receiver Active ===").bold().cyan());
            println!("  Device Name:   {}", style(&identity.device_name).green().bold());
            println!("  Device ID:     {}", style(format_device_id_grouped(&identity.device_id)).yellow());
            println!("  Receiving to:  {}", target_dir.display());
            println!("  TCP Listening: 0.0.0.0:{}", actual_port);
            println!("  UDP Discovery: 0.0.0.0:{}", udp_port);
            println!();

            let id_arc = Arc::new(identity);
            let discovery = Arc::new(DiscoveryEngine::new(id_arc.clone(), actual_port, udp_port).await?);
            let (stop_tx, stop_rx) = broadcast::channel(1);

            let disc_recv = discovery.clone();
            tokio::spawn(async move {
                disc_recv.run_receiver(stop_rx).await;
            });

            // Periodic discovery announce in background
            let disc_ann = discovery.clone();
            tokio::spawn(async move {
                loop {
                    let _ = disc_ann.broadcast_announce().await;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            });

            println!("{}", style("[*] Ready for incoming transfers. Awaiting sender connection...").dim());

            loop {
                let (stream, peer_addr) = listener.accept().await?;
                configure_high_throughput_socket(&stream)?;

                println!("\n[*] Incoming connection from {}", style(peer_addr).bold());

                let mut channel = match SecureChannel::accept_responder(stream, &id_arc).await {
                    Ok(ch) => ch,
                    Err(e) => {
                        eprintln!("{} Handshake failed: {e}", style("✗").red());
                        continue;
                    }
                };

                let remote_id_hex = format_device_id_compact(&channel.remote_device_id);
                let remote_id_grouped = format_device_id_grouped(&channel.remote_device_id);
                let sas_code = channel.verification_code.clone();

                // Check trust
                let mut local_id = DeviceIdentity::load_or_generate()?;
                let trust_status = local_id.check_key_trust(&channel.remote_static_key);

                match trust_status {
                    TrustStatus::Trusted { name, .. } => {
                        println!(
                            "  ✓ Authenticated trusted sender: {} ({})",
                            style(name).green().bold(),
                            remote_id_grouped
                        );
                    }
                    TrustStatus::KeyMismatch { stored_name, .. } => {
                        eprintln!(
                            "\n{} SENDER KEY MISMATCH! Possible Man-In-The-Middle attack!\nStored key for '{}' ({}) does not match current remote key.",
                            style("CRITICAL ALERT:").red().bold(),
                            stored_name,
                            remote_id_grouped
                        );
                        continue;
                    }
                    TrustStatus::Unknown { .. } => {
                        println!("\n{}", style("=== New Unknown Device Contact ===").yellow().bold());
                        println!("  Sender Device ID: {}", style(&remote_id_grouped).bold());
                        println!(
                            "  Verification SAS Code: {}  {}",
                            style(format!("[ {} ]", format_sas_display(&sas_code))).bold().cyan(),
                            style("(Check sender's screen)").dim()
                        );
                        print!("  Accept and trust this device? (y/N): ");
                        io::stdout().flush()?;

                        let mut answer = String::new();
                        io::stdin().read_line(&mut answer)?;
                        if !answer.trim().eq_ignore_ascii_case("y") {
                            println!("{}", style("Transfer rejected by user.").yellow());
                            continue;
                        }

                        let _ = local_id.trust_device(
                            remote_id_hex,
                            &channel.remote_static_key,
                            format!("device-{}", &remote_id_grouped[..9]),
                        );
                        println!("  ✓ Device added to trusted devices list.");
                    }
                }

                // Run transfer receive
                let (prog_tx, prog_rx) = mpsc::unbounded_channel();
                let prog_handle = tokio::spawn(progress::handle_progress_stream(prog_rx));

                let result = TransferEngine::receive_file(
                    &mut channel,
                    &storage,
                    |file_name, size| {
                        println!(
                            "\n[?] Accept incoming file '{}' ({:.2} MB)? (y/N): ",
                            style(file_name).bold(),
                            size as f64 / (1024.0 * 1024.0)
                        );
                        let _ = io::stdout().flush();
                        let mut ans = String::new();
                        let _ = io::stdin().read_line(&mut ans);
                        ans.trim().eq_ignore_ascii_case("y")
                    },
                    Some(prog_tx),
                )
                .await;

                let _ = prog_handle.await;

                match result {
                    Ok(saved_path) => {
                        println!(
                            "{} File saved to: {}",
                            style("✓").green().bold(),
                            style(saved_path.display()).bold()
                        );
                    }
                    Err(e) => {
                        eprintln!("{} Transfer error: {e}", style("✗").red());
                    }
                }
            }
        }

        Commands::Send { file, peer, addr, udp_port } => {
            if !file.exists() {
                eprintln!("{} File not found: {}", style("✗").red(), file.display());
                std::process::exit(1);
            }

            let mut identity = DeviceIdentity::load_or_generate()?;
            let id_arc = Arc::new(identity);

            // Resolve target peer address
            let target_addr: SocketAddr = if let Some(direct_addr) = addr {
                direct_addr.parse().map_err(|e| {
                    format!("Invalid address '{direct_addr}': {e}. Expected <ip:port>")
                })?
            } else {
                let discovery = Arc::new(DiscoveryEngine::new(id_arc.clone(), 0, udp_port).await?);
                let (stop_tx, stop_rx) = broadcast::channel(1);

                let disc_recv = discovery.clone();
                let recv_handle = tokio::spawn(async move {
                    disc_recv.run_receiver(stop_rx).await;
                });

                println!("Probing LAN for peer '{}'...", style(&peer).bold());
                let _ = discovery.broadcast_probe().await;
                tokio::time::sleep(Duration::from_millis(2000)).await;

                let found = discovery.find_peer(&peer).await;
                let _ = stop_tx.send(());
                let _ = recv_handle.await;

                match found {
                    Some(p) => {
                        println!(
                            "  ✓ Discovered peer '{}' at {}:{}",
                            style(&p.device_name).bold(),
                            p.ip,
                            p.tcp_port
                        );
                        SocketAddr::new(p.ip, p.tcp_port)
                    }
                    None => {
                        eprintln!(
                            "{} Peer '{}' not found on local network.",
                            style("✗").red(),
                            peer
                        );
                        eprintln!("  - Ensure both devices are on the same LAN / connected via cable.");
                        eprintln!("  - Ensure 'dispatch listen' is active on the receiver.");
                        eprintln!("  - Or specify direct address with: dispatch send <file> <peer> --addr <ip:port>");
                        std::process::exit(1);
                    }
                }
            };

            println!("Connecting to {}...", style(target_addr).cyan());
            let stream = TcpStream::connect(target_addr).await?;
            configure_high_throughput_socket(&stream)?;

            let mut channel = SecureChannel::connect_initiator(stream, &id_arc).await?;

            let remote_id_hex = format_device_id_compact(&channel.remote_device_id);
            let remote_id_grouped = format_device_id_grouped(&channel.remote_device_id);
            let sas_code = channel.verification_code.clone();

            // Check trust on receiver
            let mut local_id = DeviceIdentity::load_or_generate()?;
            let trust_status = local_id.check_key_trust(&channel.remote_static_key);

            match trust_status {
                TrustStatus::Trusted { name, .. } => {
                    println!("  ✓ Connected to trusted peer: {}", style(name).green().bold());
                }
                TrustStatus::KeyMismatch { stored_name, .. } => {
                    eprintln!(
                        "\n{} RECEIVER KEY MISMATCH! Possible Man-In-The-Middle attack!\nStored key for '{}' ({}) does not match current remote key.",
                        style("CRITICAL ALERT:").red().bold(),
                        stored_name,
                        remote_id_grouped
                    );
                    std::process::exit(1);
                }
                TrustStatus::Unknown { .. } => {
                    println!("\n{}", style("=== First Contact with Receiver ===").yellow().bold());
                    println!("  Receiver Device ID: {}", style(&remote_id_grouped).bold());
                    println!(
                        "  Verification SAS Code: {}  {}",
                        style(format!("[ {} ]", format_sas_display(&sas_code))).bold().cyan(),
                        style("(Compare with receiver's screen)").dim()
                    );
                    print!("  Confirm and trust this receiver? (y/N): ");
                    io::stdout().flush()?;

                    let mut answer = String::new();
                    io::stdin().read_line(&mut answer)?;
                    if !answer.trim().eq_ignore_ascii_case("y") {
                        println!("{}", style("Transfer aborted by user.").yellow());
                        std::process::exit(1);
                    }

                    let _ = local_id.trust_device(
                        remote_id_hex,
                        &channel.remote_static_key,
                        peer.clone(),
                    );
                    println!("  ✓ Receiver saved to trusted devices.");
                }
            }

            let (prog_tx, prog_rx) = mpsc::unbounded_channel();
            let prog_handle = tokio::spawn(progress::handle_progress_stream(prog_rx));

            let result = TransferEngine::send_file(&mut channel, &file, Some(prog_tx)).await;
            let _ = prog_handle.await;

            match result {
                Ok(_) => {
                    println!("{} File send successful!", style("✓").green().bold());
                }
                Err(e) => {
                    eprintln!("{} Send failed: {e}", style("✗").red());
                    std::process::exit(1);
                }
            }
        }

        Commands::Trust { action } => match action {
            TrustAction::List => {
                let identity = DeviceIdentity::load_or_generate()?;
                let devices = &identity.trust_store.devices;
                println!("{}", style("=== Trusted Devices List ===").bold().cyan());
                if devices.is_empty() {
                    println!("  No trusted devices registered yet.");
                } else {
                    println!("{:<24} {:<36} FIRST SEEN", "NAME", "DEVICE ID");
                    println!("{:-<75}", "");
                    for (id, entry) in devices {
                        println!("{:<24} {:<36} {}s ago", entry.name, id, entry.first_seen_secs);
                    }
                }
            }
            TrustAction::Remove { id } => {
                let mut identity = DeviceIdentity::load_or_generate()?;
                if identity.remove_trust(&id)? {
                    println!("{} Removed device '{}' from trusted list.", style("✓").green(), id);
                } else {
                    println!("{} Device '{}' was not found in trusted list.", style("!").yellow(), id);
                }
            }
        },

        Commands::Doctor { udp_port } => {
            doctor::run_doctor(udp_port).await;
        }
    }

    Ok(())
}

fn format_sas_display(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}
