use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "dispatch",
    about = "Direct, encrypted PC-to-PC LAN file transfer over local networks",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Show device name, device ID, and public key fingerprint
    Id,

    /// Set a new human-readable device name
    Name {
        /// The new device name
        new_name: String,
    },

    /// List discovered LAN peers
    Peers {
        /// Continuously watch for peer announcements
        #[arg(short, long)]
        watch: bool,
    },

    /// Run receive mode (announces presence, accepts files)
    Listen {
        /// Directory where incoming files are saved (default: current directory)
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// TCP port to bind for file transfers (default: auto or 47601)
        #[arg(long, default_value_t = 47601)]
        port: u16,

        /// UDP discovery port (default: 47600)
        #[arg(long, default_value_t = 47600)]
        udp_port: u16,
    },

    /// Send a file to a discovered peer
    Send {
        /// Path to the file to send
        file: PathBuf,

        /// Peer name or device ID prefix
        peer: String,

        /// Direct IP:Port fallback if broadcast is blocked
        #[arg(long)]
        addr: Option<String>,

        /// UDP discovery port (default: 47600)
        #[arg(long, default_value_t = 47600)]
        udp_port: u16,
    },

    /// Manage trusted devices
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },

    /// Check network adapters, firewall settings, and port bindings
    Doctor {
        /// UDP discovery port to test (default: 47600)
        #[arg(long, default_value_t = 47600)]
        udp_port: u16,
    },
}

#[derive(Subcommand, Debug)]
pub enum TrustAction {
    /// List all trusted devices
    List,

    /// Remove a device from the trusted list by its ID
    Remove {
        /// Device ID hex or prefix
        id: String,
    },
}
