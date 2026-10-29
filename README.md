# Dispatch — PC-to-PC Encrypted File Transfer over LAN

Dispatch is a high-throughput, encrypted direct file transfer system designed to saturate local area network (LAN) connections (100+ MB/s over gigabit Ethernet) with **zero internet, zero cloud, zero accounts, zero DNS/NTP, and zero manual IP entry**.

Built with Rust, Tokio, the Noise Protocol Framework (`Noise_XX`), and BLAKE3.

---

## Architecture Overview

Dispatch is structured as a modular Cargo workspace:
- **`dispatch-core`**: A headless, pure async library crate with zero stdout printing. Provides device identity, custom UDP broadcast discovery, Noise_XX channel management, 6-digit SAS verification, and pipelined 4 MiB block streaming with sidecar resume.
- **`dispatch-cli`**: A thin CLI client providing intuitive user interactions, terminal multi-progress bars with live throughput (MB/s) and ETA, and network diagnostics (`dispatch doctor`).

```
┌────────────────────────────────────────────────────────┐
│                      dispatch-cli                      │
│      id | name | peers | listen | send | trust | doctor │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                     dispatch-core                      │
│ ┌─────────────────┐ ┌────────────────┐ ┌─────────────┐ │
│ │ Device Identity │ │ Discovery (UDP)│ │ Noise XX    │ │
│ │ Curve25519/TOFU │ │ All Interfaces │ │ SAS Code    │ │
│ └─────────────────┘ └────────────────┘ └─────────────┘ │
│ ┌─────────────────┐ ┌────────────────┐ ┌─────────────┐ │
│ │ 64 KiB Framing  │ │ 4 MiB Blocks   │ │ Storage/Meta│ │
│ │ Postcard Wire   │ │ BLAKE3 Streaming│ │ Resume Part │ │
│ └─────────────────┘ └────────────────┘ └─────────────┘ │
└────────────────────────────────────────────────────────┘
```

---

## Cryptographic Guarantees & Network Safety

1. **Mandatory Encryption:** All TCP payloads after the 3-way handshake are encrypted with ChaCha20-Poly1305 and authenticated with BLAKE2s. Plaintext mode does not exist.
2. **Mutual Authentication (Noise_XX):** Static Curve25519 public keys are mutually exchanged under ephemeral keys to protect device identities from passive eavesdroppers.
3. **Trust-on-First-Use (TOFU) & 6-Digit SAS Code:**
   On first contact with an unknown peer, both the sender and receiver calculate and display an identical 6-digit Short Authentication String derived from the Noise handshake hash $h$:
   $$\text{SAS} = (\text{BigEndianU32}(h[0..4]) \pmod{10^6})$$
   The user compares the 6 digits on both screens. Upon acceptance, the peer is added to the trusted devices list.
4. **Man-in-the-Middle (MitM) Prevention:** If a known device ID appears with a modified public key, Dispatch refuses the connection immediately with a critical alert.
5. **Path Traversal & Windows Reserved Name Safety:** Incoming file names are stripped of directory paths, null bytes, and parent references (`..`). Reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) are rejected across all platforms.
6. **Disk Space Safety:** The receiver inspects filesystem capacity via `fs2` before accepting transfers; offers exceeding free disk space are rejected.

---

## Build Instructions

### Prerequisites
- Rust stable toolchain (1.80+ recommended)
- `cargo` and C compiler (for platform crypto primitives)

### Linux / macOS
```bash
# Clone the repository
git clone https://github.com/shadowofaroman/dispatch.git
cd dispatch

# Build release binaries
cargo build --release

# The CLI binary is generated at:
./target/release/dispatch --help
```

### Windows (PowerShell / Command Prompt)
```powershell
# Build release binaries
cargo build --release

# Run CLI
.\target\release\dispatch.exe --help
```

---

## CLI Usage Guide

### 1. Inspect Local Identity
Displays human-readable device name, 16-byte hex device ID, and Curve25519 public key fingerprint:
```bash
dispatch id
```

### 2. Rename Local Device
```bash
dispatch name "workstation-alpha"
```

### 3. Discover Peers on LAN
Scans all active interfaces (WiFi, Ethernet, direct link-local cables) using custom UDP broadcast on port 47600:
```bash
dispatch peers

# Or continuously monitor incoming announcements:
dispatch peers --watch
```

### 4. Receive Mode (Receiver PC)
Binds TCP transfer socket and broadcasts periodic announcements. Prompts user interactively on first contact:
```bash
# Save incoming transfers to default directory
dispatch listen

# Or save to a specific directory
dispatch listen --dir /mnt/storage/transfers
```

### 5. Send a File (Sender PC)
Resolves peer by name or device ID prefix, executes Noise handshake, and streams blocks:
```bash
# Send 5 GB file to peer by name
dispatch send /path/to/archive.iso "workstation-alpha"

# Or send by device ID prefix
dispatch send /path/to/archive.iso 4f8c2e19

# Fallback for broadcast-restricted networks
dispatch send /path/to/archive.iso "workstation-alpha" --addr 192.168.1.142:47601
```

### 6. Manage Trusted Devices
```bash
dispatch trust list
dispatch trust remove <device_id>
```

### 7. Diagnostics (`dispatch doctor`)
Reports network adapters, IP addresses, UDP 47600 availability, and firewall guidance:
```bash
dispatch doctor
```

---

## 5 GB+ Transfer Resume Protocol

Dispatch decomposes files into **4 MiB blocks**.
- As blocks stream in ~32 KiB encrypted frames, the sender computes BLAKE3 hashes concurrently without pre-hashing the full 5 GB file.
- The receiver writes incomplete data to `<filename>.dispatch-part` and tracks verified blocks in a lightweight JSON sidecar `<filename>.dispatch-meta`.
- **Interruption & Resume:**
  If the network drops or the connection is terminated mid-transfer:
  1. The receiver preserves `.dispatch-part` and `.dispatch-meta`.
  2. Upon reconnecting, the receiver replies to the `Offer` with an `Accept { have_blocks: [...] }` list.
  3. The sender skips all blocks the receiver already has.
  4. Only missing blocks are re-sent.
  5. On completion, the receiver re-verifies the whole-file BLAKE3 hash, deletes the sidecar, and atomically renames the part file. Byte-identical fidelity is guaranteed.

---

## Manual Test Script: Two PCs over Direct Cable / LAN

### Test Setup: Two PCs Connected via Single Ethernet Cable (No Router)
1. Plug an Ethernet cable directly between PC-1 and PC-2.
2. Both operating systems will automatically assign link-local IPv4 addresses in the `169.254.x.x` subnet.
3. On PC-1 (Receiver):
   ```bash
   dispatch listen --dir ./received_files
   ```
4. On PC-2 (Sender):
   ```bash
   # Run doctor to verify link-local interface and peer detection
   dispatch doctor

   # Discover PC-1
   dispatch peers

   # Create a test 5 GB file
   # Linux/macOS:
   dd if=/dev/urandom of=test_5gb.dat bs=1M count=5000 status=progress
   # Windows PowerShell:
   # fsutil file createnew test_5gb.dat 5242880000

   # Send file
   dispatch send test_5gb.dat "PC-1-Name"
   ```
5. Confirm that:
   - Both screens display matching 6-digit SAS codes (e.g. `[ 481 902 ]`).
   - Throughput displays ~105 - 115 MB/s on Gigabit Ethernet.
   - Kill the sender mid-way (`Ctrl+C` at 50%).
   - Re-run `dispatch send test_5gb.dat "PC-1-Name"`.
   - Transfer resumes instantly from 50%, sending only remaining blocks.
   - Final whole-file BLAKE3 hashes match on both machines.

---

## Known Platform Caveats & Limitations

1. **Windows Firewall Network Profiles:**
   On Windows, unmanaged peer-to-peer connections (or newly joined networks) default to the `Public` network profile, which blocks incoming UDP broadcasts by default. Users must set the network profile to `Private` or click "Allow" on the Windows Defender Firewall prompt when `dispatch` first starts.
2. **Direct Link-Local Broadcast on Windows:**
   When using a direct cable without a DHCP server, Windows may take 5–15 seconds to finish IPv4 link-local address autoconfiguration (`169.254.x.x/16`). Running `dispatch doctor` verifies when the link-local interface has bound.
3. **UDP Broadcast Multi-Homing:**
   Machines with multiple active network interfaces (e.g., active WiFi and plugged-in Ethernet simultaneously) send broadcast announcements across all interfaces. In rare topologies where routers isolate broadcast domains between interfaces, the `--addr <ip:port>` fallback allows direct point-to-point connection.
4. **In-Memory Frame Limits:**
   Frames are strictly bounded at 64 KiB ciphertext. Systems with low RAM (e.g., small embedded boards) can safely stream 50 GB+ files because memory consumption never exceeds small I/O buffer pools (~4 MiB).


   **This tool was built by Elkana Liman**
