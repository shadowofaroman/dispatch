# Dispatch Protocol Specification (v1)

## 1. Overview & Security Architecture

Dispatch is an encrypted, zero-configuration local area network (LAN) file transfer protocol designed to saturate gigabit+ links without internet, DNS, NTP, PKI, or central servers.

### Cryptographic Stack
- **Handshake Pattern:** `Noise_XX_25519_ChaChaPoly_BLAKE2s`
  - Pattern `XX` exchanges and mutually authenticates static Curve25519 public keys in 3 messages.
  - Mitigates identity exposure to passive eavesdroppers (static keys are transmitted encrypted under ephemeral keys).
  - Works cleanly in trust-on-first-use (TOFU) environments without pre-shared certificates.
- **Verification Code:** 6-digit SAS (Short Authentication String) computed identically by both peers from the Noise handshake hash `h`:
  $$\text{Code} = (\text{BigEndianU32}(h[0..4]) \pmod{10^6})$$ formatted as `%06u`.
- **Integrity Hashing:**
  - **Device ID:** Hex string of first 16 bytes of $\text{BLAKE3}(\text{StaticPublicKey}_{\text{raw}})$.
  - **Block Hashing:** BLAKE3 hash computed on each 4 MiB transfer block.
  - **Whole-File Hashing:** BLAKE3 tree hash across the full canonical file stream.

---

## 2. Peer Discovery (UDP Broadcast)

- **Default Port:** `47600/UDP` (configurable).
- **Socket Configuration:** `SO_BROADCAST`, `SO_REUSEADDR`, `SO_REUSEPORT` (where supported).
- **Transmission Targets:**
  - Enumerates all active, non-loopback network interfaces.
  - Sends to both each interface's directed broadcast IP (e.g., `192.168.1.255`, `10.0.0.255`, `169.254.255.255`) and the global broadcast address `255.255.255.255`.
- **Security Posture:** Announce datagrams are treated as **unauthenticated routing hints only**. Trust is established exclusively via the Noise handshake.

### Discovery Packet (Postcard serialized)
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DiscoveryPacket {
    /// Broadcast announcement or probe
    Announce {
        version: u16,         // Currently 1
        device_id: [u8; 16],  // 16-byte BLAKE3 truncated device ID
        device_name: String,  // Max 64 UTF-8 bytes
        tcp_port: u16,        // Listening TCP port
    },
    /// Probe request triggering an immediate unicast announce reply
    Probe {
        version: u16,
        device_id: [u8; 16],
    },
}
```

---

## 3. Framing Layer (Length-Prefixed Wire Protocol)

Because Noise transport messages are strictly capped at 65,535 bytes ($2^{16} - 1$), the underlying TCP byte stream is framed:

```
+-------------------------------------------------------+
|  Length (2 bytes, Big-Endian)  | Payload (Length bytes)|
+-------------------------------------------------------+
```

1. **Length Header:** `u16` big-endian indicating the payload length $L \in [1, 65535]$.
2. **Handshake Phase:** Payload is raw Noise handshake messages (token sequences $\to e$, $\to e, ee, s, es$, $\to s, se$).
3. **Transport Phase:**
   - Plaintext messages are serialized with `postcard`.
   - Plaintext payload length is limited to $\le 65519$ bytes (allowing 16 bytes for Poly1305 MAC tag).
   - Encrypted via `Noise.write_message()` $\to$ ciphertext of size $L = P + 16 \le 65535$.
   - Receiver reads 2-byte length $L$, receives $L$ ciphertext bytes, and decrypts via `Noise.read_message()`.

---

## 4. Transfer Messages (Encrypted Postcard Payloads)

```rust
pub type TransferId = [u8; 16]; // Random UUIDv4 / 128-bit BLAKE3 hash

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TransferMessage {
    /// Sender offers a file to the receiver
    Offer {
        transfer_id: TransferId,
        file_name: String,            // Sanitized basename only
        file_size: u64,               // Total bytes
        block_size: u32,              // Fixed at 4 * 1024 * 1024 (4 MiB)
        total_blocks: u32,            // ceil(file_size / block_size)
    },

    /// Receiver accepts and indicates missing or already-verified blocks
    Accept {
        transfer_id: TransferId,
        /// Bitfield or list of block indices that receiver already has verified
        have_blocks: Vec<u32>,
    },

    /// Receiver rejects transfer (user declined, out of disk space, busy)
    Reject {
        transfer_id: TransferId,
        reason: RejectReason,
    },

    /// Sender transmits a slice of a block
    /// (Subdivided to fit within 64 KiB transport frames, typically 32 KiB chunks)
    DataChunk {
        transfer_id: TransferId,
        block_index: u32,
        offset_in_block: u32,
        payload: Vec<u8>,
    },

    /// Sender signals that all chunks for block_index were transmitted
    BlockDone {
        transfer_id: TransferId,
        block_index: u32,
        block_hash: [u8; 32],         // BLAKE3 hash of the 4 MiB block
    },

    /// Sender signals end of stream with whole-file BLAKE3 hash
    Complete {
        transfer_id: TransferId,
        whole_file_hash: [u8; 32],
    },

    /// Receiver confirms whole-file hash matched and file is saved
    Verified {
        transfer_id: TransferId,
    },

    /// Explicit cancellation from either side
    Cancel {
        transfer_id: TransferId,
        reason: String,
    },

    /// Error notification
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
```

---

## 5. Handshake & Trust-on-First-Use (TOFU) Flow

```
Sender (Initiator)                                 Receiver (Responder)
==================                                 ====================
    |                                                       |
    |  Noise Msg 1: -> e                                   |
    |------------------------------------------------------>|
    |                                                       |
    |  Noise Msg 2: <- e, ee, s, es                         |
    |<------------------------------------------------------|
    |                                                       |
    |  Noise Msg 3: -> s, se                                |
    |------------------------------------------------------>|
    |                                                       |
    | [Derive Handshake Hash `h`]                           | [Derive Handshake Hash `h`]
    | SAS Code = BigEndianU32(h[0..4]) % 1_000_000          | SAS Code = BigEndianU32(h[0..4]) % 1_000_000
    |                                                       |
    | Check Receiver Static Key:                            | Check Sender Static Key:
    | - Known & matches: OK                                 | - Known & matches: OK
    | - Known but different key: ABORT (MitM Alert)         | - Known but different key: ABORT (MitM Alert)
    | - Unknown: Prompt user:                               | - Unknown: Prompt user:
    |   "Verify SAS Code: [ 481 902 ]"                     |   "Incoming from Alice [ 481 902 ]"
    |   User confirms -> Saved to trusted store             |   User confirms -> Saved to trusted store
    |                                                       |
    | [Cipherstate Split: Transport Encryption Active]      | [Cipherstate Split: Transport Encryption Active]
```

---

## 6. Resume & 4 MiB Block Streaming Flow

### 6.1 Disk Layout During Transfer
- Target file: `<download_dir>/<sanitized_name>.dispatch-part`
- Sidecar metadata: `<download_dir>/<sanitized_name>.dispatch-meta`
  - JSON/Postcard containing:
    - `transfer_id`: 16 bytes
    - `file_name`: String
    - `file_size`: u64
    - `block_size`: 4,194,304 bytes
    - `verified_blocks`: Set of `(block_index, blake3_hash)`

### 6.2 Transfer Progression
1. **Offer & Negotiation:**
   - Sender sends `Offer`.
   - Receiver checks disk space via `fs2::available_space()`. If `available < file_size`, sends `Reject(InsufficientDiskSpace)`.
   - Receiver checks for existing `.dispatch-meta` matching `transfer_id` and `file_size`.
   - Receiver populates `have_blocks` with all blocks already verified in sidecar and sends `Accept { have_blocks }`.
2. **Pipelined Streaming:**
   - Sender iterates through blocks $0..\text{total\_blocks}$.
   - If `have_blocks.contains(&i)`, sender skips block $i$.
   - For missing blocks, sender reads 4 MiB, streaming it in 32 KiB `DataChunk` messages.
   - Concurrently, sender updates BLAKE3 block hash.
   - At block end, sender dispatches `BlockDone { block_index, block_hash }`.
3. **Receiver Block Verification:**
   - Receiver buffers chunks to `.dispatch-part` at `block_index * block_size + offset`.
   - Once all bytes of block $i$ arrive, receiver computes BLAKE3 hash.
   - If match $\to$ adds index to sidecar `verified_blocks` and syncs metadata.
   - If mismatch $\to$ discards block and requests retransmission or sends `Error`.
4. **Completion:**
   - Sender transmits `Complete { whole_file_hash }`.
   - Receiver validates all blocks present, validates full BLAKE3 hash.
   - Receiver atomic-renames `.dispatch-part` $\to$ `<file_name>` (appends `(1)`, `(2)` if name exists).
   - Receiver removes `.dispatch-meta` and sends `Verified`.

---

## 7. Safety, Path Sanitization & Windows Compatibility

1. **Path Sanitization:**
   - Extract raw file name with `std::path::Path::file_name()`.
   - Disallow empty names, null bytes, `.`, `..`, `/`, `\`.
   - Strip Windows reserved filenames on all OSes: `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`.
   - Restrict write target strictly to receiver's configured directory with canonicalization check.
2. **Socket Tuning for Gigabit Line Rate:**
   - `TCP_NODELAY = true` to disable Nagle's algorithm.
   - Sockets configured with enlarged send/recv buffers: `SO_SNDBUF = 2 MiB`, `SO_RCVBUF = 2 MiB`.
