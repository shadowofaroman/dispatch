use snow::TransportState;
use tokio::net::TcpStream;
use crate::error::{DispatchError, Result};
use crate::framing::{read_frame, write_frame};
use crate::identity::{compute_device_id, DeviceIdentity};
use crate::protocol::{DeviceId, TransferMessage, MAX_FRAME_PAYLOAD};

pub struct SecureChannel {
    stream: TcpStream,
    transport: TransportState,
    pub remote_static_key: [u8; 32],
    pub remote_device_id: DeviceId,
    pub verification_code: String,
}

impl SecureChannel {
    /// Perform Noise_XX handshake as initiator (Sender)
    pub async fn connect_initiator(
        mut stream: TcpStream,
        identity: &DeviceIdentity,
    ) -> Result<Self> {
        let pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(pattern.parse().unwrap());

        let mut initiator = builder
            .local_private_key(&identity.private_key)
            .build_initiator()
            .map_err(|e| DispatchError::Handshake(format!("Initiator build error: {e}")))?;

        let mut buf = vec![0u8; 65535];

        // Msg 1: -> e
        let len = initiator
            .write_message(&[], &mut buf)
            .map_err(|e| DispatchError::Handshake(format!("Write Msg 1 error: {e}")))?;
        write_frame(&mut stream, &buf[..len]).await?;

        // Msg 2: <- e, ee, s, es
        let incoming = read_frame(&mut stream).await?;
        initiator
            .read_message(&incoming, &mut buf)
            .map_err(|e| DispatchError::Handshake(format!("Read Msg 2 error: {e}")))?;

        // Msg 3: -> s, se
        let len = initiator
            .write_message(&[], &mut buf)
            .map_err(|e| DispatchError::Handshake(format!("Write Msg 3 error: {e}")))?;
        write_frame(&mut stream, &buf[..len]).await?;

        let remote_key_slice = initiator
            .get_remote_static()
            .ok_or_else(|| DispatchError::Handshake("Missing remote static public key".into()))?;

        let mut remote_static_key = [0u8; 32];
        remote_static_key.copy_from_slice(remote_key_slice);
        let remote_device_id = compute_device_id(&remote_static_key);

        let handshake_hash = initiator.get_handshake_hash();
        let verification_code = compute_verification_code(handshake_hash);

        let transport = initiator
            .into_transport_mode()
            .map_err(|e| DispatchError::Handshake(format!("Transport transition error: {e}")))?;

        Ok(Self {
            stream,
            transport,
            remote_static_key,
            remote_device_id,
            verification_code,
        })
    }

    /// Perform Noise_XX handshake as responder (Receiver)
    pub async fn accept_responder(
        mut stream: TcpStream,
        identity: &DeviceIdentity,
    ) -> Result<Self> {
        let pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
        let builder = snow::Builder::new(pattern.parse().unwrap());

        let mut responder = builder
            .local_private_key(&identity.private_key)
            .build_responder()
            .map_err(|e| DispatchError::Handshake(format!("Responder build error: {e}")))?;

        let mut buf = vec![0u8; 65535];

        // Msg 1: -> e
        let incoming = read_frame(&mut stream).await?;
        responder
            .read_message(&incoming, &mut buf)
            .map_err(|e| DispatchError::Handshake(format!("Read Msg 1 error: {e}")))?;

        // Msg 2: <- e, ee, s, es
        let len = responder
            .write_message(&[], &mut buf)
            .map_err(|e| DispatchError::Handshake(format!("Write Msg 2 error: {e}")))?;
        write_frame(&mut stream, &buf[..len]).await?;

        // Msg 3: -> s, se
        let incoming = read_frame(&mut stream).await?;
        responder
            .read_message(&incoming, &mut buf)
            .map_err(|e| DispatchError::Handshake(format!("Read Msg 3 error: {e}")))?;

        let remote_key_slice = responder
            .get_remote_static()
            .ok_or_else(|| DispatchError::Handshake("Missing remote static public key".into()))?;

        let mut remote_static_key = [0u8; 32];
        remote_static_key.copy_from_slice(remote_key_slice);
        let remote_device_id = compute_device_id(&remote_static_key);

        let handshake_hash = responder.get_handshake_hash();
        let verification_code = compute_verification_code(handshake_hash);

        let transport = responder
            .into_transport_mode()
            .map_err(|e| DispatchError::Handshake(format!("Transport transition error: {e}")))?;

        Ok(Self {
            stream,
            transport,
            remote_static_key,
            remote_device_id,
            verification_code,
        })
    }

    /// Encrypt and send a TransferMessage frame
    pub async fn send_message(&mut self, message: &TransferMessage) -> Result<()> {
        let plaintext = postcard::to_allocvec(message)
            .map_err(|e| DispatchError::Serialization(format!("Message serialization failed: {e}")))?;

        if plaintext.len() > MAX_FRAME_PAYLOAD {
            return Err(DispatchError::Framing(format!(
                "Message payload {} exceeds max frame payload {}",
                plaintext.len(),
                MAX_FRAME_PAYLOAD
            )));
        }

        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let len = self
            .transport
            .write_message(&plaintext, &mut ciphertext)
            .map_err(|e| DispatchError::Crypto(format!("Encryption error: {e}")))?;

        write_frame(&mut self.stream, &ciphertext[..len]).await?;
        Ok(())
    }

    /// Read and decrypt a TransferMessage frame
    pub async fn recv_message(&mut self) -> Result<TransferMessage> {
        let ciphertext = read_frame(&mut self.stream).await?;
        if ciphertext.is_empty() {
            return Err(DispatchError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Received empty frame",
            )));
        }

        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| DispatchError::Crypto(format!("Decryption error: {e}")))?;

        let message = postcard::from_bytes(&plaintext[..len])
            .map_err(|e| DispatchError::Serialization(format!("Message deserialization failed: {e}")))?;

        Ok(message)
    }

    pub fn get_stream_ref(&self) -> &TcpStream {
        &self.stream
    }
}

/// Derives 6-digit Short Authentication String from the Noise handshake hash
pub fn compute_verification_code(handshake_hash: &[u8]) -> String {
    if handshake_hash.len() < 4 {
        return "000000".to_string();
    }
    let u32_val = u32::from_be_bytes([
        handshake_hash[0],
        handshake_hash[1],
        handshake_hash[2],
        handshake_hash[3],
    ]);
    let code = u32_val % 1_000_000;
    format!("{:06}", code)
}
