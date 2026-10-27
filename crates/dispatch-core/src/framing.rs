use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::error::{DispatchError, Result};

pub const MAX_FRAME_SIZE: usize = 65535;

/// Writes a 2-byte big-endian length-prefixed frame to the stream
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(DispatchError::Framing(format!(
            "Payload size {} exceeds max frame limit {}",
            data.len(),
            MAX_FRAME_SIZE
        )));
    }

    let len = data.len() as u16;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a 2-byte big-endian length-prefixed frame from the stream
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(DispatchError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection closed by peer while waiting for frame header",
            )));
        }
        Err(e) => return Err(DispatchError::Io(e)),
    }

    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}
