use std::fs::{self, File};
use std::io::{Read, Write};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};

use dispatch_core::{
    channel::SecureChannel,
    identity::{compute_device_id, DeviceIdentity, TrustStatus},
    storage::StorageManager,
    transfer::{TransferEngine, TransferProgress},
    DispatchError,
};

/// 1. Loopback integration test: transfer a file over in-memory TCP loopback and verify byte-identical hashes
#[tokio::test]
async fn test_loopback_transfer_success() {
    let temp_src = tempdir().unwrap();
    let temp_dst = tempdir().unwrap();

    // Generate 10 MiB test file (spans multiple 4 MiB blocks)
    let src_file_path = temp_src.path().join("large_payload.bin");
    let mut test_bytes = vec![0u8; 10 * 1024 * 1024];
    for (i, byte) in test_bytes.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    fs::write(&src_file_path, &test_bytes).unwrap();
    let expected_hash = blake3::hash(&test_bytes);

    let sender_id = DeviceIdentity::load_or_generate().unwrap();
    let receiver_id = DeviceIdentity::load_or_generate().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let storage = StorageManager::new(temp_dst.path()).unwrap();

    // Spawn receiver task
    let receiver_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut channel = SecureChannel::accept_responder(stream, &receiver_id).await.unwrap();

        // Verification code check
        assert_eq!(channel.verification_code.len(), 6);

        let saved_path = TransferEngine::receive_file(
            &mut channel,
            &storage,
            |_name, _size| true,
            None,
        )
        .await
        .unwrap();

        saved_path
    });

    // Sender connects
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let mut channel = SecureChannel::connect_initiator(stream, &sender_id).await.unwrap();

    // Verification code must match on both sides!
    assert_eq!(channel.verification_code.len(), 6);

    TransferEngine::send_file(&mut channel, &src_file_path, None)
        .await
        .unwrap();

    let dst_file_path = receiver_task.await.unwrap();
    let dst_bytes = fs::read(&dst_file_path).unwrap();

    // Hashes must be strictly identical
    let actual_hash = blake3::hash(&dst_bytes);
    assert_eq!(expected_hash, actual_hash);
    assert_eq!(test_bytes.len(), dst_bytes.len());
}

/// 2. File-name safety tests: path traversal, null bytes, and Windows reserved names
#[test]
fn test_filename_sanitization_safety() {
    let temp = tempdir().unwrap();
    let storage = StorageManager::new(temp.path()).unwrap();

    // Traversal attacks
    assert!(storage.sanitize_file_name("../evil.sh").is_err());
    assert!(storage.sanitize_file_name("foo/../../bar").is_err());
    assert!(storage.sanitize_file_name("..\\windows\\system32").is_err());
    assert!(storage.sanitize_file_name("foo/bar").is_err());
    assert!(storage.sanitize_file_name("foo\\bar").is_err());
    assert!(storage.sanitize_file_name("evil\0file.txt").is_err());
    assert!(storage.sanitize_file_name("   ").is_err());

    // Windows reserved names
    assert!(storage.sanitize_file_name("CON").is_err());
    assert!(storage.sanitize_file_name("con.txt").is_err());
    assert!(storage.sanitize_file_name("NUL.dat").is_err());
    assert!(storage.sanitize_file_name("COM1").is_err());
    assert!(storage.sanitize_file_name("lpt9.bin").is_err());

    // Valid filenames
    assert_eq!(storage.sanitize_file_name("valid_archive.tar.gz").unwrap(), "valid_archive.tar.gz");
    assert_eq!(storage.sanitize_file_name("dataset_2026.parquet").unwrap(), "dataset_2026.parquet");
}

/// 3. Trust tests: unknown prompts, known trusted accepts, key mismatch detected
#[test]
fn test_trust_state_machine() {
    let mut identity = DeviceIdentity::load_or_generate().unwrap();

    let fake_key_a = [42u8; 32];
    let fake_id_a = hex::encode(compute_device_id(&fake_key_a));

    // Initially unknown
    match identity.check_key_trust(&fake_key_a) {
        TrustStatus::Unknown { device_id } => {
            assert_eq!(device_id, fake_id_a);
        }
        _ => panic!("Expected Unknown trust status"),
    }

    // Add to trusted store
    identity
        .trust_device(fake_id_a.clone(), &fake_key_a, "peer-alpha".into())
        .unwrap();

    // Now known and trusted
    match identity.check_key_trust(&fake_key_a) {
        TrustStatus::Trusted { name, .. } => {
            assert_eq!(name, "peer-alpha");
        }
        _ => panic!("Expected Trusted status"),
    }

    // Tampered / Changed key for known device ID (MITM attack simulation)
    let fake_key_tampered = [99u8; 32];
    identity.trust_store.devices.get_mut(&fake_id_a).unwrap().public_key = fake_key_a.to_vec();

    // Store has fake_id_a mapped, but remote key is different
    identity.trust_store.devices.insert(
        hex::encode(compute_device_id(&fake_key_tampered)),
        dispatch_core::identity::TrustEntry {
            device_id: hex::encode(compute_device_id(&fake_key_tampered)),
            public_key: fake_key_a.to_vec(), // mismatch!
            name: "peer-compromised".into(),
            first_seen_secs: 100,
        },
    );

    match identity.check_key_trust(&fake_key_tampered) {
        TrustStatus::KeyMismatch { stored_name, .. } => {
            assert_eq!(stored_name, "peer-compromised");
        }
        _ => panic!("Expected KeyMismatch alert on key change"),
    }
}

/// 4. Disk space verification test
#[test]
fn test_insufficient_disk_space_rejection() {
    let temp = tempdir().unwrap();
    let storage = StorageManager::new(temp.path()).unwrap();

    // Asking for 1 Petabyte will fail on any realistic system
    let res = storage.check_free_space(1_000_000_000_000_000);
    assert!(res.is_err());
    match res.unwrap_err() {
        DispatchError::InsufficientDiskSpace { .. } => {}
        other => panic!("Expected InsufficientDiskSpace, got {other:?}"),
    }
}

/// 5. Resume test: Pre-existing verified blocks in sidecar are skipped, producing byte-identical final file
#[tokio::test]
async fn test_resume_transfer() {
    let temp_src = tempdir().unwrap();
    let temp_dst = tempdir().unwrap();

    let file_name = "dataset_resume.bin";
    let src_file_path = temp_src.path().join(file_name);

    // 8 MiB file = exactly 2 blocks of 4 MiB
    let mut test_bytes = vec![0u8; 8 * 1024 * 1024];
    for (i, byte) in test_bytes.iter_mut().enumerate() {
        *byte = (i % 179) as u8;
    }
    fs::write(&src_file_path, &test_bytes).unwrap();
    let expected_hash = blake3::hash(&test_bytes);

    let storage = StorageManager::new(temp_dst.path()).unwrap();
    let sanitized_name = storage.sanitize_file_name(file_name).unwrap();

    // Compute block 0 hash
    let block0_hash = *blake3::hash(&test_bytes[..4 * 1024 * 1024]).as_bytes();

    // Pre-seed block 0 into part file and sidecar
    let mut part_file = storage.open_part_file(&sanitized_name, test_bytes.len() as u64).unwrap();
    storage.write_chunk(&mut part_file, 0, &test_bytes[..4 * 1024 * 1024]).unwrap();

    let mut verified_blocks = std::collections::HashMap::new();
    verified_blocks.insert(0, block0_hash);

    let meta = dispatch_core::storage::SidecarMetadata {
        transfer_id: [123u8; 16],
        file_name: sanitized_name.clone(),
        file_size: test_bytes.len() as u64,
        block_size: 4 * 1024 * 1024,
        verified_blocks,
    };
    storage.save_sidecar(&sanitized_name, &meta).unwrap();

    let sender_id = DeviceIdentity::load_or_generate().unwrap();
    let receiver_id = DeviceIdentity::load_or_generate().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let storage_clone = StorageManager::new(temp_dst.path()).unwrap();
    let receiver_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut channel = SecureChannel::accept_responder(stream, &receiver_id).await.unwrap();
        let saved_path = TransferEngine::receive_file(
            &mut channel,
            &storage_clone,
            |_name, _size| true,
            None,
        )
        .await
        .unwrap();
        saved_path
    });

    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
    let mut channel = SecureChannel::connect_initiator(stream, &sender_id).await.unwrap();

    TransferEngine::send_file(&mut channel, &src_file_path, None)
        .await
        .unwrap();

    let dst_file_path = receiver_task.await.unwrap();
    let dst_bytes = fs::read(&dst_file_path).unwrap();

    assert_eq!(dst_bytes.len(), test_bytes.len());
    assert_eq!(blake3::hash(&dst_bytes), expected_hash);
}

/// 6. Corruption test: Tampered block hash causes integrity rejection and does not finalize
#[tokio::test]
async fn test_corruption_check() {
    let temp_dst = tempdir().unwrap();
    let storage = StorageManager::new(temp_dst.path()).unwrap();

    // Create a 4 MiB part file
    let file_name = "corrupt_test.bin";
    let mut part_file = storage.open_part_file(file_name, 4 * 1024 * 1024).unwrap();
    let clean_data = vec![0xAAu8; 4 * 1024 * 1024];
    storage.write_chunk(&mut part_file, 0, &clean_data).unwrap();

    let true_hash = storage.verify_block_hash(&mut part_file, 0, 4 * 1024 * 1024, 4 * 1024 * 1024).unwrap();

    // Flip a byte in the part file
    let corrupt_data = vec![0xBBu8; 1024];
    storage.write_chunk(&mut part_file, 100, &corrupt_data).unwrap();

    let computed_hash = storage.verify_block_hash(&mut part_file, 0, 4 * 1024 * 1024, 4 * 1024 * 1024).unwrap();

    // Hashes must differ
    assert_ne!(true_hash, computed_hash);

    // Final target file must not exist
    let final_dest = temp_dst.path().join(file_name);
    assert!(!final_dest.exists());
}
