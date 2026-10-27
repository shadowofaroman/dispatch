use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::error::{DispatchError, Result};
use crate::protocol::DeviceId;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdentityConfig {
    pub device_name: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustEntry {
    pub device_id: String,
    pub public_key: Vec<u8>,
    pub name: String,
    pub first_seen_secs: u64,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct TrustStore {
    pub devices: HashMap<String, TrustEntry>,
}

pub struct DeviceIdentity {
    pub config_dir: PathBuf,
    pub device_name: String,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub device_id: DeviceId,
    pub trust_store: TrustStore,
}

impl DeviceIdentity {
    pub fn load_or_generate() -> Result<Self> {
        let config_dir = get_config_dir()?;
        fs::create_dir_all(&config_dir)?;

        let id_file = config_dir.join("identity.json");
        let trust_file = config_dir.join("trusted_devices.json");

        let identity_config = if id_file.exists() {
            let data = fs::read_to_string(&id_file)?;
            serde_json::from_str::<IdentityConfig>(&data)
                .map_err(|e| DispatchError::Serialization(e.to_string()))?
        } else {
            let gen = Self::generate_keypair()?;
            let default_name = get_hostname();
            let config = IdentityConfig {
                device_name: default_name,
                private_key: gen.0.to_vec(),
                public_key: gen.1.to_vec(),
            };
            let json = serde_json::to_string_pretty(&config)
                .map_err(|e| DispatchError::Serialization(e.to_string()))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                use std::io::Write;
                let mut f = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&id_file)?;
                f.write_all(json.as_bytes())?;
            }

            #[cfg(not(unix))]
            {
                fs::write(&id_file, json.as_bytes())?;
            }

            config
        };

        let trust_store = if trust_file.exists() {
            let data = fs::read_to_string(&trust_file)?;
            serde_json::from_str::<TrustStore>(&data).unwrap_or_default()
        } else {
            TrustStore::default()
        };

        let mut priv_arr = [0u8; 32];
        let mut pub_arr = [0u8; 32];
        priv_arr.copy_from_slice(&identity_config.private_key[..32]);
        pub_arr.copy_from_slice(&identity_config.public_key[..32]);

        let device_id = compute_device_id(&pub_arr);

        Ok(Self {
            config_dir,
            device_name: identity_config.device_name,
            private_key: priv_arr,
            public_key: pub_arr,
            device_id,
            trust_store,
        })
    }

    pub fn set_name(&mut self, new_name: String) -> Result<()> {
        self.device_name = new_name.clone();
        let id_file = self.config_dir.join("identity.json");
        let config = IdentityConfig {
            device_name: new_name,
            private_key: self.private_key.to_vec(),
            public_key: self.public_key.to_vec(),
        };
        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| DispatchError::Serialization(e.to_string()))?;
        fs::write(&id_file, json.as_bytes())?;
        Ok(())
    }

    pub fn save_trust_store(&self) -> Result<()> {
        let trust_file = self.config_dir.join("trusted_devices.json");
        let json = serde_json::to_string_pretty(&self.trust_store)
            .map_err(|e| DispatchError::Serialization(e.to_string()))?;
        fs::write(trust_file, json.as_bytes())?;
        Ok(())
    }

    pub fn trust_device(&mut self, device_id: String, public_key: &[u8; 32], name: String) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.trust_store.devices.insert(
            device_id.clone(),
            TrustEntry {
                device_id,
                public_key: public_key.to_vec(),
                name,
                first_seen_secs: now,
            },
        );
        self.save_trust_store()
    }

    pub fn remove_trust(&mut self, device_id: &str) -> Result<bool> {
        let removed = self.trust_store.devices.remove(device_id).is_some();
        if removed {
            self.save_trust_store()?;
        }
        Ok(removed)
    }

    pub fn check_key_trust(&self, remote_pubkey: &[u8; 32]) -> TrustStatus {
        let remote_id = format_device_id_compact(&compute_device_id(remote_pubkey));
        if let Some(entry) = self.trust_store.devices.get(&remote_id) {
            if entry.public_key.as_slice() == remote_pubkey {
                TrustStatus::Trusted {
                    device_id: remote_id,
                    name: entry.name.clone(),
                }
            } else {
                TrustStatus::KeyMismatch {
                    device_id: remote_id,
                    stored_name: entry.name.clone(),
                }
            }
        } else {
            TrustStatus::Unknown {
                device_id: remote_id,
            }
        }
    }

    fn generate_keypair() -> Result<([u8; 32], [u8; 32])> {
        let builder = snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let keypair = builder
            .generate_keypair()
            .map_err(|e| DispatchError::Crypto(format!("Failed to generate keypair: {e}")))?;

        let mut priv_k = [0u8; 32];
        let mut pub_k = [0u8; 32];
        priv_k.copy_from_slice(&keypair.private[..32]);
        pub_k.copy_from_slice(&keypair.public[..32]);
        Ok((priv_k, pub_k))
    }
}

pub enum TrustStatus {
    Trusted { device_id: String, name: String },
    Unknown { device_id: String },
    KeyMismatch { device_id: String, stored_name: String },
}

pub fn compute_device_id(public_key: &[u8; 32]) -> DeviceId {
    let hash = blake3::hash(public_key);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash.as_bytes()[..16]);
    id
}

pub fn format_device_id_grouped(id: &DeviceId) -> String {
    let hex = hex::encode(id);
    let mut grouped = String::new();
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            grouped.push(' ');
        }
        grouped.push(c);
    }
    grouped
}

pub fn format_device_id_compact(id: &DeviceId) -> String {
    hex::encode(id)
}

fn get_config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|p| p.join("dispatch"))
        .ok_or_else(|| DispatchError::ConfigPath("Could not determine user configuration directory".into()))
}

fn get_hostname() -> String {
    if let Ok(name) = std::env::var("HOSTNAME") {
        if !name.trim().is_empty() {
            return name;
        }
    }
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        if !name.trim().is_empty() {
            return name;
        }
    }
    "dispatch-node".to_string()
}
