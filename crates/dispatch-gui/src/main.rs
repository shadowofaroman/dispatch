#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dispatch_core::{
    bind_listener, configure_high_throughput_socket, format_device_id_compact,
    format_device_id_grouped, DeviceIdentity, DiscoveredPeer, DiscoveryEngine, DispatchError,
    SecureChannel, StorageManager, TransferEngine, TransferProgress, TrustStatus,
    DEFAULT_UDP_PORT,
};
use serde::Serialize;
use tauri::async_runtime::JoinHandle;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};

type CoreResult<T> = dispatch_core::Result<T>;

const TCP_PORT: u16 = 47601;
const EVENT: &str = "dispatch://event";

// ---------------------------------------------------------------------------
// Types shared with the UI (field names match ui/index.html)
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone, PartialEq)]
struct PeerDto {
    device_id: String,
    name: String,
    addr: String,
    trusted: bool,
}

#[derive(Serialize)]
struct IdentityDto {
    name: String,
    id: String,
}

#[derive(Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UiEvent {
    PeerFound { peer: PeerDto },
    PeerLost { device_id: String },
    ListeningChanged { active: bool, dir: Option<String> },
    SasRequired { request_id: u64, peer: PeerDto, code: String },
    KeyMismatch { peer: PeerDto },
    IncomingOffer { offer_id: u64, peer: PeerDto, name: String, size: u64 },
    TransferStarted { id: u64, name: String, size: u64, outgoing: bool, resumed_blocks: u32 },
    TransferProgress { id: u64, bytes: u64, total: u64, bytes_per_sec: f64, eta_secs: Option<u64> },
    TransferDone { id: u64, path: Option<String>, verified: bool, avg_bytes_per_sec: f64 },
    TransferFailed { id: u64, reason: String, resumable: bool },
}

fn emit(app: &AppHandle, ev: UiEvent) {
    let _ = app.emit(EVENT, ev);
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct AppState {
    /// Immutable copy used for handshakes and discovery.
    crypto_id: Arc<DeviceIdentity>,
    /// Mutable copy used for the trust store and renaming. Never hold across an await.
    me: Mutex<DeviceIdentity>,
    discovery: Arc<DiscoveryEngine>,
    /// Keep alive: if the sender drops, run_receiver exits immediately.
    stop_tx: broadcast::Sender<()>,
    listening: AtomicBool,
    listener: Mutex<Option<JoinHandle<()>>>,
    prompts: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    transfers: Mutex<HashMap<u64, JoinHandle<()>>>,
    next: AtomicU64,
}

impl AppState {
    async fn new() -> CoreResult<Self> {
        let crypto_id = Arc::new(DeviceIdentity::load_or_generate()?);
        let me = DeviceIdentity::load_or_generate()?;
        let discovery =
            Arc::new(DiscoveryEngine::new(crypto_id.clone(), TCP_PORT, DEFAULT_UDP_PORT).await?);
        let (stop_tx, _) = broadcast::channel(1);
        Ok(Self {
            crypto_id,
            me: Mutex::new(me),
            discovery,
            stop_tx,
            listening: AtomicBool::new(false),
            listener: Mutex::new(None),
            prompts: Mutex::new(HashMap::new()),
            transfers: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
        })
    }

    fn id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }
}

fn peer_dto(st: &AppState, p: &DiscoveredPeer) -> PeerDto {
    let id = format_device_id_compact(&p.device_id);
    let trusted = st.me.lock().unwrap().trust_store.devices.contains_key(&id);
    PeerDto {
        device_id: id,
        name: p.device_name.clone(),
        addr: format!("{}:{}", p.ip, p.tcp_port),
        trusted,
    }
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => dirs::home_dir().unwrap_or_default().join(rest),
        None => PathBuf::from(p),
    }
}

// ---------------------------------------------------------------------------
// Prompts: emit an event, wait for the UI to answer through a command
// ---------------------------------------------------------------------------

async fn ask(app: &AppHandle, st: &AppState, make: impl FnOnce(u64) -> UiEvent) -> bool {
    let rid = st.id();
    let (tx, rx) = oneshot::channel();
    st.prompts.lock().unwrap().insert(rid, tx);
    emit(app, make(rid));
    rx.await.unwrap_or(false)
}

fn answer(st: &AppState, id: u64, accept: bool) {
    if let Some(tx) = st.prompts.lock().unwrap().remove(&id) {
        let _ = tx.send(accept);
    }
}

/// Trust check after a handshake: trusted passes, changed key is refused,
/// unknown devices go through the SAS dialog and are saved on accept.
async fn vet_peer(app: &AppHandle, st: &AppState, ch: &SecureChannel) -> CoreResult<()> {
    let key = ch.remote_static_key;
    let status = st.me.lock().unwrap().check_key_trust(&key);
    match status {
        TrustStatus::Trusted { .. } => Ok(()),
        TrustStatus::KeyMismatch { device_id, stored_name } => {
            emit(
                app,
                UiEvent::KeyMismatch {
                    peer: PeerDto { device_id, name: stored_name, addr: String::new(), trusted: true },
                },
            );
            Err(DispatchError::ProtocolViolation(
                "Device key changed, connection refused".into(),
            ))
        }
        TrustStatus::Unknown { device_id } => {
            let name = st
                .discovery
                .get_peers()
                .await
                .into_iter()
                .find(|p| format_device_id_compact(&p.device_id) == device_id)
                .map(|p| p.device_name)
                .unwrap_or_else(|| format!("device {}", &device_id[..8]));
            let c = &ch.verification_code;
            let code = if c.len() == 6 { format!("{} {}", &c[..3], &c[3..]) } else { c.clone() };
            let peer = PeerDto {
                device_id: device_id.clone(),
                name: name.clone(),
                addr: String::new(),
                trusted: false,
            };
            let ok = ask(app, st, |rid| UiEvent::SasRequired { request_id: rid, peer, code }).await;
            if !ok {
                return Err(DispatchError::Cancelled("Codes did not match".into()));
            }
            st.me.lock().unwrap().trust_device(device_id, &key, name)
        }
    }
}

// ---------------------------------------------------------------------------
// Progress forwarding and failure reporting
// ---------------------------------------------------------------------------

async fn forward(
    app: AppHandle,
    id: u64,
    outgoing: bool,
    mut rx: mpsc::UnboundedReceiver<TransferProgress>,
) {
    while let Some(p) = rx.recv().await {
        let ev = match p {
            TransferProgress::Started { file_name, file_size, .. } => UiEvent::TransferStarted {
                id,
                name: file_name,
                size: file_size,
                outgoing,
                // TODO: core does not report this yet, see the optional patch.
                resumed_blocks: 0,
            },
            TransferProgress::Progress { transferred_bytes, total_bytes, bytes_per_sec, .. } => {
                let eta = (bytes_per_sec > 0.0).then(|| {
                    (total_bytes.saturating_sub(transferred_bytes) as f64 / bytes_per_sec).ceil() as u64
                });
                UiEvent::TransferProgress {
                    id,
                    bytes: transferred_bytes,
                    total: total_bytes,
                    bytes_per_sec,
                    eta_secs: eta,
                }
            }
            TransferProgress::BlockDone { .. } => continue,
            TransferProgress::Completed { average_speed_mbps, .. } => UiEvent::TransferDone {
                id,
                path: None,
                verified: true,
                // core's "mbps" is really MiB/s (file_size / 1 MiB / secs)
                avg_bytes_per_sec: average_speed_mbps * 1_048_576.0,
            },
        };
        emit(&app, ev);
    }
}

async fn finish(app: &AppHandle, st: &AppState, id: u64, res: CoreResult<()>) {
    st.transfers.lock().unwrap().remove(&id);
    if let Err(e) = res {
        let resumable = !matches!(
            e,
            DispatchError::TransferRejected(_)
                | DispatchError::InvalidFileName(_)
                | DispatchError::InsufficientDiskSpace { .. }
                | DispatchError::WholeFileIntegrityFailed
        );
        emit(app, UiEvent::TransferFailed { id, reason: e.to_string(), resumable });
    }
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

async fn send_inner(
    app: &AppHandle,
    st: &Arc<AppState>,
    id: u64,
    path: String,
    peer: &DiscoveredPeer,
) -> CoreResult<()> {
    let stream = TcpStream::connect((peer.ip, peer.tcp_port)).await?;
    configure_high_throughput_socket(&stream)?;
    let mut ch = SecureChannel::connect_initiator(stream, &st.crypto_id).await?;
    vet_peer(app, st, &ch).await?;

    let (tx, rx) = mpsc::unbounded_channel();
    let fwd = tauri::async_runtime::spawn(forward(app.clone(), id, true, rx));
    let res = TransferEngine::send_file(&mut ch, &path, Some(tx)).await;
    let _ = fwd.await;
    res
}

#[tauri::command]
async fn send_file(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    path: String,
    peer_id: String,
) -> Result<u64, String> {
    let st = state.inner().clone();
    let peer = st
        .discovery
        .get_peers()
        .await
        .into_iter()
        .find(|p| format_device_id_compact(&p.device_id) == peer_id)
        .ok_or("That device is no longer visible on the network")?;

    let id = st.id();
    let task = {
        let (app, st) = (app.clone(), st.clone());
        tauri::async_runtime::spawn(async move {
            let res = send_inner(&app, &st, id, path, &peer).await;
            finish(&app, &st, id, res).await;
        })
    };
    st.transfers.lock().unwrap().insert(id, task);
    Ok(id)
}

#[tauri::command]
fn cancel_transfer(app: AppHandle, state: State<'_, Arc<AppState>>, transfer_id: u64) {
    if let Some(h) = state.transfers.lock().unwrap().remove(&transfer_id) {
        h.abort();
        emit(
            &app,
            UiEvent::TransferFailed { id: transfer_id, reason: "Cancelled".into(), resumable: true },
        );
    }
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

async fn incoming_inner(
    app: &AppHandle,
    st: &Arc<AppState>,
    stream: TcpStream,
    storage: &Arc<StorageManager>,
    id: u64,
) -> CoreResult<PathBuf> {
    configure_high_throughput_socket(&stream)?;
    let mut ch = SecureChannel::accept_responder(stream, &st.crypto_id).await?;
    vet_peer(app, st, &ch).await?;

    let dev = format_device_id_compact(&ch.remote_device_id);
    let name = st
        .me
        .lock()
        .unwrap()
        .trust_store
        .devices
        .get(&dev)
        .map(|e| e.name.clone())
        .unwrap_or_else(|| "Unknown device".into());
    let peer = PeerDto { device_id: dev, name, addr: String::new(), trusted: true };

    // receive_file takes a blocking callback, so park this worker thread until
    // the UI answers. Needs the multi-threaded runtime (Tauri's default).
    let (a, s) = (app.clone(), st.clone());
    let confirm = move |file: &str, size: u64| -> bool {
        let rid = s.id();
        let (tx, rx) = oneshot::channel();
        s.prompts.lock().unwrap().insert(rid, tx);
        emit(
            &a,
            UiEvent::IncomingOffer { offer_id: rid, peer: peer.clone(), name: file.to_string(), size },
        );
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(rx))
            .unwrap_or(false)
    };

    let (tx, rx) = mpsc::unbounded_channel();
    let fwd = tauri::async_runtime::spawn(forward(app.clone(), id, false, rx));
    let res = TransferEngine::receive_file(&mut ch, storage, confirm, Some(tx)).await;
    let _ = fwd.await;
    res
}

async fn handle_incoming(
    app: AppHandle,
    st: Arc<AppState>,
    stream: TcpStream,
    storage: Arc<StorageManager>,
    id: u64,
) {
    let res = incoming_inner(&app, &st, stream, &storage, id).await;
    finish(&app, &st, id, res.map(|_| ())).await;
}

#[tauri::command]
async fn start_listening(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    dir: String,
) -> Result<(), String> {
    let st = state.inner().clone();
    if st.listening.load(Ordering::Relaxed) {
        return Ok(());
    }
    let dir = expand(&dir);
    // ASSUMPTION: StorageManager::new(PathBuf) -> Result<StorageManager>. Adjust to storage.rs.
    let storage = Arc::new(StorageManager::new(dir.clone()).map_err(|e| e.to_string())?);
    let listener = bind_listener(TCP_PORT).await.map_err(|e| e.to_string())?;

    let (a, s) = (app.clone(), st.clone());
    let task = tauri::async_runtime::spawn(async move {
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let id = s.id();
            let t = tauri::async_runtime::spawn(handle_incoming(
                a.clone(),
                s.clone(),
                stream,
                storage.clone(),
                id,
            ));
            s.transfers.lock().unwrap().insert(id, t);
        }
    });

    *st.listener.lock().unwrap() = Some(task);
    st.listening.store(true, Ordering::Relaxed);
    emit(&app, UiEvent::ListeningChanged { active: true, dir: Some(dir.display().to_string()) });
    Ok(())
}

#[tauri::command]
fn stop_listening(app: AppHandle, state: State<'_, Arc<AppState>>) {
    if let Some(h) = state.listener.lock().unwrap().take() {
        h.abort(); // running transfers are separate tasks and keep going
    }
    state.listening.store(false, Ordering::Relaxed);
    emit(&app, UiEvent::ListeningChanged { active: false, dir: None });
}

// ---------------------------------------------------------------------------
// Small commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_identity(state: State<'_, Arc<AppState>>) -> IdentityDto {
    let me = state.me.lock().unwrap();
    IdentityDto { name: me.device_name.clone(), id: format_device_id_grouped(&me.device_id) }
}

#[tauri::command]
fn set_device_name(state: State<'_, Arc<AppState>>, name: String) -> Result<(), String> {
    // Saved to disk now; discovery keeps announcing the old name until restart.
    state.me.lock().unwrap().set_name(name).map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_peers(state: State<'_, Arc<AppState>>) -> Result<Vec<PeerDto>, String> {
    let st = state.inner().clone();
    let peers = st.discovery.get_peers().await;
    Ok(peers.iter().map(|p| peer_dto(&st, p)).collect())
}

#[tauri::command]
fn respond_sas(state: State<'_, Arc<AppState>>, request_id: u64, accept: bool) {
    answer(&state, request_id, accept);
}

#[tauri::command]
fn respond_offer(state: State<'_, Arc<AppState>>, offer_id: u64, accept: bool) {
    answer(&state, offer_id, accept);
}

// ---------------------------------------------------------------------------
// Discovery loop: probe every 2s, announce while listening, push peer changes
// ---------------------------------------------------------------------------

async fn peer_loop(app: AppHandle, st: Arc<AppState>) {
    let mut known: HashMap<String, PeerDto> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let _ = st.discovery.broadcast_probe().await;
        if st.listening.load(Ordering::Relaxed) {
            let _ = st.discovery.broadcast_announce().await;
        }
        let peers = st.discovery.get_peers().await;
        let now: HashMap<String, PeerDto> = peers
            .iter()
            .map(|p| {
                let d = peer_dto(&st, p);
                (d.device_id.clone(), d)
            })
            .collect();
        for (id, p) in &now {
            if known.get(id) != Some(p) {
                emit(&app, UiEvent::PeerFound { peer: p.clone() });
            }
        }
        for id in known.keys() {
            if !now.contains_key(id) {
                emit(&app, UiEvent::PeerLost { device_id: id.clone() });
            }
        }
        known = now;
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let st = Arc::new(
                tauri::async_runtime::block_on(AppState::new()).map_err(|e| e.to_string())?,
            );
            app.manage(st.clone());

            let d = st.discovery.clone();
            let stop = st.stop_tx.subscribe();
            tauri::async_runtime::spawn(async move { d.run_receiver(stop).await });
            tauri::async_runtime::spawn(peer_loop(app.handle().clone(), st));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_identity,
            set_device_name,
            list_peers,
            start_listening,
            stop_listening,
            send_file,
            cancel_transfer,
            respond_sas,
            respond_offer,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Dispatch");
}
