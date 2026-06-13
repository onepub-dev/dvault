use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::server_log::log_server_event;
use getrandom::getrandom;
use sha2::{Digest, Sha256};

use lockbox_share_protocol::client::{HttpTransport, Transport};
use lockbox_share_protocol::payload;
use lockbox_share_protocol::protocol::{self, Operation, Reader, Status};
use lockbox_share_protocol::ClientError;
use lockbox_share_protocol::{
    build_ring_routes, decode_topology, decode_topology_registration, encode_replication_request,
    encode_topology, encode_topology_registration, share_code_locator, share_code_server_id_char,
    sign_replication_event, ClusterTopology, ReplicationEvent, ReplicationEventKind,
    ReplicationRequest, ServerStatus, TopologyRegistration, TopologyRoute, TopologyServer,
};

const RECORD_MAGIC: &[u8; 4] = b"LBSF";
const RECORD_HEADER_LEN: usize = 20;
const KIND_PUT: u16 = 1;
const KIND_TOMBSTONE: u16 = 2;
const KIND_FETCH_COUNT: u16 = 3;
const DEFAULT_SECRET_LEN: usize = 32;
const HASH_LEN: usize = 16;
const BUCKET_COUNT: usize = 4096;
const BUCKET_RECORD_LEN: usize = 64;
const BUCKET_PUT: u8 = 1;
const BUCKET_TOMBSTONE: u8 = 2;
const BUCKET_FETCH_COUNT: u8 = 3;
const OUTBOX_MAGIC: &[u8; 4] = b"LBSO";
const OUTBOX_HEADER_LEN: usize = 16;
const OUTBOX_EVENT: u16 = 1;
const OUTBOX_ACK: u16 = 2;
const REPLICATION_STATE_MAGIC: &[u8; 8] = b"LBSR2\0\0\0";
const REPLICATION_STATE_PERSIST_INTERVAL: usize = 1024;
const SHARE_CODE_BODY_DIGITS: usize = 12;
const TOPOLOGY_HEARTBEAT_INTERVAL_MS: u64 = 30_000;
const DEFAULT_TOPOLOGY_STALE_MS: u64 = 90_000;

type RecordHash = [u8; HASH_LEN];

#[derive(Debug, Default)]
struct ReplicationState {
    origins: HashMap<u8, ReplicationOriginState>,
    accepted_since_persist: usize,
}

#[derive(Debug, Default)]
struct ReplicationOriginState {
    epoch: u64,
    contiguous_sequence: u64,
    gaps: HashSet<u64>,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub state_dir: PathBuf,
    pub server_id: u8,
    pub cluster_id: String,
    pub public_url: Option<String>,
    pub topology_version: u64,
    pub topology_servers: Vec<TopologyServer>,
    pub topology_routes: Vec<TopologyRoute>,
    pub replication_token: Option<String>,
    pub replication_peer_urls: Vec<String>,
    pub origin_epoch: u64,
    pub promoted_owner_ids: Vec<u8>,
    pub max_payload_bytes: usize,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub shard_count: usize,
    pub developer_mode: bool,
    pub benchmark_requests: usize,
    pub benchmark_payload_bytes: usize,
    pub benchmark_concurrency: usize,
    pub benchmark_preload_shares: usize,
    pub max_fetches_per_share: u16,
    pub compact_min_bytes: u64,
    pub index_cache_entries: usize,
    pub rate_limit_per_minute: u32,
    pub rate_limit_burst: u32,
    pub verification_email_command: Option<String>,
    pub verification_email_rate_limit_per_hour: u32,
    pub verification_email_ip_rate_limit_per_hour: u32,
    pub topology_token: Option<String>,
    pub topology_stale_after_ms: u64,
    pub topology_heartbeat_interval_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8089".to_string(),
            state_dir: PathBuf::from("/var/lib/lockbox-key-server"),
            server_id: 0,
            cluster_id: "default".to_string(),
            public_url: None,
            topology_version: 1,
            topology_servers: Vec::new(),
            topology_routes: Vec::new(),
            replication_token: None,
            replication_peer_urls: Vec::new(),
            origin_epoch: unix_ms(SystemTime::now()),
            promoted_owner_ids: Vec::new(),
            max_payload_bytes: 8 * 1024,
            default_ttl: Duration::from_secs(15 * 60),
            max_ttl: Duration::from_secs(15 * 60),
            shard_count: 16,
            developer_mode: false,
            benchmark_requests: 50_000,
            benchmark_payload_bytes: 512,
            benchmark_concurrency: 0,
            benchmark_preload_shares: 0,
            max_fetches_per_share: 8,
            compact_min_bytes: 64 * 1024 * 1024,
            index_cache_entries: 65_536,
            rate_limit_per_minute: 120,
            rate_limit_burst: 40,
            verification_email_command: None,
            verification_email_rate_limit_per_hour: 5,
            verification_email_ip_rate_limit_per_hour: 30,
            topology_token: None,
            topology_stale_after_ms: DEFAULT_TOPOLOGY_STALE_MS,
            topology_heartbeat_interval_ms: TOPOLOGY_HEARTBEAT_INTERVAL_MS,
        }
    }
}

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Protocol(protocol::ProtocolError),
    PayloadTooLarge,
    NotFound,
    Expired,
    Exhausted,
    DeleteTokenInvalid,
    PayloadInvalid(String),
    Config(String),
    ReplicationUnauthorized,
    RateLimited,
    EmailUnverified,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Protocol(err) => write!(f, "{err}"),
            Self::PayloadTooLarge => write!(f, "payload too large"),
            Self::NotFound => write!(f, "share not found"),
            Self::Expired => write!(f, "share expired"),
            Self::Exhausted => write!(f, "share exhausted"),
            Self::DeleteTokenInvalid => write!(f, "delete token invalid"),
            Self::PayloadInvalid(err) => write!(f, "payload invalid: {err}"),
            Self::Config(err) => write!(f, "{err}"),
            Self::ReplicationUnauthorized => write!(f, "replication unauthorized"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::EmailUnverified => write!(f, "publisher email is not verified"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

fn lock_store<'a, T>(mutex: &'a Mutex<T>, name: &str) -> Result<MutexGuard<'a, T>, StoreError> {
    mutex
        .lock()
        .map_err(|_| StoreError::Config(format!("{name} lock was poisoned")))
}

impl From<protocol::ProtocolError> for StoreError {
    fn from(value: protocol::ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

fn store_error_from_client_error(err: ClientError) -> StoreError {
    match err {
        ClientError::Protocol(err) => StoreError::Protocol(err),
        ClientError::Payload(err) => StoreError::PayloadInvalid(err.to_string()),
        ClientError::Topology(err) => StoreError::PayloadInvalid(err),
        ClientError::Io(err) => StoreError::Io(err),
        ClientError::Url(err) => StoreError::Config(err),
        ClientError::Http(err) => StoreError::Config(err),
        ClientError::Replication(err) => StoreError::Config(err),
        ClientError::Server { message, .. } => StoreError::Config(message),
        ClientError::UnexpectedOperation { expected, actual } => {
            StoreError::Config(format!("unexpected operation {expected:?} != {actual:?}"))
        }
    }
}

#[derive(Clone)]
struct ShareEntry {
    share_code: String,
    delete_token_hash: RecordHash,
    contact_email: Option<String>,
    payload_offset: u64,
    payload_len: u32,
    expires_at_ms: u64,
    max_fetches: u16,
    fetches: u16,
}

struct Shard {
    path: PathBuf,
    file: Mutex<File>,
    index: Mutex<HashMap<RecordHash, ShareEntry>>,
    expiry_buckets: Mutex<VecDeque<(u64, Vec<(RecordHash, String)>)>>,
}

pub struct ShareStore {
    config: ServerConfig,
    auto_routes: bool,
    secret: [u8; 32],
    bucket_dir: PathBuf,
    shards: Vec<Shard>,
    verifications: Mutex<HashMap<String, VerificationEntry>>,
    email_rate_limits: Mutex<EmailRateLimits>,
    created: AtomicU64,
    fetched: AtomicU64,
    deleted: AtomicU64,
    expired: AtomicU64,
    misses: AtomicU64,
    live: AtomicUsize,
    replication_state: Mutex<ReplicationState>,
    replication_state_path: PathBuf,
    replication_tx: Option<mpsc::SyncSender<ReplicationEventKind>>,
    replication_outbox_path: PathBuf,
    replication_sequence_path: PathBuf,
    topology: Mutex<ClusterTopology>,
}

pub struct CreatedShare {
    pub share_code: String,
    pub delete_token: Vec<u8>,
    pub expires_at_ms: u64,
    pub max_fetches: u16,
    pub verification_url: Option<String>,
}

pub struct FetchedShare {
    pub payload: Vec<u8>,
    pub expires_at_ms: u64,
    pub remaining_fetches: u16,
    pub email_verification: Option<protocol::EmailVerification>,
}

#[derive(Clone, Debug)]
struct VerificationEntry {
    email: String,
    token_hash: RecordHash,
    expires_at_ms: u64,
    verified_at_ms: Option<u64>,
}

#[derive(Default)]
struct EmailRateLimits {
    by_email: HashMap<String, VecDeque<u64>>,
    by_ip: HashMap<IpAddr, VecDeque<u64>>,
}

#[derive(Clone, Debug)]
pub struct VerificationPage {
    pub success: bool,
    pub title: String,
    pub message: String,
    pub email: Option<String>,
}

impl ShareStore {
    fn encode_response_with_topology(
        &self,
        operation: Operation,
        status: Status,
        payload: &[u8],
    ) -> Vec<u8> {
        let base = protocol::encode_response(operation, status, payload);
        let topology = self.topology();
        match encode_topology(&topology) {
            Ok(bytes) => protocol::encode_response_with_tail(operation, status, payload, &bytes),
            Err(_) => base,
        }
    }

    fn encode_store_error_with_topology(&self, operation: Operation, err: StoreError) -> Vec<u8> {
        let status = match err {
            StoreError::PayloadTooLarge => Status::PayloadTooLarge,
            StoreError::NotFound => Status::ShareNotFound,
            StoreError::Expired => Status::ShareExpired,
            StoreError::Exhausted => Status::ShareExhausted,
            StoreError::DeleteTokenInvalid => Status::DeleteTokenInvalid,
            StoreError::PayloadInvalid(_) => Status::MalformedRequest,
            StoreError::Protocol(_) => Status::MalformedRequest,
            StoreError::Config(_) => Status::StoreUnavailable,
            StoreError::ReplicationUnauthorized => Status::ReplicationUnauthorized,
            StoreError::RateLimited => Status::RateLimited,
            StoreError::EmailUnverified => Status::ShareNotFound,
            StoreError::Io(_) => Status::StoreUnavailable,
        };
        let mut payload = Vec::new();
        protocol::put_u16(&mut payload, protocol::MESSAGE_VERSION);
        protocol::put_u16(&mut payload, status as u16);
        protocol::put_string(&mut payload, &err.to_string());
        self.encode_response_with_topology(operation, status, &payload)
    }
    pub fn open(mut config: ServerConfig) -> Result<Self, StoreError> {
        const MAX_SERVER_ID: u8 = 35;
        if config.developer_mode {
            config.state_dir = std::env::temp_dir().join("lockbox-key-server-dev");
        }
        if config.server_id > MAX_SERVER_ID {
            return Err(StoreError::Config(
                "server id must be an index 0..35 (0..9, a..z)".to_string(),
            ));
        }
        for promoted_owner_id in &config.promoted_owner_ids {
            if *promoted_owner_id > MAX_SERVER_ID {
                return Err(StoreError::Config(
                    "promoted owner id must be an index 0..35 (0..9, a..z)".to_string(),
                ));
            }
        }
        for topology_server in &config.topology_servers {
            if topology_server.id > MAX_SERVER_ID {
                return Err(StoreError::Config(
                    "topology server id must be an index 0..35 (0..9, a..z)".to_string(),
                ));
            }
        }
        for topology_route in &config.topology_routes {
            if topology_route.owner_id > MAX_SERVER_ID
                || topology_route.primary_id > MAX_SERVER_ID
                || topology_route
                    .failover_ids
                    .iter()
                    .any(|id| *id > MAX_SERVER_ID)
            {
                return Err(StoreError::Config(
                    "topology route id must be an index 0..35 (0..9, a..z)".to_string(),
                ));
            }
        }
        fs::create_dir_all(&config.state_dir)?;
        let auto_routes = config.topology_routes.is_empty();
        let bucket_dir = config.state_dir.join("index");
        fs::create_dir_all(&bucket_dir)?;
        let replication_state_path = config.state_dir.join("replication-state.bin");
        let replication_state = load_replication_state(&replication_state_path)?;
        let replication_outbox_path = config.state_dir.join("replication-outbox.bin");
        let replication_sequence_path = config.state_dir.join("replication-origin-sequence");
        let replication_tx = start_replication_worker(
            &config,
            &replication_outbox_path,
            &replication_sequence_path,
        );
        let secret = load_or_create_secret(&config.state_dir)?;
        let shard_count = config.shard_count.max(1);
        let cache_per_shard = config.index_cache_entries / shard_count;
        let mut shards = Vec::with_capacity(shard_count);
        let mut live = 0;
        for shard_id in 0..shard_count {
            let path = config.state_dir.join(format!("shares-{shard_id:03}.seg"));
            let mut file = OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(&path)?;
            let mut index = replay(&mut file)?;
            live += index.len();
            if cache_per_shard > 0 && index.len() > cache_per_shard {
                index = index.into_iter().take(cache_per_shard).collect();
            }
            shards.push(Shard {
                path,
                file: Mutex::new(file),
                index: Mutex::new(index),
                expiry_buckets: Mutex::new(VecDeque::new()),
            });
        }
        let topology = Self::build_initial_topology(&config);
        Ok(Self {
            config,
            auto_routes,
            secret,
            bucket_dir,
            shards,
            verifications: Mutex::new(HashMap::new()),
            email_rate_limits: Mutex::new(EmailRateLimits::default()),
            created: AtomicU64::new(0),
            fetched: AtomicU64::new(0),
            deleted: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            live: AtomicUsize::new(live),
            replication_state: Mutex::new(replication_state),
            replication_state_path,
            replication_tx,
            replication_outbox_path,
            replication_sequence_path,
            topology: Mutex::new(topology),
        })
    }

    pub fn handle(&self, operation: Operation, payload: &[u8]) -> Vec<u8> {
        self.handle_with_peer(operation, payload, None)
    }

    pub fn handle_with_peer(
        &self,
        operation: Operation,
        payload: &[u8],
        peer_ip: Option<IpAddr>,
    ) -> Vec<u8> {
        match operation {
            Operation::Share => self.handle_share(payload, peer_ip),
            Operation::Fetch => self.handle_fetch(payload),
            Operation::Delete => self.handle_delete(payload),
            Operation::Replicate => self.handle_replication(payload),
        }
    }

    pub fn max_payload_bytes(&self) -> usize {
        self.config.max_payload_bytes
    }

    pub fn rate_limit_per_minute(&self) -> u32 {
        self.config.rate_limit_per_minute
    }

    pub fn rate_limit_burst(&self) -> u32 {
        self.config.rate_limit_burst
    }

    pub fn start_topology_background(self: &Arc<Self>) {
        if self.config.topology_token.is_none() {
            return;
        }
        if self.config.topology_heartbeat_interval_ms == 0 {
            return;
        }
        let store = Arc::clone(self);
        let interval = Duration::from_millis(self.config.topology_heartbeat_interval_ms.max(1_000));
        thread::spawn(move || loop {
            for peer_url in store.topology_peer_urls() {
                if let Some(register_url) = Self::topology_register_url(&peer_url) {
                    store.send_topology_registration(&register_url);
                }
            }
            thread::sleep(interval);
        });
    }

    fn normalize_routes_for_automembership(&self, topology: &mut ClusterTopology) {
        if self.auto_routes {
            topology.routes = build_ring_routes(&topology.servers);
        }
    }

    pub fn topology(&self) -> ClusterTopology {
        let mut topology = match self.topology.lock() {
            Ok(topology) => topology.clone(),
            Err(_) => Self::build_initial_topology(&self.config),
        };
        let stale_after_ms = self.config.topology_stale_after_ms;
        if stale_after_ms > 0 {
            topology = topology.with_filtered_stale_servers(stale_after_ms);
            if topology.routes.is_empty() {
                topology.routes = build_ring_routes(&topology.servers);
            }
        }
        topology
    }

    pub fn register_topology_server(
        &self,
        registration: TopologyRegistration,
    ) -> Result<ClusterTopology, StoreError> {
        if registration.cluster_id != self.config.cluster_id {
            return Err(StoreError::Config(
                "topology cluster id mismatch".to_string(),
            ));
        }
        if registration.server_url.is_empty() || registration.security_token.is_empty() {
            return Err(StoreError::Config(
                "topology registration missing required fields".to_string(),
            ));
        }
        if self.config.topology_token.as_ref() != Some(&registration.security_token) {
            return Err(StoreError::Config(
                "topology registration token invalid".to_string(),
            ));
        }
        let mut topology = lock_store(&self.topology, "topology")?.clone();
        let now_ms = unix_ms(SystemTime::now());
        if let Some(server) = topology
            .servers
            .iter_mut()
            .find(|server| server.id == registration.server_id)
        {
            if server.url != registration.server_url {
                server.url = registration.server_url;
            }
            server.status = registration.status;
            server.last_seen_ms = Some(now_ms);
        } else {
            topology.servers.push(TopologyServer {
                id: registration.server_id,
                url: registration.server_url,
                status: registration.status,
                last_seen_ms: Some(now_ms),
            });
        }
        if topology.cluster_id != self.config.cluster_id {
            topology.cluster_id = self.config.cluster_id.clone();
        }
        topology.version = topology.version.saturating_add(1);
        topology.validate().map_err(store_error_from_client_error)?;
        topology = topology.with_filtered_stale_servers(self.config.topology_stale_after_ms);
        self.normalize_routes_for_automembership(&mut topology);
        *lock_store(&self.topology, "topology")? = topology.clone();
        Ok(topology)
    }

    pub fn handle_topology_registration(&self, payload: &[u8]) -> Result<Vec<u8>, StoreError> {
        let registration =
            decode_topology_registration(payload).map_err(store_error_from_client_error)?;
        let topology = self.register_topology_server(registration)?;
        encode_topology(&topology).map_err(store_error_from_client_error)
    }

    fn topology_peer_urls(&self) -> Vec<String> {
        self.topology()
            .servers
            .iter()
            .filter(|server| server.id != self.config.server_id)
            .filter(|server| {
                matches!(
                    server.status,
                    ServerStatus::Active | ServerStatus::Promoted | ServerStatus::Standby
                )
            })
            .map(|server| server.url.clone())
            .collect()
    }

    fn send_topology_registration(self: &Arc<Self>, register_url: &str) {
        let token = match &self.config.topology_token {
            Some(token) => token.clone(),
            None => return,
        };
        let topology = self.topology();
        let Some(self_server) = topology
            .servers
            .iter()
            .find(|server| server.id == self.config.server_id)
        else {
            return;
        };
        if matches!(self_server.status, ServerStatus::Disabled) {
            return;
        }
        let registration = TopologyRegistration {
            cluster_id: topology.cluster_id.clone(),
            server_id: self.config.server_id,
            server_url: self_server.url.clone(),
            status: self_server.status.clone(),
            security_token: token,
        };
        let payload = match encode_topology_registration(&registration) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let Ok(transport) = HttpTransport::new(register_url) else {
            return;
        };
        let Ok(response) = transport.post_binary(&payload) else {
            return;
        };
        if let Ok(updated) = decode_topology(&response) {
            let _ = self.apply_topology_update(updated);
        }
    }

    fn apply_topology_update(&self, mut topology: ClusterTopology) -> Result<(), StoreError> {
        if topology.with_filtered_stale_servers(0).servers.is_empty() {
            return Err(StoreError::Config("topology has no servers".to_string()));
        }
        if topology.version == 0 {
            topology.version = 1;
        }
        topology = topology.with_filtered_stale_servers(self.config.topology_stale_after_ms);
        self.normalize_routes_for_automembership(&mut topology);
        if topology.servers.is_empty() {
            return Err(StoreError::Config(
                "topology has no healthy servers".to_string(),
            ));
        }
        topology.version = topology.version.max(1);
        let version = lock_store(&self.topology, "topology")?.version;
        if topology.version < version {
            return Ok(());
        }
        *lock_store(&self.topology, "topology")? = topology;
        Ok(())
    }

    fn build_initial_topology(config: &ServerConfig) -> ClusterTopology {
        let servers = if config.topology_servers.is_empty() {
            vec![TopologyServer {
                id: config.server_id,
                url: config
                    .public_url
                    .clone()
                    .unwrap_or_else(|| format!("http://{}/v1/share", config.bind_addr)),
                status: ServerStatus::Active,
                last_seen_ms: None,
            }]
        } else {
            config.topology_servers.clone()
        };
        let mut routes = if config.topology_routes.is_empty() {
            build_ring_routes(&servers)
        } else {
            config.topology_routes.clone()
        };
        if routes.is_empty() {
            routes = vec![TopologyRoute {
                owner_id: config.server_id,
                primary_id: config.server_id,
                failover_ids: vec![config.server_id],
            }];
        }
        ClusterTopology {
            cluster_id: config.cluster_id.clone(),
            version: config.topology_version,
            servers,
            routes,
        }
    }

    fn topology_register_url(server_url: &str) -> Option<String> {
        let trimmed = server_url.trim().trim_end_matches('/');
        let base = trimmed
            .split("/v1/")
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or(trimmed);
        Some(format!("{base}/v1/topology/register"))
    }

    fn public_share_url(&self) -> String {
        self.config.public_url.clone().unwrap_or_else(|| {
            let authority = self
                .config
                .bind_addr
                .strip_prefix("0.0.0.0:")
                .map(|port| format!("127.0.0.1:{port}"))
                .unwrap_or_else(|| self.config.bind_addr.clone());
            format!("http://{authority}/v1/share")
        })
    }

    fn handle_share(&self, payload: &[u8], peer_ip: Option<IpAddr>) -> Vec<u8> {
        match self.create_from_payload_with_peer(payload, peer_ip) {
            Ok(created) => {
                let mut body = Vec::new();
                protocol::put_u16(&mut body, protocol::MESSAGE_VERSION);
                protocol::put_string(&mut body, &created.share_code);
                protocol::put_bytes(&mut body, &created.delete_token);
                protocol::put_u64(&mut body, created.expires_at_ms);
                protocol::put_u16(&mut body, created.max_fetches);
                if let Some(verification_url) = &created.verification_url {
                    protocol::put_string(&mut body, verification_url);
                }
                self.encode_response_with_topology(Operation::Share, Status::Success, &body)
            }
            Err(err) => self.encode_store_error_with_topology(Operation::Share, err),
        }
    }

    fn handle_fetch(&self, payload: &[u8]) -> Vec<u8> {
        let result = (|| {
            let mut reader = Reader::new(payload);
            reader.message_version()?;
            let share_code = reader.string()?;
            self.fetch_by_lookup(&share_code)
        })();
        match result {
            Ok(fetched) => {
                let mut body = Vec::new();
                protocol::put_u16(&mut body, protocol::MESSAGE_VERSION);
                protocol::put_bytes(&mut body, &fetched.payload);
                protocol::put_u64(&mut body, fetched.expires_at_ms);
                protocol::put_u16(&mut body, fetched.remaining_fetches);
                if let Some(verification) = &fetched.email_verification {
                    protocol::put_string(&mut body, &verification.email);
                    body.push(u8::from(verification.verified));
                    protocol::put_u64(&mut body, verification.verified_at_unix_ms);
                    protocol::put_bytes(&mut body, &verification.attestation);
                }
                self.encode_response_with_topology(Operation::Fetch, Status::Success, &body)
            }
            Err(err) => self.encode_store_error_with_topology(Operation::Fetch, err),
        }
    }

    fn handle_delete(&self, payload: &[u8]) -> Vec<u8> {
        let result = (|| {
            let mut reader = Reader::new(payload);
            reader.message_version()?;
            let share_code = reader.string()?;
            let token = reader.bytes()?;
            self.delete(&share_code, &token)
        })();
        match result {
            Ok(deleted) => {
                let mut body = Vec::new();
                protocol::put_u16(&mut body, protocol::MESSAGE_VERSION);
                body.push(u8::from(deleted));
                self.encode_response_with_topology(Operation::Delete, Status::Success, &body)
            }
            Err(err) => self.encode_store_error_with_topology(Operation::Delete, err),
        }
    }

    fn handle_replication(&self, payload: &[u8]) -> Vec<u8> {
        match self.apply_replication_payload(payload) {
            Ok(_) => self.encode_response_with_topology(Operation::Replicate, Status::Success, &[]),
            Err(StoreError::ReplicationUnauthorized) => self.encode_store_error_with_topology(
                Operation::Replicate,
                StoreError::ReplicationUnauthorized,
            ),
            Err(err) => self.encode_store_error_with_topology(Operation::Replicate, err),
        }
    }

    pub fn create_from_payload(&self, payload: &[u8]) -> Result<CreatedShare, StoreError> {
        self.create_from_payload_with_peer(payload, None)
    }

    pub fn create_from_payload_with_peer(
        &self,
        payload: &[u8],
        peer_ip: Option<IpAddr>,
    ) -> Result<CreatedShare, StoreError> {
        let mut reader = Reader::new(payload);
        reader.message_version()?;
        let ttl_seconds = reader.u32()?;
        let requested_fetches = reader.u16()?;
        let max_fetches = if requested_fetches == 0 {
            1
        } else {
            requested_fetches.min(self.config.max_fetches_per_share.max(1))
        };
        let share_payload = reader.bytes()?;
        let verification_email = if reader.is_done() {
            None
        } else {
            let email = reader.string()?;
            Some(normalize_verification_email(&email)?)
        };
        if share_payload.len() > self.config.max_payload_bytes {
            return Err(StoreError::PayloadTooLarge);
        }
        payload::validate_payload(&share_payload)
            .map_err(|err| StoreError::PayloadInvalid(err.to_string()))?;
        if let Some(email) = verification_email.as_deref() {
            self.check_email_rate_limit(email, peer_ip)?;
        }
        let ttl = if ttl_seconds == 0 {
            self.config.default_ttl
        } else {
            Duration::from_secs(ttl_seconds as u64).min(self.config.max_ttl)
        };
        let expires_at_ms = unix_ms(SystemTime::now() + ttl);
        let share_code = self.generate_unique_code()?;
        let mut delete_token = vec![0_u8; DEFAULT_SECRET_LEN];
        getrandom(&mut delete_token)
            .map_err(|err| StoreError::Io(std::io::Error::other(err.to_string())))?;
        let code_hash = self.code_hash(&share_code);
        let delete_token_hash = self.delete_token_hash(&delete_token);
        let mut entry = ShareEntry {
            share_code: share_code.clone(),
            delete_token_hash,
            contact_email: verification_email.clone(),
            payload_offset: 0,
            payload_len: share_payload.len() as u32,
            expires_at_ms,
            max_fetches,
            fetches: 0,
        };
        let shard_id = self.shard_for(&code_hash);
        let shard = &self.shards[shard_id];
        let mut index = lock_store(&shard.index, "shard index")?;
        let mut file = lock_store(&shard.file, "shard file")?;
        let (payload_offset, payload_len) =
            append_put(&mut file, &code_hash, &entry, &share_payload)?;
        entry.payload_offset = payload_offset;
        entry.payload_len = payload_len;
        self.append_bucket_put(&code_hash, &entry)?;
        let contact_email = entry.contact_email.clone();
        if index.len() < self.config.index_cache_entries / self.shards.len().max(1) {
            index.insert(code_hash, entry);
        }
        lock_store(&shard.expiry_buckets, "expiry buckets")?
            .push_back((expires_at_ms, vec![(code_hash, share_code.clone())]));
        self.created.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_add(1, Ordering::Relaxed);
        self.enqueue_replication(ReplicationEventKind::PutShare {
            share_code: share_code.clone(),
            delete_token_hash: delete_token_hash.to_vec(),
            payload: share_payload,
            contact_email,
            expires_at_unix_ms: expires_at_ms,
            max_fetches,
            fetches: 0,
        });
        let verification_url = if let Some(email) = verification_email {
            Some(self.create_verification(&share_code, &email, expires_at_ms)?)
        } else {
            None
        };
        Ok(CreatedShare {
            share_code,
            delete_token,
            expires_at_ms,
            max_fetches,
            verification_url,
        })
    }

    fn check_email_rate_limit(
        &self,
        email: &str,
        peer_ip: Option<IpAddr>,
    ) -> Result<(), StoreError> {
        let email_limit = self.config.verification_email_rate_limit_per_hour as usize;
        let ip_limit = self.config.verification_email_ip_rate_limit_per_hour as usize;
        if email_limit == 0 && (ip_limit == 0 || peer_ip.is_none()) {
            return Ok(());
        }

        let now = unix_ms(SystemTime::now());
        let cutoff = now.saturating_sub(Duration::from_secs(60 * 60).as_millis() as u64);
        let mut limits = lock_store(&self.email_rate_limits, "email rate limits")?;

        if email_limit != 0 {
            let bucket = limits.by_email.entry(email.to_string()).or_default();
            prune_rate_bucket(bucket, cutoff);
            if bucket.len() >= email_limit {
                return Err(StoreError::RateLimited);
            }
        }
        if ip_limit != 0 {
            if let Some(ip) = peer_ip {
                let bucket = limits.by_ip.entry(ip).or_default();
                prune_rate_bucket(bucket, cutoff);
                if bucket.len() >= ip_limit {
                    return Err(StoreError::RateLimited);
                }
            }
        }

        if email_limit != 0 {
            limits
                .by_email
                .entry(email.to_string())
                .or_default()
                .push_back(now);
        }
        if ip_limit != 0 {
            if let Some(ip) = peer_ip {
                limits.by_ip.entry(ip).or_default().push_back(now);
            }
        }
        Ok(())
    }

    fn resolve_share_lookup(&self, lookup: &str) -> Result<String, StoreError> {
        if lookup.is_empty() {
            return Err(StoreError::NotFound);
        }
        if share_code_locator(lookup).is_some() {
            if !self.can_serve_share_code(lookup) {
                return Err(StoreError::NotFound);
            }
            return Ok(lookup.to_string());
        }
        Err(StoreError::NotFound)
    }

    fn create_verification(
        &self,
        share_code: &str,
        email: &str,
        expires_at_ms: u64,
    ) -> Result<String, StoreError> {
        let mut token = vec![0_u8; DEFAULT_SECRET_LEN];
        getrandom(&mut token)
            .map_err(|err| StoreError::Io(std::io::Error::other(err.to_string())))?;
        let token_hex = hex_encode(&token);
        let token_hash = stable_hash(b"email-verification-token", token_hex.as_bytes());
        lock_store(&self.verifications, "email verifications")?.insert(
            share_code.to_string(),
            VerificationEntry {
                email: email.to_string(),
                token_hash,
                expires_at_ms,
                verified_at_ms: None,
            },
        );
        let verification_url = format!(
            "{}?code={share_code}&token={token_hex}",
            self.public_verify_url()
        );
        self.send_verification_email(email, &verification_url)?;
        Ok(verification_url)
    }

    fn public_verify_url(&self) -> String {
        let share_url = self.public_share_url();
        if let Some(base) = share_url.strip_suffix("/v1/share") {
            format!("{base}/v1/verify")
        } else {
            format!("{}/v1/verify", share_url.trim_end_matches('/'))
        }
    }

    fn verify_email_inner(&self, share_code: &str, token: &str) -> Result<String, String> {
        if !self.can_serve_share_code(share_code) {
            return Err("This server does not own the supplied share code.".to_string());
        }
        let token_hash = stable_hash(b"email-verification-token", token.as_bytes());
        let now = unix_ms(SystemTime::now());
        let mut verifications = self
            .verifications
            .lock()
            .map_err(|_| "The verification state is unavailable.".to_string())?;
        let Some(entry) = verifications.get_mut(share_code) else {
            return Err("The verification link is unknown or has expired.".to_string());
        };
        if entry.expires_at_ms <= now {
            verifications.remove(share_code);
            return Err("The verification link has expired.".to_string());
        }
        if entry.token_hash != token_hash {
            return Err("The verification token is invalid.".to_string());
        }
        if entry.verified_at_ms.is_none() {
            entry.verified_at_ms = Some(now);
        }
        Ok(entry.email.clone())
    }

    fn email_verification_for_fetch(
        &self,
        share_code: &str,
        expires_at_ms: u64,
    ) -> Option<protocol::EmailVerification> {
        let Ok(verifications) = self.verifications.lock() else {
            return None;
        };
        let entry = verifications.get(share_code)?.clone();
        let verified_at = entry.verified_at_ms.unwrap_or(0);
        let verified = verified_at != 0;
        let attestation = if verified {
            self.email_attestation(share_code, &entry.email, verified_at, expires_at_ms)
        } else {
            Vec::new()
        };
        Some(protocol::EmailVerification {
            email: entry.email,
            verified,
            verified_at_unix_ms: verified_at,
            attestation,
        })
    }

    fn email_attestation(
        &self,
        share_code: &str,
        email: &str,
        verified_at_ms: u64,
        expires_at_ms: u64,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.secret);
        hasher.update(b"email-verification-attestation-v1");
        hasher.update(share_code.as_bytes());
        hasher.update(email.as_bytes());
        hasher.update(verified_at_ms.to_be_bytes());
        hasher.update(expires_at_ms.to_be_bytes());
        hasher.finalize().to_vec()
    }

    fn send_verification_email(
        &self,
        email: &str,
        verification_url: &str,
    ) -> Result<(), StoreError> {
        let Some(command) = &self.config.verification_email_command else {
            return Ok(());
        };
        let status = ProcessCommand::new(command)
            .arg(email)
            .arg(verification_url)
            .status()?;
        if !status.success() {
            return Err(StoreError::Config(format!(
                "verification email command failed with status {status}"
            )));
        }
        Ok(())
    }

    pub fn fetch(&self, share_code: &str) -> Result<FetchedShare, StoreError> {
        if !self.can_serve_share_code(share_code) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Err(StoreError::NotFound);
        }
        let code_hash = self.code_hash(share_code);
        let shard = &self.shards[self.shard_for(&code_hash)];
        let mut index = lock_store(&shard.index, "shard index")?;
        let mut cached = true;
        let mut entry = match index.get(&code_hash) {
            Some(entry) => entry.clone(),
            None => {
                cached = false;
                match self.lookup_bucket(&code_hash)? {
                    Some(entry) => entry,
                    None => {
                        self.misses.fetch_add(1, Ordering::Relaxed);
                        return Err(StoreError::NotFound);
                    }
                }
            }
        };
        if entry.expires_at_ms <= unix_ms(SystemTime::now()) {
            index.remove(&code_hash);
            let mut file = lock_store(&shard.file, "shard file")?;
            append_tombstone(&mut file, &code_hash)?;
            self.append_bucket_tombstone(&code_hash)?;
            self.enqueue_replication(ReplicationEventKind::Tombstone {
                share_code: share_code.to_string(),
            });
            self.expired.fetch_add(1, Ordering::Relaxed);
            self.live.fetch_sub(1, Ordering::Relaxed);
            return Err(StoreError::Expired);
        }
        if entry.fetches >= entry.max_fetches {
            index.remove(&code_hash);
            let mut file = lock_store(&shard.file, "shard file")?;
            append_tombstone(&mut file, &code_hash)?;
            self.append_bucket_tombstone(&code_hash)?;
            self.enqueue_replication(ReplicationEventKind::Tombstone {
                share_code: share_code.to_string(),
            });
            self.live.fetch_sub(1, Ordering::Relaxed);
            return Err(StoreError::Exhausted);
        }
        entry.fetches += 1;
        let remaining = entry.max_fetches.saturating_sub(entry.fetches);
        let payload_offset = entry.payload_offset;
        let payload_len = entry.payload_len;
        let expires_at_ms = entry.expires_at_ms;
        let fetches = entry.fetches;
        if remaining == 0 {
            index.remove(&code_hash);
            self.live.fetch_sub(1, Ordering::Relaxed);
        } else if cached {
            index.insert(code_hash, entry.clone());
        }
        let mut file = lock_store(&shard.file, "shard file")?;
        if remaining == 0 {
            append_tombstone(&mut file, &code_hash)?;
            self.append_bucket_tombstone(&code_hash)?;
            self.enqueue_replication(ReplicationEventKind::Tombstone {
                share_code: share_code.to_string(),
            });
        } else {
            append_fetch_count(&mut file, &code_hash, fetches)?;
            self.append_bucket_fetch_count(&code_hash, fetches)?;
            self.enqueue_replication(ReplicationEventKind::FetchCount {
                share_code: share_code.to_string(),
                fetches,
            });
        }
        drop(index);
        let payload = read_payload(&mut file, payload_offset, payload_len)?;
        let email_verification = self.email_verification_for_fetch(share_code, expires_at_ms);
        if remaining == 0 {
            lock_store(&self.verifications, "email verifications")?.remove(share_code);
        }
        self.fetched.fetch_add(1, Ordering::Relaxed);
        Ok(FetchedShare {
            payload,
            expires_at_ms,
            remaining_fetches: remaining,
            email_verification,
        })
    }

    pub fn fetch_by_lookup(&self, lookup: &str) -> Result<FetchedShare, StoreError> {
        let share_code = self.resolve_share_lookup(lookup)?;
        self.fetch(&share_code)
    }

    pub fn verify_email(&self, share_code: &str, token: &str) -> VerificationPage {
        match self.verify_email_inner(share_code, token) {
            Ok(email) => VerificationPage {
                success: true,
                title: "Email verified".to_string(),
                message: "This email address is now attached to the pending reVault key share. The recipient still needs a second independent verification channel before fully trusting the key.".to_string(),
                email: Some(email),
            },
            Err(message) => VerificationPage {
                success: false,
                title: "Verification failed".to_string(),
                message,
                email: None,
            },
        }
    }

    pub fn delete(&self, share_code: &str, delete_token: &[u8]) -> Result<bool, StoreError> {
        if !self.can_serve_share_code(share_code) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        let code_hash = self.code_hash(share_code);
        let token_hash = self.delete_token_hash(delete_token);
        let shard = &self.shards[self.shard_for(&code_hash)];
        let mut index = lock_store(&shard.index, "shard index")?;
        let entry = match index.get(&code_hash).cloned() {
            Some(entry) => entry,
            None => match self.lookup_bucket(&code_hash)? {
                Some(entry) => entry,
                None => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
            },
        };
        if entry.delete_token_hash != token_hash {
            return Err(StoreError::DeleteTokenInvalid);
        }
        index.remove(&code_hash);
        let mut file = lock_store(&shard.file, "shard file")?;
        append_tombstone(&mut file, &code_hash)?;
        self.append_bucket_tombstone(&code_hash)?;
        lock_store(&self.verifications, "email verifications")?.remove(share_code);
        self.deleted.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_sub(1, Ordering::Relaxed);
        self.enqueue_replication(ReplicationEventKind::Tombstone {
            share_code: share_code.to_string(),
        });
        Ok(true)
    }

    pub fn delete_by_lookup(&self, lookup: &str, delete_token: &[u8]) -> Result<bool, StoreError> {
        self.delete(lookup, delete_token)
    }

    pub fn apply_replication_payload(&self, payload: &[u8]) -> Result<bool, StoreError> {
        let request = lockbox_share_protocol::decode_replication_request(payload)
            .map_err(|err| StoreError::PayloadInvalid(err.to_string()))?;
        self.authorize_replication(&request)?;
        self.apply_replication_event(request.event)
    }

    pub fn apply_replication_event(&self, event: ReplicationEvent) -> Result<bool, StoreError> {
        if !self.reserve_replication_event(
            event.origin_server_id,
            event.origin_epoch,
            event.origin_sequence,
        )? {
            return Ok(false);
        }
        match event.kind {
            ReplicationEventKind::PutShare {
                share_code,
                delete_token_hash,
                payload,
                contact_email,
                expires_at_unix_ms,
                max_fetches,
                fetches,
            } => self.apply_replica_put(
                &share_code,
                &delete_token_hash,
                &payload,
                contact_email.as_deref(),
                expires_at_unix_ms,
                max_fetches,
                fetches,
            )?,
            ReplicationEventKind::FetchCount {
                share_code,
                fetches,
            } => self.apply_replica_fetch_count(&share_code, fetches)?,
            ReplicationEventKind::Tombstone { share_code } => {
                self.apply_replica_tombstone(&share_code)?
            }
        }
        Ok(true)
    }

    fn authorize_replication(&self, request: &ReplicationRequest) -> Result<(), StoreError> {
        let Some(token) = &self.config.replication_token else {
            return Err(StoreError::ReplicationUnauthorized);
        };
        let expected = sign_replication_event(token.as_bytes(), &request.event);
        if request.authentication == expected {
            Ok(())
        } else {
            Err(StoreError::ReplicationUnauthorized)
        }
    }

    fn reserve_replication_event(
        &self,
        origin: u8,
        epoch: u64,
        sequence: u64,
    ) -> Result<bool, StoreError> {
        let mut state = lock_store(&self.replication_state, "replication state")?;
        let should_persist_for_gap = {
            let origin_state = state.origins.entry(origin).or_default();
            if epoch < origin_state.epoch {
                return Ok(false);
            }
            if epoch > origin_state.epoch {
                origin_state.epoch = epoch;
                origin_state.contiguous_sequence = 0;
                origin_state.gaps.clear();
            }
            if sequence <= origin_state.contiguous_sequence || origin_state.gaps.contains(&sequence)
            {
                return Ok(false);
            }

            let had_gaps = !origin_state.gaps.is_empty();
            if sequence == origin_state.contiguous_sequence.saturating_add(1) {
                origin_state.contiguous_sequence = sequence;
                while origin_state
                    .gaps
                    .remove(&origin_state.contiguous_sequence.saturating_add(1))
                {
                    origin_state.contiguous_sequence =
                        origin_state.contiguous_sequence.saturating_add(1);
                }
            } else {
                origin_state.gaps.insert(sequence);
            }
            had_gaps || !origin_state.gaps.is_empty()
        };

        state.accepted_since_persist = state.accepted_since_persist.saturating_add(1);
        if should_persist_for_gap
            || state.accepted_since_persist >= REPLICATION_STATE_PERSIST_INTERVAL
        {
            store_replication_state(&self.replication_state_path, &state)?;
            state.accepted_since_persist = 0;
        }
        Ok(true)
    }

    fn apply_replica_put(
        &self,
        share_code: &str,
        delete_token_hash: &[u8],
        payload: &[u8],
        contact_email: Option<&str>,
        expires_at_ms: u64,
        max_fetches: u16,
        fetches: u16,
    ) -> Result<(), StoreError> {
        if delete_token_hash.len() != HASH_LEN {
            return Err(StoreError::PayloadInvalid(
                "delete token hash has invalid length".to_string(),
            ));
        }
        payload::validate_payload(payload)
            .map_err(|err| StoreError::PayloadInvalid(err.to_string()))?;
        let mut token_hash = [0_u8; HASH_LEN];
        token_hash.copy_from_slice(delete_token_hash);
        let contact_email = match contact_email {
            Some(email) => Some(normalize_verification_email(email)?),
            None => None,
        };
        let code_hash = self.code_hash(share_code);
        let shard = &self.shards[self.shard_for(&code_hash)];
        let mut entry = ShareEntry {
            share_code: share_code.to_string(),
            delete_token_hash: token_hash,
            contact_email,
            payload_offset: 0,
            payload_len: payload.len() as u32,
            expires_at_ms,
            max_fetches,
            fetches,
        };
        let mut index = lock_store(&shard.index, "shard index")?;
        let existed = index.contains_key(&code_hash) || self.lookup_bucket(&code_hash)?.is_some();
        let mut file = lock_store(&shard.file, "shard file")?;
        let (payload_offset, payload_len) = append_put(&mut file, &code_hash, &entry, payload)?;
        entry.payload_offset = payload_offset;
        entry.payload_len = payload_len;
        self.append_bucket_put(&code_hash, &entry)?;
        if index.len() < self.config.index_cache_entries / self.shards.len().max(1) {
            index.insert(code_hash, entry);
        }
        if !existed {
            self.live.fetch_add(1, Ordering::Relaxed);
        }
        lock_store(&shard.expiry_buckets, "expiry buckets")?
            .push_back((expires_at_ms, vec![(code_hash, share_code.to_string())]));
        Ok(())
    }

    fn apply_replica_fetch_count(&self, share_code: &str, fetches: u16) -> Result<(), StoreError> {
        let code_hash = self.code_hash(share_code);
        let shard = &self.shards[self.shard_for(&code_hash)];
        if self.lookup_bucket(&code_hash)?.is_some() {
            if let Some(cached) = lock_store(&shard.index, "shard index")?.get_mut(&code_hash) {
                cached.fetches = fetches;
            }
        }
        let mut file = lock_store(&shard.file, "shard file")?;
        append_fetch_count(&mut file, &code_hash, fetches)?;
        self.append_bucket_fetch_count(&code_hash, fetches)?;
        Ok(())
    }

    fn apply_replica_tombstone(&self, share_code: &str) -> Result<(), StoreError> {
        let code_hash = self.code_hash(share_code);
        let shard = &self.shards[self.shard_for(&code_hash)];
        let removed = lock_store(&shard.index, "shard index")?
            .remove(&code_hash)
            .is_some()
            || self.lookup_bucket(&code_hash)?.is_some();
        let mut file = lock_store(&shard.file, "shard file")?;
        append_tombstone(&mut file, &code_hash)?;
        self.append_bucket_tombstone(&code_hash)?;
        if removed {
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn can_serve_share_code(&self, share_code: &str) -> bool {
        let Some((owner_id, secondary_id)) = share_code_locator(share_code) else {
            return false;
        };
        owner_id == self.config.server_id
            || secondary_id == self.config.server_id
            || self.config.promoted_owner_ids.contains(&owner_id)
    }

    fn enqueue_replication(&self, kind: ReplicationEventKind) {
        if let Some(tx) = &self.replication_tx {
            let _ = tx.send(kind);
        }
    }

    pub fn purge_expired(&self) -> usize {
        let now_ms = unix_ms(SystemTime::now());
        let mut purged = 0;
        for shard in &self.shards {
            let mut due = Vec::new();
            {
                let Ok(mut buckets) = shard.expiry_buckets.lock() else {
                    continue;
                };
                while let Some((expires_at, _)) = buckets.front() {
                    if *expires_at > now_ms {
                        break;
                    }
                    if let Some((_, entries)) = buckets.pop_front() {
                        due.extend(entries);
                    }
                }
            }
            if due.is_empty() {
                continue;
            }
            let Ok(mut index) = shard.index.lock() else {
                continue;
            };
            let Ok(mut file) = shard.file.lock() else {
                continue;
            };
            for (hash, share_code) in due {
                if index.remove(&hash).is_some() {
                    let _ = append_tombstone(&mut file, &hash);
                    let _ = self.append_bucket_tombstone(&hash);
                    self.enqueue_replication(ReplicationEventKind::Tombstone { share_code });
                    purged += 1;
                }
            }
        }
        if purged > 0 {
            self.expired.fetch_add(purged as u64, Ordering::Relaxed);
            self.live.fetch_sub(purged, Ordering::Relaxed);
        }
        let now_ms = unix_ms(SystemTime::now());
        if let Ok(mut verifications) = self.verifications.lock() {
            verifications.retain(|_, entry| entry.expires_at_ms > now_ms);
        }
        purged
    }

    pub fn stats(&self) -> StoreStats {
        StoreStats {
            created: self.created.load(Ordering::Relaxed),
            fetched: self.fetched.load(Ordering::Relaxed),
            deleted: self.deleted.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            live: self.live.load(Ordering::Relaxed),
            segment_bytes: self.segment_bytes(),
            replication_pending: load_outbox_pending(&self.replication_outbox_path)
                .map(|pending| pending.len())
                .unwrap_or(0),
            replication_last_sequence: load_replication_sequence(&self.replication_sequence_path)
                .unwrap_or(0),
        }
    }

    pub fn status_document(&self) -> lockbox_share_protocol::KeyServerStatus {
        let stats = self.stats();
        lockbox_share_protocol::KeyServerStatus {
            created: stats.created,
            fetched: stats.fetched,
            deleted: stats.deleted,
            expired: stats.expired,
            misses: stats.misses,
            live: stats.live as u64,
            segment_bytes: stats.segment_bytes,
            replication_pending: stats.replication_pending as u64,
            replication_last_sequence: stats.replication_last_sequence,
        }
    }

    pub fn resync_peer(&self, peer_url: &str) -> Result<usize, StoreError> {
        let token = self.config.replication_token.as_ref().ok_or_else(|| {
            StoreError::Config("replication_token is required for resync".to_string())
        })?;
        let mut sequence = load_replication_sequence(&self.replication_sequence_path)?;
        let mut sent = 0usize;
        for shard in &self.shards {
            let snapshot = lock_store(&shard.index, "shard index")?
                .iter()
                .map(|(hash, entry)| (*hash, entry.clone()))
                .collect::<Vec<_>>();
            if snapshot.is_empty() {
                continue;
            }
            let mut file = lock_store(&shard.file, "shard file")?;
            for (_, entry) in snapshot {
                if entry.expires_at_ms <= unix_ms(SystemTime::now()) {
                    continue;
                }
                let payload = read_payload(&mut file, entry.payload_offset, entry.payload_len)?;
                sequence = sequence.saturating_add(1);
                store_replication_sequence(&self.replication_sequence_path, sequence)?;
                let event = ReplicationEvent {
                    origin_server_id: self.config.server_id,
                    origin_epoch: self.config.origin_epoch,
                    origin_sequence: sequence,
                    kind: ReplicationEventKind::PutShare {
                        share_code: entry.share_code.clone(),
                        delete_token_hash: entry.delete_token_hash.to_vec(),
                        payload,
                        contact_email: entry.contact_email.clone(),
                        expires_at_unix_ms: entry.expires_at_ms,
                        max_fetches: entry.max_fetches,
                        fetches: entry.fetches,
                    },
                };
                let request = encode_replication_request(&ReplicationRequest {
                    authentication: sign_replication_event(token.as_bytes(), &event),
                    event,
                });
                append_outbox_event(&self.replication_outbox_path, sequence, &request)?;
                if let Err(err) = send_replication_request(&[peer_url.to_string()], &request) {
                    return Err(StoreError::Io(std::io::Error::other(format!(
                        "replication peer {peer_url} did not accept resync event {sequence}: {err}"
                    ))));
                } else {
                    append_outbox_ack(&self.replication_outbox_path, sequence)?;
                    sent += 1;
                }
            }
        }
        Ok(sent)
    }

    pub fn segment_bytes(&self) -> u64 {
        self.shards
            .iter()
            .filter_map(|shard| shard.path.metadata().ok())
            .map(|metadata| metadata.len())
            .sum()
    }

    pub fn compact_if_needed(&self) -> Result<CompactionReport, StoreError> {
        if self.live.load(Ordering::Relaxed) > self.config.index_cache_entries {
            return Ok(CompactionReport::default());
        }
        let mut report = CompactionReport::default();
        for shard in &self.shards {
            let segment_bytes = shard.path.metadata().map(|m| m.len()).unwrap_or(0);
            if segment_bytes < self.config.compact_min_bytes {
                continue;
            }
            let live_bytes = {
                let index = lock_store(&shard.index, "shard index")?;
                compacted_bytes_for_index(&index)
            };
            if live_bytes == 0 || live_bytes.saturating_mul(2) < segment_bytes {
                report.add(compact_shard(shard)?);
            }
        }
        Ok(report)
    }

    pub fn compact(&self) -> Result<CompactionReport, StoreError> {
        if self.live.load(Ordering::Relaxed) > self.config.index_cache_entries {
            return Ok(CompactionReport::default());
        }
        let mut report = CompactionReport::default();
        for shard in &self.shards {
            report.add(compact_shard(shard)?);
        }
        Ok(report)
    }

    fn share_code_locator(&self) -> (u8, u8) {
        let topology = self.topology();
        let primary_id = topology
            .routes
            .iter()
            .find(|route| route.owner_id == self.config.server_id)
            .map(|route| route.primary_id)
            .unwrap_or(self.config.server_id);
        let secondary_id = topology
            .routes
            .iter()
            .find(|route| route.owner_id == self.config.server_id)
            .and_then(|route| route.failover_ids.first().copied())
            .or_else(|| {
                topology
                    .servers
                    .iter()
                    .filter(|server| server.status != ServerStatus::Disabled)
                    .find(|server| server.id != self.config.server_id)
                    .map(|server| server.id)
            })
            .unwrap_or(primary_id);
        (primary_id, secondary_id)
    }

    fn generate_unique_code(&self) -> Result<String, StoreError> {
        let space = 10_u64.pow(SHARE_CODE_BODY_DIGITS as u32);
        let (primary_id, secondary_id) = self.share_code_locator();
        for _ in 0..100 {
            let mut random = [0_u8; 8];
            getrandom(&mut random)
                .map_err(|err| StoreError::Io(std::io::Error::other(err.to_string())))?;
            let value = u64::from_be_bytes(random) % space;
            if let Some(code) = self.unique_code_from_value(primary_id, secondary_id, value)? {
                return Ok(code);
            }
        }
        Err(StoreError::Io(std::io::Error::other(
            "unable to allocate unique share code",
        )))
    }

    fn unique_code_from_value(
        &self,
        primary_id: u8,
        secondary_id: u8,
        value: u64,
    ) -> Result<Option<String>, StoreError> {
        let primary = share_code_server_id_char(primary_id)
            .ok_or_else(|| StoreError::Config("invalid primary server id".to_string()))?;
        let secondary = share_code_server_id_char(secondary_id)
            .ok_or_else(|| StoreError::Config("invalid secondary server id".to_string()))?;
        let code = format!(
            "{}{}{:0width$}",
            primary as char,
            secondary as char,
            value % 10_u64.pow(SHARE_CODE_BODY_DIGITS as u32),
            width = SHARE_CODE_BODY_DIGITS
        );
        let hash = self.code_hash(&code);
        let shard = &self.shards[self.shard_for(&hash)];
        if lock_store(&shard.index, "shard index")?.contains_key(&hash) {
            return Ok(None);
        }
        if self.lookup_bucket(&hash)?.is_some() {
            return Ok(None);
        }
        Ok(Some(code))
    }

    fn code_hash(&self, code: &str) -> RecordHash {
        keyed_hash(&self.secret, b"share-code", code.as_bytes())
    }

    fn delete_token_hash(&self, token: &[u8]) -> RecordHash {
        stable_hash(b"delete-token", token)
    }

    fn shard_for(&self, code_hash: &RecordHash) -> usize {
        let raw = u32::from_be_bytes([code_hash[0], code_hash[1], code_hash[2], code_hash[3]]);
        raw as usize % self.shards.len()
    }

    fn bucket_path(&self, code_hash: &RecordHash) -> PathBuf {
        self.bucket_dir
            .join(format!("bucket-{:03x}.idx", bucket_for_hash(code_hash)))
    }

    fn append_bucket_put(
        &self,
        code_hash: &RecordHash,
        entry: &ShareEntry,
    ) -> Result<(), StoreError> {
        let mut record = [0_u8; BUCKET_RECORD_LEN];
        record[0] = BUCKET_PUT;
        record[1..1 + HASH_LEN].copy_from_slice(code_hash);
        record[17..17 + HASH_LEN].copy_from_slice(&entry.delete_token_hash);
        record[33..41].copy_from_slice(&entry.payload_offset.to_be_bytes());
        record[41..45].copy_from_slice(&entry.payload_len.to_be_bytes());
        record[45..53].copy_from_slice(&entry.expires_at_ms.to_be_bytes());
        record[53..55].copy_from_slice(&entry.max_fetches.to_be_bytes());
        record[55..57].copy_from_slice(&entry.fetches.to_be_bytes());
        self.append_bucket_record(code_hash, &record)
    }

    fn append_bucket_tombstone(&self, code_hash: &RecordHash) -> Result<(), StoreError> {
        let mut record = [0_u8; BUCKET_RECORD_LEN];
        record[0] = BUCKET_TOMBSTONE;
        record[1..1 + HASH_LEN].copy_from_slice(code_hash);
        self.append_bucket_record(code_hash, &record)
    }

    fn append_bucket_fetch_count(
        &self,
        code_hash: &RecordHash,
        fetches: u16,
    ) -> Result<(), StoreError> {
        let mut record = [0_u8; BUCKET_RECORD_LEN];
        record[0] = BUCKET_FETCH_COUNT;
        record[1..1 + HASH_LEN].copy_from_slice(code_hash);
        record[55..57].copy_from_slice(&fetches.to_be_bytes());
        self.append_bucket_record(code_hash, &record)
    }

    fn append_bucket_record(
        &self,
        code_hash: &RecordHash,
        record: &[u8; BUCKET_RECORD_LEN],
    ) -> Result<(), StoreError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.bucket_path(code_hash))?;
        file.write_all(record)?;
        Ok(())
    }

    fn lookup_bucket(&self, code_hash: &RecordHash) -> Result<Option<ShareEntry>, StoreError> {
        let path = self.bucket_path(code_hash);
        if !path.exists() {
            return Ok(None);
        }
        let mut file = OpenOptions::new().read(true).open(path)?;
        let records = file.metadata()?.len() as usize / BUCKET_RECORD_LEN;
        let mut latest_fetches = None;
        let mut record = [0_u8; BUCKET_RECORD_LEN];
        for index in (0..records).rev() {
            file.seek(SeekFrom::Start((index * BUCKET_RECORD_LEN) as u64))?;
            file.read_exact(&mut record)?;
            if record[1..1 + HASH_LEN] != code_hash[..] {
                continue;
            }
            match record[0] {
                BUCKET_TOMBSTONE => return Ok(None),
                BUCKET_FETCH_COUNT => {
                    latest_fetches = Some(u16::from_be_bytes([record[55], record[56]]));
                }
                BUCKET_PUT => {
                    let mut delete_token_hash = [0_u8; HASH_LEN];
                    delete_token_hash.copy_from_slice(&record[17..17 + HASH_LEN]);
                    let fetches =
                        latest_fetches.unwrap_or(u16::from_be_bytes([record[55], record[56]]));
                    return Ok(Some(ShareEntry {
                        share_code: String::new(),
                        delete_token_hash,
                        contact_email: None,
                        payload_offset: u64::from_be_bytes([
                            record[33], record[34], record[35], record[36], record[37], record[38],
                            record[39], record[40],
                        ]),
                        payload_len: u32::from_be_bytes([
                            record[41], record[42], record[43], record[44],
                        ]),
                        expires_at_ms: u64::from_be_bytes([
                            record[45], record[46], record[47], record[48], record[49], record[50],
                            record[51], record[52],
                        ]),
                        max_fetches: u16::from_be_bytes([record[53], record[54]]),
                        fetches,
                    }));
                }
                _ => {}
            }
        }
        Ok(None)
    }
}

fn bucket_for_hash(code_hash: &RecordHash) -> usize {
    let raw = u16::from_be_bytes([code_hash[0], code_hash[1]]) as usize;
    raw % BUCKET_COUNT
}

#[derive(Debug)]
pub struct StoreStats {
    pub created: u64,
    pub fetched: u64,
    pub deleted: u64,
    pub expired: u64,
    pub misses: u64,
    pub live: usize,
    pub segment_bytes: u64,
    pub replication_pending: usize,
    pub replication_last_sequence: u64,
}

#[derive(Debug, Default)]
pub struct CompactionReport {
    pub shards_compacted: usize,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub live_records: usize,
}

impl CompactionReport {
    fn add(&mut self, other: Self) {
        self.shards_compacted += other.shards_compacted;
        self.bytes_before += other.bytes_before;
        self.bytes_after += other.bytes_after;
        self.live_records += other.live_records;
    }
}

fn prune_rate_bucket(bucket: &mut VecDeque<u64>, cutoff_ms: u64) {
    while matches!(bucket.front(), Some(value) if *value < cutoff_ms) {
        bucket.pop_front();
    }
}

fn load_or_create_secret(state_dir: &std::path::Path) -> Result<[u8; 32], StoreError> {
    let path = state_dir.join("server.secret");
    if path.exists() {
        restrict_secret_file_permissions(&path)?;
        return load_existing_secret(&path);
    }
    let mut secret = [0_u8; 32];
    getrandom(&mut secret).map_err(|err| StoreError::Io(std::io::Error::other(err.to_string())))?;
    match write_secret_file(&path, &secret) {
        Ok(()) => Ok(secret),
        Err(StoreError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            restrict_secret_file_permissions(&path)?;
            load_existing_secret(&path)
        }
        Err(err) => Err(err),
    }
}

fn load_existing_secret(path: &std::path::Path) -> Result<[u8; 32], StoreError> {
    let mut bytes = fs::read(path)?;
    if bytes.len() < 32 {
        return Err(StoreError::Io(std::io::Error::other(
            "server secret is too short",
        )));
    }
    bytes.truncate(32);
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

fn write_secret_file(path: &std::path::Path, secret: &[u8; 32]) -> Result<(), StoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(secret)?;
    file.sync_data()?;
    Ok(())
}

fn restrict_secret_file_permissions(path: &std::path::Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn load_replication_state(path: &Path) -> Result<ReplicationState, StoreError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ReplicationState::default());
        }
        Err(err) => return Err(StoreError::Io(err)),
    };
    if !bytes.starts_with(REPLICATION_STATE_MAGIC) {
        return Ok(ReplicationState::default());
    }
    let mut offset = REPLICATION_STATE_MAGIC.len();
    let origin_count = read_u32(&bytes, &mut offset)? as usize;
    let mut state = ReplicationState::default();
    for _ in 0..origin_count {
        let origin = read_u8(&bytes, &mut offset)?;
        let epoch = read_u64(&bytes, &mut offset)?;
        let contiguous_sequence = read_u64(&bytes, &mut offset)?;
        let gap_count = read_u32(&bytes, &mut offset)? as usize;
        let mut gaps = HashSet::with_capacity(gap_count);
        for _ in 0..gap_count {
            gaps.insert(read_u64(&bytes, &mut offset)?);
        }
        state.origins.insert(
            origin,
            ReplicationOriginState {
                epoch,
                contiguous_sequence,
                gaps,
            },
        );
    }
    Ok(state)
}

fn store_replication_state(path: &Path, state: &ReplicationState) -> Result<(), StoreError> {
    let mut bytes = Vec::with_capacity(16 + state.origins.len() * 32);
    bytes.extend_from_slice(REPLICATION_STATE_MAGIC);
    bytes.extend_from_slice(&(state.origins.len() as u32).to_be_bytes());
    for (origin, origin_state) in &state.origins {
        bytes.push(*origin);
        bytes.extend_from_slice(&origin_state.epoch.to_be_bytes());
        bytes.extend_from_slice(&origin_state.contiguous_sequence.to_be_bytes());
        bytes.extend_from_slice(&(origin_state.gaps.len() as u32).to_be_bytes());
        for gap in &origin_state.gaps {
            bytes.extend_from_slice(&gap.to_be_bytes());
        }
    }
    let mut tmp_path = path.to_path_buf();
    tmp_path.set_extension("bin.tmp");
    fs::write(&tmp_path, bytes)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, StoreError> {
    if *offset >= bytes.len() {
        return Err(StoreError::Io(std::io::Error::other(
            "truncated replication state",
        )));
    }
    let value = bytes[*offset];
    *offset += 1;
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, StoreError> {
    let end = offset.saturating_add(4);
    if end > bytes.len() {
        return Err(StoreError::Io(std::io::Error::other(
            "truncated replication state",
        )));
    }
    let value = u32::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset = end;
    Ok(value)
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, StoreError> {
    let end = offset.saturating_add(8);
    if end > bytes.len() {
        return Err(StoreError::Io(std::io::Error::other(
            "truncated replication state",
        )));
    }
    let value = u64::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
        bytes[*offset + 4],
        bytes[*offset + 5],
        bytes[*offset + 6],
        bytes[*offset + 7],
    ]);
    *offset = end;
    Ok(value)
}

fn start_replication_worker(
    config: &ServerConfig,
    outbox_path: &Path,
    sequence_path: &Path,
) -> Option<mpsc::SyncSender<ReplicationEventKind>> {
    let token = config.replication_token.clone()?;
    if config.replication_peer_urls.is_empty() {
        return None;
    }
    let peer_urls = config.replication_peer_urls.clone();
    let origin_server_id = config.server_id;
    let origin_epoch = config.origin_epoch;
    let outbox_path = outbox_path.to_path_buf();
    let sequence_path = sequence_path.to_path_buf();
    let (tx, rx) = mpsc::sync_channel::<ReplicationEventKind>(8192);
    thread::Builder::new()
        .name("share-replication".to_string())
        .stack_size(256 * 1024)
        .spawn(move || {
            let mut sequence = load_replication_sequence(&sequence_path).unwrap_or(0);
            let mut pending = load_outbox_pending(&outbox_path).unwrap_or_else(|err| {
                log_server_event(format!("replication outbox load failed: {err}"));
                VecDeque::new()
            });
            let mut last_retry_log = Instant::now() - Duration::from_secs(30);
            loop {
                let timeout = if pending.is_empty() {
                    Duration::from_secs(1)
                } else {
                    Duration::from_millis(10)
                };
                match rx.recv_timeout(timeout) {
                    Ok(kind) => queue_replication_event(
                        kind,
                        &mut sequence,
                        &sequence_path,
                        &outbox_path,
                        &mut pending,
                        origin_server_id,
                        origin_epoch,
                        token.as_bytes(),
                    ),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
                for kind in rx.try_iter().take(8192) {
                    queue_replication_event(
                        kind,
                        &mut sequence,
                        &sequence_path,
                        &outbox_path,
                        &mut pending,
                        origin_server_id,
                        origin_epoch,
                        token.as_bytes(),
                    );
                }
                retry_pending_outbox(&outbox_path, &peer_urls, &mut pending, &mut last_retry_log);
            }
        })
        .ok()?;
    Some(tx)
}

fn queue_replication_event(
    kind: ReplicationEventKind,
    sequence: &mut u64,
    sequence_path: &Path,
    outbox_path: &Path,
    pending: &mut VecDeque<(u64, Vec<u8>)>,
    origin_server_id: u8,
    origin_epoch: u64,
    token: &[u8],
) {
    *sequence = sequence.saturating_add(1);
    if let Err(err) = store_replication_sequence(sequence_path, *sequence) {
        log_server_event(format!("replication sequence persist failed: {err}"));
        return;
    }
    let event = ReplicationEvent {
        origin_server_id,
        origin_epoch,
        origin_sequence: *sequence,
        kind,
    };
    let request = encode_replication_request(&ReplicationRequest {
        authentication: sign_replication_event(token, &event),
        event,
    });
    if let Err(err) = append_outbox_event(outbox_path, *sequence, &request) {
        log_server_event(format!("replication outbox append failed: {err}"));
        return;
    }
    pending.push_back((*sequence, request));
}

fn retry_pending_outbox(
    outbox_path: &Path,
    peer_urls: &[String],
    pending: &mut VecDeque<(u64, Vec<u8>)>,
    last_retry_log: &mut Instant,
) {
    let attempted = pending.len();
    let mut failed = 0usize;
    let mut first_failure = None;
    let mut remaining = VecDeque::new();
    while let Some((sequence, request)) = pending.pop_front() {
        match send_replication_request(peer_urls, &request) {
            Ok(()) => {
                if let Err(err) = append_outbox_ack(outbox_path, sequence) {
                    log_server_event(format!("replication outbox ack failed: {err}"));
                    remaining.push_back((sequence, request));
                }
            }
            Err(err) => {
                failed += 1;
                if first_failure.is_none() {
                    first_failure = Some(err);
                }
                remaining.push_back((sequence, request));
                remaining.append(pending);
                break;
            }
        }
    }
    if failed > 0 && last_retry_log.elapsed() >= Duration::from_secs(10) {
        let first_failure = first_failure.unwrap_or_else(|| "unknown failure".to_string());
        log_server_event(format!(
            "replication retry deferred {failed}/{attempted} pending event(s) for {} peer(s); first failure: {first_failure}",
            peer_urls.len()
        ));
        *last_retry_log = Instant::now();
    }
    *pending = remaining;
}

fn send_replication_request(peer_urls: &[String], request: &[u8]) -> Result<(), String> {
    let mut first_failure = None;
    for peer_url in peer_urls {
        match HttpTransport::new(peer_url).and_then(|transport| {
            let response = transport.post_binary(request)?;
            protocol::decode_response(&response, 1024)
                .map_err(lockbox_share_protocol::ClientError::from)
        }) {
            Ok(response) if response.status == Status::Success => {}
            Ok(response) => {
                if first_failure.is_none() {
                    first_failure = Some(format!(
                        "replication peer {peer_url} returned {:?}",
                        response.status
                    ));
                }
            }
            Err(err) => {
                if first_failure.is_none() {
                    first_failure = Some(format!("replication peer {peer_url} failed: {err}"));
                }
            }
        }
    }
    first_failure.map_or(Ok(()), Err)
}

fn load_replication_sequence(path: &Path) -> Result<u64, StoreError> {
    match fs::read(path) {
        Ok(bytes) if bytes.len() >= 8 => Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        Ok(_) => Ok(0),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(StoreError::Io(err)),
    }
}

fn store_replication_sequence(path: &Path, sequence: u64) -> Result<(), StoreError> {
    fs::write(path, sequence.to_be_bytes()).map_err(StoreError::Io)
}

fn append_outbox_event(path: &Path, sequence: u64, request: &[u8]) -> Result<(), StoreError> {
    let mut body = Vec::with_capacity(8 + 4 + request.len());
    body.extend_from_slice(&sequence.to_be_bytes());
    protocol::put_bytes(&mut body, request);
    append_outbox_record(path, OUTBOX_EVENT, &body)
}

fn append_outbox_ack(path: &Path, sequence: u64) -> Result<(), StoreError> {
    append_outbox_record(path, OUTBOX_ACK, &sequence.to_be_bytes())
}

fn append_outbox_record(path: &Path, kind: u16, body: &[u8]) -> Result<(), StoreError> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut header = Vec::with_capacity(OUTBOX_HEADER_LEN);
    header.extend_from_slice(OUTBOX_MAGIC);
    header.extend_from_slice(&1_u16.to_be_bytes());
    header.extend_from_slice(&kind.to_be_bytes());
    header.extend_from_slice(&(body.len() as u32).to_be_bytes());
    header.extend_from_slice(&checksum(body).to_be_bytes());
    file.write_all(&header)?;
    file.write_all(body)?;
    Ok(())
}

fn load_outbox_pending(path: &Path) -> Result<VecDeque<(u64, Vec<u8>)>, StoreError> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(VecDeque::new()),
        Err(err) => return Err(StoreError::Io(err)),
    };
    let mut events = HashMap::<u64, Vec<u8>>::new();
    let mut acks = HashSet::<u64>::new();
    let mut header = [0_u8; OUTBOX_HEADER_LEN];
    loop {
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(StoreError::Io(err)),
        }
        if &header[0..4] != OUTBOX_MAGIC {
            break;
        }
        let kind = u16::from_be_bytes([header[6], header[7]]);
        let len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let expected = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
        let mut body = vec![0_u8; len];
        if file.read_exact(&mut body).is_err() {
            break;
        }
        if checksum(&body) != expected {
            break;
        }
        match kind {
            OUTBOX_EVENT if body.len() >= 12 => {
                let sequence = u64::from_be_bytes([
                    body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                ]);
                let request_len =
                    u32::from_be_bytes([body[8], body[9], body[10], body[11]]) as usize;
                if body.len() == 12 + request_len {
                    events.insert(sequence, body[12..].to_vec());
                }
            }
            OUTBOX_ACK if body.len() == 8 => {
                acks.insert(u64::from_be_bytes([
                    body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                ]));
            }
            _ => {}
        }
    }
    let mut pending = events
        .into_iter()
        .filter(|(sequence, _)| !acks.contains(sequence))
        .collect::<Vec<_>>();
    pending.sort_by_key(|(sequence, _)| *sequence);
    Ok(VecDeque::from(pending))
}

fn keyed_hash(secret: &[u8; 32], domain: &[u8], value: &[u8]) -> RecordHash {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(domain);
    hasher.update(value);
    let full_hash: [u8; 32] = hasher.finalize().into();
    let mut out = [0_u8; HASH_LEN];
    out.copy_from_slice(&full_hash[..HASH_LEN]);
    out
}

fn stable_hash(domain: &[u8], value: &[u8]) -> RecordHash {
    let mut hasher = Sha256::new();
    hasher.update(b"lockbox-key-server-stable-hash-v1");
    hasher.update(domain);
    hasher.update(value);
    let full_hash: [u8; 32] = hasher.finalize().into();
    let mut out = [0_u8; HASH_LEN];
    out.copy_from_slice(&full_hash[..HASH_LEN]);
    out
}

fn normalize_verification_email(email: &str) -> Result<String, StoreError> {
    payload::normalize_contact_email(email)
        .map_err(|_| StoreError::PayloadInvalid("verification email is invalid".to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn append_put(
    file: &mut File,
    code_hash: &RecordHash,
    entry: &ShareEntry,
    payload: &[u8],
) -> Result<(u64, u32), StoreError> {
    if entry.share_code.len() > u8::MAX as usize {
        return Err(StoreError::Config("share code is too long".to_string()));
    }
    let prefix_len = put_record_payload_offset(&entry.share_code);
    let mut body = Vec::with_capacity(prefix_len + payload.len());
    body.extend_from_slice(code_hash);
    body.push(entry.share_code.len() as u8);
    body.extend_from_slice(entry.share_code.as_bytes());
    body.extend_from_slice(&entry.delete_token_hash);
    body.extend_from_slice(&entry.expires_at_ms.to_be_bytes());
    body.extend_from_slice(&entry.max_fetches.to_be_bytes());
    protocol::put_bytes(&mut body, payload);
    if let Some(email) = &entry.contact_email {
        protocol::put_string(&mut body, email);
    }
    let body_offset = append_record(file, KIND_PUT, &body)?;
    Ok((body_offset + prefix_len as u64, payload.len() as u32))
}

fn append_tombstone(file: &mut File, code_hash: &RecordHash) -> Result<(), StoreError> {
    append_record(file, KIND_TOMBSTONE, code_hash).map(|_| ())
}

fn append_fetch_count(
    file: &mut File,
    code_hash: &RecordHash,
    fetches: u16,
) -> Result<(), StoreError> {
    let mut body = Vec::with_capacity(HASH_LEN + 2);
    body.extend_from_slice(code_hash);
    body.extend_from_slice(&fetches.to_be_bytes());
    append_record(file, KIND_FETCH_COUNT, &body).map(|_| ())
}

fn append_record(file: &mut File, kind: u16, body: &[u8]) -> Result<u64, StoreError> {
    let record_start = file.seek(SeekFrom::End(0))?;
    let mut header = Vec::with_capacity(RECORD_HEADER_LEN);
    header.extend_from_slice(RECORD_MAGIC);
    header.extend_from_slice(&1_u16.to_be_bytes());
    header.extend_from_slice(&kind.to_be_bytes());
    header.extend_from_slice(&(RECORD_HEADER_LEN as u16).to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(&(body.len() as u32).to_be_bytes());
    header.extend_from_slice(&checksum(body).to_be_bytes());
    file.write_all(&header)?;
    file.write_all(body)?;
    Ok(record_start + RECORD_HEADER_LEN as u64)
}

fn replay(file: &mut File) -> Result<HashMap<RecordHash, ShareEntry>, StoreError> {
    file.seek(SeekFrom::Start(0))?;
    let mut index = HashMap::new();
    let mut header = [0_u8; RECORD_HEADER_LEN];
    let now_ms = unix_ms(SystemTime::now());
    loop {
        let record_start = file.stream_position()?;
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(StoreError::Io(err)),
        }
        if &header[0..4] != RECORD_MAGIC {
            break;
        }
        let kind = u16::from_be_bytes([header[6], header[7]]);
        let len = u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
        let expected = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
        let mut body = vec![0_u8; len];
        if file.read_exact(&mut body).is_err() {
            break;
        }
        if checksum(&body) != expected {
            break;
        }
        match kind {
            KIND_PUT => {
                if body.len() < HASH_LEN + 1 {
                    continue;
                }
                let mut code_hash = [0_u8; HASH_LEN];
                code_hash.copy_from_slice(&body[0..HASH_LEN]);
                let code_len = body[HASH_LEN] as usize;
                let code_start = HASH_LEN + 1;
                let code_end = code_start + code_len;
                if body.len() < code_end + HASH_LEN + 8 + 2 + 4 {
                    continue;
                }
                let Ok(share_code) = std::str::from_utf8(&body[code_start..code_end]) else {
                    continue;
                };
                let mut delete_token_hash = [0_u8; HASH_LEN];
                delete_token_hash.copy_from_slice(&body[code_end..code_end + HASH_LEN]);
                let expires_offset = code_end + HASH_LEN;
                let expires_at_ms = u64::from_be_bytes([
                    body[expires_offset],
                    body[expires_offset + 1],
                    body[expires_offset + 2],
                    body[expires_offset + 3],
                    body[expires_offset + 4],
                    body[expires_offset + 5],
                    body[expires_offset + 6],
                    body[expires_offset + 7],
                ]);
                let max_fetches_offset = expires_offset + 8;
                let max_fetches =
                    u16::from_be_bytes([body[max_fetches_offset], body[max_fetches_offset + 1]]);
                let payload_len_offset = max_fetches_offset + 2;
                let payload_len = u32::from_be_bytes([
                    body[payload_len_offset],
                    body[payload_len_offset + 1],
                    body[payload_len_offset + 2],
                    body[payload_len_offset + 3],
                ]) as usize;
                let payload_offset = payload_len_offset + 4;
                if body.len() < payload_offset + payload_len {
                    continue;
                }
                let contact_email_offset = payload_offset + payload_len;
                let contact_email = if body.len() == contact_email_offset {
                    None
                } else {
                    let mut reader = Reader::new(&body[contact_email_offset..]);
                    match reader
                        .string()
                        .ok()
                        .and_then(|email| normalize_verification_email(&email).ok())
                    {
                        Some(email) if reader.is_done() => Some(email),
                        _ => None,
                    }
                };
                if expires_at_ms > now_ms {
                    index.insert(
                        code_hash,
                        ShareEntry {
                            share_code: share_code.to_string(),
                            delete_token_hash,
                            contact_email,
                            payload_offset: record_start
                                + RECORD_HEADER_LEN as u64
                                + payload_offset as u64,
                            payload_len: payload_len as u32,
                            expires_at_ms,
                            max_fetches,
                            fetches: 0,
                        },
                    );
                }
            }
            KIND_TOMBSTONE => {
                if body.len() == HASH_LEN {
                    let mut code_hash = [0_u8; HASH_LEN];
                    code_hash.copy_from_slice(&body);
                    index.remove(&code_hash);
                }
            }
            KIND_FETCH_COUNT => {
                if body.len() == HASH_LEN + 2 {
                    let mut code_hash = [0_u8; HASH_LEN];
                    code_hash.copy_from_slice(&body[0..HASH_LEN]);
                    let fetches = u16::from_be_bytes([body[HASH_LEN], body[HASH_LEN + 1]]);
                    if let Some(entry) = index.get_mut(&code_hash) {
                        if fetches >= entry.max_fetches {
                            index.remove(&code_hash);
                        } else {
                            entry.fetches = fetches;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    file.seek(SeekFrom::End(0))?;
    Ok(index)
}

fn compacted_bytes_for_index(index: &HashMap<RecordHash, ShareEntry>) -> u64 {
    index
        .values()
        .map(|entry| {
            RECORD_HEADER_LEN as u64
                + put_record_payload_offset(&entry.share_code) as u64
                + entry.payload_len as u64
        })
        .sum()
}

fn put_record_payload_offset(share_code: &str) -> usize {
    HASH_LEN + 1 + share_code.len() + HASH_LEN + 8 + 2 + 4
}

fn compact_shard(shard: &Shard) -> Result<CompactionReport, StoreError> {
    let bytes_before = shard.path.metadata().map(|m| m.len()).unwrap_or(0);
    let mut index = lock_store(&shard.index, "shard index")?;
    let mut file = lock_store(&shard.file, "shard file")?;

    if index.is_empty() {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        return Ok(CompactionReport {
            shards_compacted: usize::from(bytes_before > 0),
            bytes_before,
            bytes_after: 0,
            live_records: 0,
        });
    }

    let tmp_path = compact_tmp_path(&shard.path);
    let mut compacted = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .truncate(true)
        .open(&tmp_path)?;

    let mut rewritten = Vec::with_capacity(index.len());
    for (code_hash, entry) in index.iter() {
        let payload = read_payload(&mut file, entry.payload_offset, entry.payload_len)?;
        rewritten.push((*code_hash, entry.clone(), payload));
    }

    for (code_hash, entry, payload) in rewritten {
        let (payload_offset, payload_len) =
            append_put(&mut compacted, &code_hash, &entry, &payload)?;
        if let Some(current) = index.get_mut(&code_hash) {
            current.payload_offset = payload_offset;
            current.payload_len = payload_len;
        }
    }

    compacted.flush()?;
    compacted.sync_data()?;
    fs::rename(&tmp_path, &shard.path)?;
    *file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(&shard.path)?;
    let bytes_after = shard.path.metadata().map(|m| m.len()).unwrap_or(0);
    Ok(CompactionReport {
        shards_compacted: 1,
        bytes_before,
        bytes_after,
        live_records: index.len(),
    })
}

fn compact_tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("seg.compact");
    tmp
}

fn read_payload(file: &mut File, offset: u64, len: u32) -> Result<Vec<u8>, StoreError> {
    let mut payload = vec![0_u8; len as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut payload)?;
    file.seek(SeekFrom::End(0))?;
    Ok(payload)
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5_u32, |hash, byte| {
        hash.wrapping_mul(16777619) ^ *byte as u32
    })
}

fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

pub fn bench_store(config: ServerConfig) -> Result<(), StoreError> {
    let requests = config.benchmark_requests;
    let payload_bytes = config.benchmark_payload_bytes;
    let store = ShareStore::open(config)?;
    let payload = benchmark_payload(payload_bytes);
    let request = protocol::encode_share_request(900, 2, &payload);
    let decoded = protocol::decode_request(&request, 16 * 1024)?;
    let start = Instant::now();
    let mut codes = Vec::with_capacity(requests);
    for _ in 0..requests {
        let response = store.handle(decoded.operation, &decoded.payload);
        if response[6] != 0 || response[7] != 0 {
            continue;
        }
        let mut reader = Reader::new(&response[14..]);
        reader.message_version()?;
        let code = reader.string()?;
        codes.push(code);
    }
    let create_elapsed = start.elapsed();
    let start = Instant::now();
    for code in &codes {
        let _ = store.fetch(code);
    }
    let fetch_elapsed = start.elapsed();
    println!(
        "store_create_rps={} store_fetch_rps={} live={}",
        (codes.len() as f64 / create_elapsed.as_secs_f64()) as u64,
        (codes.len() as f64 / fetch_elapsed.as_secs_f64()) as u64,
        store.stats().live
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_routes_are_rebuilt_when_topology_members_join() {
        let temp = std::env::temp_dir().join(format!(
            "lockbox-share-topology-auto-routes-{}",
            unix_ms(SystemTime::now())
        ));
        fs::create_dir_all(&temp).unwrap();
        let config = ServerConfig {
            state_dir: temp.clone(),
            topology_token: Some("token".to_string()),
            topology_servers: vec![TopologyServer {
                id: 0,
                url: "http://share-0.example/v1/share".to_string(),
                status: ServerStatus::Active,
                last_seen_ms: None,
            }],
            ..ServerConfig::default()
        };
        let store = ShareStore::open(config.clone()).unwrap();

        let topology = store
            .register_topology_server(TopologyRegistration {
                cluster_id: config.cluster_id.clone(),
                server_id: 2,
                server_url: "http://share-2.example/v1/share".to_string(),
                status: ServerStatus::Active,
                security_token: "token".to_string(),
            })
            .unwrap();

        let route_map: std::collections::HashSet<_> = topology
            .routes
            .iter()
            .map(|route| (route.owner_id, route.primary_id, route.failover_ids.clone()))
            .collect();
        assert_eq!(route_map.len(), 2);
        assert!(route_map.contains(&(0, 0, vec![2])));
        assert!(route_map.contains(&(2, 2, vec![0])));

        assert_eq!(topology.servers.len(), 2);
        assert_eq!(store.topology().routes.len(), 2);

        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn outbox_reloads_only_unacked_events() {
        let path = std::env::temp_dir().join(format!(
            "lockbox-share-outbox-test-{}",
            unix_ms(SystemTime::now())
        ));
        append_outbox_event(&path, 1, b"one").unwrap();
        append_outbox_event(&path, 2, b"two").unwrap();
        append_outbox_ack(&path, 1).unwrap();

        let pending = load_outbox_pending(&path).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 2);
        assert_eq!(pending[0].1, b"two");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn status_document_includes_replication_files() {
        let state_dir = std::env::temp_dir().join(format!(
            "lockbox-share-status-test-{}",
            unix_ms(SystemTime::now())
        ));
        fs::create_dir_all(&state_dir).unwrap();
        let config = ServerConfig {
            state_dir: state_dir.clone(),
            replication_peer_urls: Vec::new(),
            ..ServerConfig::default()
        };
        let store = ShareStore::open(config).unwrap();
        store_replication_sequence(&state_dir.join("replication-origin-sequence"), 42).unwrap();
        append_outbox_event(&state_dir.join("replication-outbox.bin"), 42, b"event").unwrap();

        let status = store.status_document();
        assert_eq!(status.replication_last_sequence, 42);
        assert_eq!(status.replication_pending, 1);

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn replication_accepts_out_of_order_sequences() {
        let state_dir = std::env::temp_dir().join(format!(
            "lockbox-share-out-of-order-test-{}",
            unix_ms(SystemTime::now())
        ));
        let store = ShareStore::open(ServerConfig {
            state_dir: state_dir.clone(),
            promoted_owner_ids: vec![0],
            ..ServerConfig::default()
        })
        .unwrap();

        let second = replication_put_event(2, "00123456789002", "second");
        let first = replication_put_event(1, "00123456789001", "first");

        assert!(store.apply_replication_event(second.clone()).unwrap());
        assert!(store.apply_replication_event(first.clone()).unwrap());
        assert!(!store.apply_replication_event(second).unwrap());

        assert_eq!(store.stats().live, 2);
        assert!(store.fetch("00123456789001").is_ok());
        assert!(store.fetch("00123456789002").is_ok());

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn delete_token_hashes_are_stable_across_replica_secrets() {
        let state_a = std::env::temp_dir().join(format!(
            "lockbox-share-token-hash-a-{}",
            unix_ms(SystemTime::now())
        ));
        let state_b = std::env::temp_dir().join(format!(
            "lockbox-share-token-hash-b-{}",
            unix_ms(SystemTime::now())
        ));
        let store_a = ShareStore::open(ServerConfig {
            state_dir: state_a.clone(),
            ..ServerConfig::default()
        })
        .unwrap();
        let store_b = ShareStore::open(ServerConfig {
            state_dir: state_b.clone(),
            ..ServerConfig::default()
        })
        .unwrap();

        assert_ne!(store_a.secret, store_b.secret);
        assert_eq!(
            store_a.delete_token_hash(b"replicated-delete-token"),
            store_b.delete_token_hash(b"replicated-delete-token")
        );
        assert_ne!(
            store_a.code_hash("00123456789012"),
            store_b.code_hash("00123456789012")
        );

        let _ = fs::remove_dir_all(state_a);
        let _ = fs::remove_dir_all(state_b);
    }

    #[test]
    fn share_code_generation_rejects_persisted_bucket_collision() {
        let state_dir = temp_state_dir("persisted-collision");
        let store = ShareStore::open(ServerConfig {
            state_dir: state_dir.clone(),
            index_cache_entries: 0,
            ..ServerConfig::default()
        })
        .unwrap();
        let code = store.unique_code_from_value(0, 0, 123).unwrap().unwrap();
        let code_hash = store.code_hash(&code);
        let entry = ShareEntry {
            share_code: code,
            delete_token_hash: [7_u8; HASH_LEN],
            contact_email: None,
            payload_offset: 0,
            payload_len: 0,
            expires_at_ms: unix_ms(SystemTime::now()) + 60_000,
            max_fetches: 1,
            fetches: 0,
        };

        store.append_bucket_put(&code_hash, &entry).unwrap();

        assert!(store.unique_code_from_value(0, 0, 123).unwrap().is_none());
        let _ = fs::remove_dir_all(state_dir);
    }

    #[cfg(unix)]
    #[test]
    fn server_secret_file_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let state_dir = temp_state_dir("server-secret-private");
        fs::create_dir_all(&state_dir).unwrap();

        let _ = load_or_create_secret(&state_dir).unwrap();

        let mode = fs::metadata(state_dir.join("server.secret"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(state_dir);
    }

    #[cfg(unix)]
    #[test]
    fn existing_server_secret_file_is_restricted_on_load() {
        use std::os::unix::fs::PermissionsExt;

        let state_dir = temp_state_dir("server-secret-existing-private");
        fs::create_dir_all(&state_dir).unwrap();
        let path = state_dir.join("server.secret");
        fs::write(&path, [3_u8; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let secret = load_or_create_secret(&state_dir).unwrap();

        assert_eq!(secret, [3_u8; 32]);
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(state_dir);
    }

    fn temp_state_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lockbox-share-{label}-{}-{}",
            std::process::id(),
            unix_ms(SystemTime::now())
        ))
    }

    fn replication_put_event(sequence: u64, share_code: &str, label: &str) -> ReplicationEvent {
        ReplicationEvent {
            origin_server_id: 0,
            origin_epoch: 1,
            origin_sequence: sequence,
            kind: ReplicationEventKind::PutShare {
                share_code: share_code.to_string(),
                delete_token_hash: [sequence as u8; HASH_LEN].to_vec(),
                payload: payload::encode_contact_share(
                    &format!("{label}@example.com"),
                    b"public-key-material",
                    b"signing-public-key-material",
                    &[1_u8; 32],
                    &[2_u8; 24],
                    1,
                    2,
                ),
                contact_email: Some(format!("{label}@example.com")),
                expires_at_unix_ms: unix_ms(SystemTime::now()) + 60_000,
                max_fetches: 2,
                fetches: 0,
            },
        }
    }
}

fn benchmark_payload(target_bytes: usize) -> Vec<u8> {
    let key_len = target_bytes.saturating_sub(112).clamp(32, 4096);
    let public_key = vec![42_u8; key_len];
    payload::encode_contact_share(
        "bench@example.com",
        &public_key,
        b"signing-public-key-material",
        &[7_u8; 32],
        &[9_u8; 24],
        1,
        2,
    )
}
