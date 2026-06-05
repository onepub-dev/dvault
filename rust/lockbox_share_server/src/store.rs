use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use getrandom::getrandom;
use sha2::{Digest, Sha256};

use lockbox_share_protocol::client::{HttpTransport, Transport};
use lockbox_share_protocol::payload;
use lockbox_share_protocol::protocol::{self, Operation, Reader, Status};
use lockbox_share_protocol::{
    encode_replication_request, share_code_owner_id, sign_replication_event, ClusterTopology,
    ReplicationEvent, ReplicationEventKind, ReplicationRequest, ServerStatus, TopologyRoute,
    TopologyServer,
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

type RecordHash = [u8; HASH_LEN];

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
    pub share_code_digits: u8,
    pub compact_min_bytes: u64,
    pub index_cache_entries: usize,
    pub rate_limit_per_minute: u32,
    pub rate_limit_burst: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8089".to_string(),
            state_dir: PathBuf::from("/var/lib/lockbox-share-server"),
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
            share_code_digits: 12,
            compact_min_bytes: 64 * 1024 * 1024,
            index_cache_entries: 65_536,
            rate_limit_per_minute: 120,
            rate_limit_burst: 40,
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
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<protocol::ProtocolError> for StoreError {
    fn from(value: protocol::ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Clone)]
struct ShareEntry {
    share_code: String,
    delete_token_hash: RecordHash,
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
    secret: [u8; 32],
    bucket_dir: PathBuf,
    shards: Vec<Shard>,
    created: AtomicU64,
    fetched: AtomicU64,
    deleted: AtomicU64,
    expired: AtomicU64,
    misses: AtomicU64,
    live: AtomicUsize,
    replication_state: Mutex<HashMap<u8, (u64, u64)>>,
    replication_state_path: PathBuf,
    replication_tx: Option<mpsc::SyncSender<ReplicationEventKind>>,
    replication_outbox_path: PathBuf,
    replication_sequence_path: PathBuf,
}

pub struct CreatedShare {
    pub share_code: String,
    pub delete_token: Vec<u8>,
    pub expires_at_ms: u64,
    pub max_fetches: u16,
}

pub struct FetchedShare {
    pub payload: Vec<u8>,
    pub expires_at_ms: u64,
    pub remaining_fetches: u16,
}

impl ShareStore {
    pub fn open(mut config: ServerConfig) -> Result<Self, StoreError> {
        if config.developer_mode {
            config.state_dir = std::env::temp_dir().join("lockbox-share-server-dev");
        }
        if config.server_id > 9 {
            return Err(StoreError::Config(
                "server id must be a decimal digit from 0 to 9".to_string(),
            ));
        }
        fs::create_dir_all(&config.state_dir)?;
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
        Ok(Self {
            config,
            secret,
            bucket_dir,
            shards,
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
        })
    }

    pub fn handle(&self, operation: Operation, payload: &[u8]) -> Vec<u8> {
        match operation {
            Operation::Share => self.handle_share(payload),
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

    pub fn topology(&self) -> ClusterTopology {
        let servers = if self.config.topology_servers.is_empty() {
            vec![TopologyServer {
                id: self.config.server_id,
                url: self.public_share_url(),
                status: ServerStatus::Active,
            }]
        } else {
            self.config.topology_servers.clone()
        };
        let routes = if self.config.topology_routes.is_empty() {
            vec![TopologyRoute {
                owner_id: self.config.server_id,
                primary_id: self.config.server_id,
                failover_ids: Vec::new(),
            }]
        } else {
            self.config.topology_routes.clone()
        };
        ClusterTopology {
            cluster_id: self.config.cluster_id.clone(),
            version: self.config.topology_version,
            servers,
            routes,
        }
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

    fn handle_share(&self, payload: &[u8]) -> Vec<u8> {
        match self.create_from_payload(payload) {
            Ok(created) => {
                let mut body = Vec::new();
                protocol::put_u16(&mut body, protocol::MESSAGE_VERSION);
                protocol::put_string(&mut body, &created.share_code);
                protocol::put_bytes(&mut body, &created.delete_token);
                protocol::put_u64(&mut body, created.expires_at_ms);
                protocol::put_u16(&mut body, created.max_fetches);
                protocol::encode_response(Operation::Share, Status::Success, &body)
            }
            Err(err) => encode_store_error(Operation::Share, err),
        }
    }

    fn handle_fetch(&self, payload: &[u8]) -> Vec<u8> {
        let result = (|| {
            let mut reader = Reader::new(payload);
            reader.message_version()?;
            let code = reader.string()?;
            self.fetch(&code)
        })();
        match result {
            Ok(fetched) => {
                let mut body = Vec::new();
                protocol::put_u16(&mut body, protocol::MESSAGE_VERSION);
                protocol::put_bytes(&mut body, &fetched.payload);
                protocol::put_u64(&mut body, fetched.expires_at_ms);
                protocol::put_u16(&mut body, fetched.remaining_fetches);
                protocol::encode_response(Operation::Fetch, Status::Success, &body)
            }
            Err(err) => encode_store_error(Operation::Fetch, err),
        }
    }

    fn handle_delete(&self, payload: &[u8]) -> Vec<u8> {
        let result = (|| {
            let mut reader = Reader::new(payload);
            reader.message_version()?;
            let code = reader.string()?;
            let token = reader.bytes()?;
            self.delete(&code, &token)
        })();
        match result {
            Ok(deleted) => {
                let mut body = Vec::new();
                protocol::put_u16(&mut body, protocol::MESSAGE_VERSION);
                body.push(u8::from(deleted));
                protocol::encode_response(Operation::Delete, Status::Success, &body)
            }
            Err(err) => encode_store_error(Operation::Delete, err),
        }
    }

    fn handle_replication(&self, payload: &[u8]) -> Vec<u8> {
        match self.apply_replication_payload(payload) {
            Ok(_) => protocol::encode_response(Operation::Replicate, Status::Success, &[]),
            Err(StoreError::ReplicationUnauthorized) => protocol::encode_error(
                Operation::Replicate,
                Status::ReplicationUnauthorized,
                "replication unauthorized",
            ),
            Err(err) => encode_store_error(Operation::Replicate, err),
        }
    }

    pub fn create_from_payload(&self, payload: &[u8]) -> Result<CreatedShare, StoreError> {
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
        if share_payload.len() > self.config.max_payload_bytes {
            return Err(StoreError::PayloadTooLarge);
        }
        payload::validate_payload(&share_payload)
            .map_err(|err| StoreError::PayloadInvalid(err.to_string()))?;
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
            payload_offset: 0,
            payload_len: share_payload.len() as u32,
            expires_at_ms,
            max_fetches,
            fetches: 0,
        };
        let shard_id = self.shard_for(&code_hash);
        let shard = &self.shards[shard_id];
        let mut index = shard.index.lock().unwrap();
        let (payload_offset, payload_len) = append_put(
            &mut shard.file.lock().unwrap(),
            &code_hash,
            &entry,
            &share_payload,
        )?;
        entry.payload_offset = payload_offset;
        entry.payload_len = payload_len;
        self.append_bucket_put(&code_hash, &entry)?;
        if index.len() < self.config.index_cache_entries / self.shards.len().max(1) {
            index.insert(code_hash, entry);
        }
        shard
            .expiry_buckets
            .lock()
            .unwrap()
            .push_back((expires_at_ms, vec![(code_hash, share_code.clone())]));
        self.created.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_add(1, Ordering::Relaxed);
        self.enqueue_replication(ReplicationEventKind::PutShare {
            share_code: share_code.clone(),
            delete_token_hash: delete_token_hash.to_vec(),
            payload: share_payload,
            expires_at_unix_ms: expires_at_ms,
            max_fetches,
            fetches: 0,
        });
        Ok(CreatedShare {
            share_code,
            delete_token,
            expires_at_ms,
            max_fetches,
        })
    }

    pub fn fetch(&self, share_code: &str) -> Result<FetchedShare, StoreError> {
        if !self.can_serve_share_code(share_code) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Err(StoreError::NotFound);
        }
        let code_hash = self.code_hash(share_code);
        let shard = &self.shards[self.shard_for(&code_hash)];
        let mut index = shard.index.lock().unwrap();
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
            append_tombstone(&mut shard.file.lock().unwrap(), &code_hash)?;
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
            append_tombstone(&mut shard.file.lock().unwrap(), &code_hash)?;
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
        let mut file = shard.file.lock().unwrap();
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
        self.fetched.fetch_add(1, Ordering::Relaxed);
        Ok(FetchedShare {
            payload,
            expires_at_ms,
            remaining_fetches: remaining,
        })
    }

    pub fn delete(&self, share_code: &str, delete_token: &[u8]) -> Result<bool, StoreError> {
        if !self.can_serve_share_code(share_code) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        let code_hash = self.code_hash(share_code);
        let token_hash = self.delete_token_hash(delete_token);
        let shard = &self.shards[self.shard_for(&code_hash)];
        let mut index = shard.index.lock().unwrap();
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
        append_tombstone(&mut shard.file.lock().unwrap(), &code_hash)?;
        self.append_bucket_tombstone(&code_hash)?;
        self.deleted.fetch_add(1, Ordering::Relaxed);
        self.live.fetch_sub(1, Ordering::Relaxed);
        self.enqueue_replication(ReplicationEventKind::Tombstone {
            share_code: share_code.to_string(),
        });
        Ok(true)
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
                expires_at_unix_ms,
                max_fetches,
                fetches,
            } => self.apply_replica_put(
                &share_code,
                &delete_token_hash,
                &payload,
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
        let mut state = self.replication_state.lock().unwrap();
        if let Some((last_epoch, last_sequence)) = state.get(&origin) {
            if epoch < *last_epoch || (epoch == *last_epoch && sequence <= *last_sequence) {
                return Ok(false);
            }
        }
        append_replication_state(&self.replication_state_path, origin, epoch, sequence)?;
        state.insert(origin, (epoch, sequence));
        Ok(true)
    }

    fn apply_replica_put(
        &self,
        share_code: &str,
        delete_token_hash: &[u8],
        payload: &[u8],
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
        let code_hash = self.code_hash(share_code);
        let shard = &self.shards[self.shard_for(&code_hash)];
        let mut entry = ShareEntry {
            share_code: share_code.to_string(),
            delete_token_hash: token_hash,
            payload_offset: 0,
            payload_len: payload.len() as u32,
            expires_at_ms,
            max_fetches,
            fetches,
        };
        let mut index = shard.index.lock().unwrap();
        let existed = index.contains_key(&code_hash) || self.lookup_bucket(&code_hash)?.is_some();
        let (payload_offset, payload_len) =
            append_put(&mut shard.file.lock().unwrap(), &code_hash, &entry, payload)?;
        entry.payload_offset = payload_offset;
        entry.payload_len = payload_len;
        self.append_bucket_put(&code_hash, &entry)?;
        if index.len() < self.config.index_cache_entries / self.shards.len().max(1) {
            index.insert(code_hash, entry);
        }
        if !existed {
            self.live.fetch_add(1, Ordering::Relaxed);
        }
        shard
            .expiry_buckets
            .lock()
            .unwrap()
            .push_back((expires_at_ms, vec![(code_hash, share_code.to_string())]));
        Ok(())
    }

    fn apply_replica_fetch_count(&self, share_code: &str, fetches: u16) -> Result<(), StoreError> {
        let code_hash = self.code_hash(share_code);
        let shard = &self.shards[self.shard_for(&code_hash)];
        if self.lookup_bucket(&code_hash)?.is_some() {
            if let Some(cached) = shard.index.lock().unwrap().get_mut(&code_hash) {
                cached.fetches = fetches;
            }
        }
        append_fetch_count(&mut shard.file.lock().unwrap(), &code_hash, fetches)?;
        self.append_bucket_fetch_count(&code_hash, fetches)?;
        Ok(())
    }

    fn apply_replica_tombstone(&self, share_code: &str) -> Result<(), StoreError> {
        let code_hash = self.code_hash(share_code);
        let shard = &self.shards[self.shard_for(&code_hash)];
        let removed = shard.index.lock().unwrap().remove(&code_hash).is_some()
            || self.lookup_bucket(&code_hash)?.is_some();
        append_tombstone(&mut shard.file.lock().unwrap(), &code_hash)?;
        self.append_bucket_tombstone(&code_hash)?;
        if removed {
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn can_serve_share_code(&self, share_code: &str) -> bool {
        let Some(owner_id) = share_code_owner_id(share_code) else {
            return false;
        };
        owner_id == self.config.server_id || self.config.promoted_owner_ids.contains(&owner_id)
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
                let mut buckets = shard.expiry_buckets.lock().unwrap();
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
            let mut index = shard.index.lock().unwrap();
            let mut file = shard.file.lock().unwrap();
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

    pub fn status_document(&self) -> lockbox_share_protocol::ShareServerStatus {
        let stats = self.stats();
        lockbox_share_protocol::ShareServerStatus {
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
            let snapshot = shard
                .index
                .lock()
                .unwrap()
                .iter()
                .map(|(hash, entry)| (*hash, entry.clone()))
                .collect::<Vec<_>>();
            if snapshot.is_empty() {
                continue;
            }
            let mut file = shard.file.lock().unwrap();
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
                if send_replication_request(&[peer_url.to_string()], &request) {
                    append_outbox_ack(&self.replication_outbox_path, sequence)?;
                    sent += 1;
                } else {
                    return Err(StoreError::Io(std::io::Error::other(format!(
                        "replication peer {peer_url} did not accept resync event {sequence}"
                    ))));
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
                let index = shard.index.lock().unwrap();
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

    fn generate_unique_code(&self) -> Result<String, StoreError> {
        let digits = self.config.share_code_digits.clamp(6, 12) as usize;
        let space = 10_u64.pow(digits as u32);
        for _ in 0..100 {
            let mut random = [0_u8; 8];
            getrandom(&mut random)
                .map_err(|err| StoreError::Io(std::io::Error::other(err.to_string())))?;
            let value = u64::from_be_bytes(random) % space;
            let code = format!("{}{value:0digits$}", self.config.server_id);
            let hash = self.code_hash(&code);
            let shard = &self.shards[self.shard_for(&hash)];
            if !shard.index.lock().unwrap().contains_key(&hash) {
                return Ok(code);
            }
        }
        Err(StoreError::Io(std::io::Error::other(
            "unable to allocate unique share code",
        )))
    }

    fn code_hash(&self, code: &str) -> RecordHash {
        keyed_hash(&self.secret, b"share-code", code.as_bytes())
    }

    fn delete_token_hash(&self, token: &[u8]) -> RecordHash {
        keyed_hash(&self.secret, b"delete-token", token)
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

fn encode_store_error(operation: Operation, err: StoreError) -> Vec<u8> {
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
        StoreError::Io(_) => Status::StoreUnavailable,
    };
    protocol::encode_error(operation, status, &err.to_string())
}

fn load_or_create_secret(state_dir: &std::path::Path) -> Result<[u8; 32], StoreError> {
    let path = state_dir.join("server.secret");
    if path.exists() {
        let mut bytes = fs::read(path)?;
        if bytes.len() < 32 {
            return Err(StoreError::Io(std::io::Error::other(
                "server secret is too short",
            )));
        }
        bytes.truncate(32);
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(&bytes);
        return Ok(secret);
    }
    let mut secret = [0_u8; 32];
    getrandom(&mut secret).map_err(|err| StoreError::Io(std::io::Error::other(err.to_string())))?;
    fs::write(path, secret)?;
    Ok(secret)
}

fn load_replication_state(path: &Path) -> Result<HashMap<u8, (u64, u64)>, StoreError> {
    let mut state = HashMap::new();
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(state),
        Err(err) => return Err(StoreError::Io(err)),
    };
    for record in bytes.chunks_exact(17) {
        let origin = record[0];
        let epoch = u64::from_be_bytes([
            record[1], record[2], record[3], record[4], record[5], record[6], record[7], record[8],
        ]);
        let sequence = u64::from_be_bytes([
            record[9], record[10], record[11], record[12], record[13], record[14], record[15],
            record[16],
        ]);
        let entry = state.entry(origin).or_insert((epoch, sequence));
        if epoch > entry.0 || (epoch == entry.0 && sequence > entry.1) {
            *entry = (epoch, sequence);
        }
    }
    Ok(state)
}

fn append_replication_state(
    path: &Path,
    origin: u8,
    epoch: u64,
    sequence: u64,
) -> Result<(), StoreError> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&[origin])?;
    file.write_all(&epoch.to_be_bytes())?;
    file.write_all(&sequence.to_be_bytes())?;
    Ok(())
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
                eprintln!("replication outbox load failed: {err}");
                VecDeque::new()
            });
            loop {
                retry_pending_outbox(&outbox_path, &peer_urls, &mut pending);
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(kind) => {
                        sequence = sequence.saturating_add(1);
                        if let Err(err) = store_replication_sequence(&sequence_path, sequence) {
                            eprintln!("replication sequence persist failed: {err}");
                            continue;
                        }
                        let event = ReplicationEvent {
                            origin_server_id,
                            origin_epoch,
                            origin_sequence: sequence,
                            kind,
                        };
                        let request = encode_replication_request(&ReplicationRequest {
                            authentication: sign_replication_event(token.as_bytes(), &event),
                            event,
                        });
                        if let Err(err) = append_outbox_event(&outbox_path, sequence, &request) {
                            eprintln!("replication outbox append failed: {err}");
                            continue;
                        }
                        pending.push_back((sequence, request));
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .ok()?;
    Some(tx)
}

fn retry_pending_outbox(
    outbox_path: &Path,
    peer_urls: &[String],
    pending: &mut VecDeque<(u64, Vec<u8>)>,
) {
    let mut remaining = VecDeque::new();
    while let Some((sequence, request)) = pending.pop_front() {
        if send_replication_request(peer_urls, &request) {
            if let Err(err) = append_outbox_ack(outbox_path, sequence) {
                eprintln!("replication outbox ack failed: {err}");
                remaining.push_back((sequence, request));
            }
        } else {
            remaining.push_back((sequence, request));
        }
    }
    *pending = remaining;
}

fn send_replication_request(peer_urls: &[String], request: &[u8]) -> bool {
    let mut all_ok = true;
    for peer_url in peer_urls {
        match HttpTransport::new(peer_url).and_then(|transport| {
            let response = transport.post_binary(request)?;
            protocol::decode_response(&response, 1024)
                .map_err(lockbox_share_protocol::ClientError::from)
        }) {
            Ok(response) if response.status == Status::Success => {}
            Ok(response) => {
                all_ok = false;
                eprintln!("replication peer {peer_url} returned {:?}", response.status)
            }
            Err(err) => {
                all_ok = false;
                eprintln!("replication peer {peer_url} failed: {err}");
            }
        }
    }
    all_ok
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
                if expires_at_ms > now_ms {
                    index.insert(
                        code_hash,
                        ShareEntry {
                            share_code: share_code.to_string(),
                            delete_token_hash,
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
    let mut index = shard.index.lock().unwrap();
    let mut file = shard.file.lock().unwrap();

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
}

fn benchmark_payload(target_bytes: usize) -> Vec<u8> {
    let key_len = target_bytes.saturating_sub(112).clamp(32, 4096);
    let public_key = vec![42_u8; key_len];
    payload::encode_contact_share(
        "bench@example.com",
        &public_key,
        &[7_u8; 32],
        &[9_u8; 24],
        1,
        2,
    )
}
