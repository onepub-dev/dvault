use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::payload::{self, PayloadType};
use crate::protocol::{self, Operation, ProtocolError, Status};
use crate::topology::{self, build_ring_routes, ClusterTopology, TopologyRoute, TopologyServer};

const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024;
const DEFAULT_RETRY_ATTEMPTS: usize = 3;
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(10);
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_millis(100);
const REQUEST_TOPOLOGY_HEADER: &str = "x-topology-version";
const DEFAULT_TOPOLOGY_TTL_MS: u64 = 60_000;

#[derive(Clone, Debug)]
pub struct ShareClient<T = HttpTransport> {
    transport: T,
    max_response_bytes: usize,
    retry_policy: RetryPolicy,
}

#[derive(Clone, Debug)]
pub struct ShareClientPool<T = HttpTransport> {
    state: Arc<Mutex<ShareTopologyState<T>>>,
}

#[derive(Clone, Debug)]
struct ShareTopologyState<T> {
    clients: Vec<ShareClient<T>>,
    server_ids: Vec<u8>,
    topology: Option<ClusterTopology>,
    routes: Vec<TopologyRoute>,
    topology_version: u64,
    topology_server_urls: Vec<String>,
    topology_ttl_ms: u64,
    topology_refreshed_ms: u64,
}

#[derive(Clone, Debug)]
pub struct TopologyAwareResponse<R> {
    pub value: R,
    pub topology: Option<ClusterTopology>,
}

#[derive(Clone, Debug)]
struct TopologyStateSnapshot<T> {
    clients: Vec<ShareClient<T>>,
    server_ids: Vec<u8>,
    routes: Vec<TopologyRoute>,
    topology: Option<ClusterTopology>,
    topology_version: u64,
    topology_server_urls: Vec<String>,
    topology_ttl_ms: u64,
    topology_refreshed_ms: u64,
}

impl<T: Clone> ShareTopologyState<T> {
    fn snapshot(&self) -> TopologyStateSnapshot<T> {
        TopologyStateSnapshot {
            clients: self.clients.clone(),
            server_ids: self.server_ids.clone(),
            routes: self.routes.clone(),
            topology: self.topology.clone(),
            topology_version: self.topology_version,
            topology_server_urls: self.topology_server_urls.clone(),
            topology_ttl_ms: self.topology_ttl_ms,
            topology_refreshed_ms: self.topology_refreshed_ms,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpTransport {
    endpoint: Endpoint,
    timeout: Duration,
}

#[derive(Clone, Debug)]
struct Endpoint {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

#[derive(Clone, Copy, Debug)]
struct RetryPolicy {
    attempts: usize,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: DEFAULT_RETRY_ATTEMPTS,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
    Http,
    Https,
}

#[derive(Clone, Debug)]
pub struct ShareResult {
    pub share_code: String,
    pub delete_token: Vec<u8>,
    pub expires_at_unix_ms: u64,
    pub max_fetches: u16,
    pub verification_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FetchedShare {
    pub payload: Vec<u8>,
    pub payload_type: PayloadType,
    pub expires_at_unix_ms: u64,
    pub remaining_fetches: u16,
    pub email_verification: Option<protocol::EmailVerification>,
}

pub trait Transport: Clone {
    fn post_binary(&self, body: &[u8]) -> Result<Vec<u8>, ClientError>;

    fn get_topology(_url: &str) -> Option<Vec<u8>> {
        None
    }

    fn from_url(_url: &str) -> Option<Self> {
        None
    }

    fn post_binary_with_topology(
        &self,
        body: &[u8],
        topology_version: Option<u64>,
    ) -> Result<Vec<u8>, ClientError> {
        if topology_version.is_some() {
            self.post_binary_with_header(body, topology_version)
        } else {
            self.post_binary(body)
        }
    }

    fn post_binary_with_header(
        &self,
        body: &[u8],
        topology_version: Option<u64>,
    ) -> Result<Vec<u8>, ClientError> {
        let _ = topology_version;
        self.post_binary(body)
    }
}

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Url(String),
    Http(String),
    Protocol(ProtocolError),
    Payload(payload::PayloadError),
    Topology(String),
    Replication(String),
    Server {
        status: Status,
        message: String,
    },
    UnexpectedOperation {
        expected: Operation,
        actual: Operation,
    },
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Url(err) => write!(f, "invalid key server url: {err}"),
            Self::Http(err) => write!(f, "http error: {err}"),
            Self::Protocol(err) => write!(f, "protocol error: {err}"),
            Self::Payload(err) => write!(f, "payload error: {err}"),
            Self::Topology(err) => write!(f, "topology error: {err}"),
            Self::Replication(err) => write!(f, "replication error: {err}"),
            Self::Server { status, message } => write!(f, "server returned {status:?}: {message}"),
            Self::UnexpectedOperation { expected, actual } => {
                write!(f, "expected {expected:?} response, got {actual:?}")
            }
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ProtocolError> for ClientError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<payload::PayloadError> for ClientError {
    fn from(value: payload::PayloadError) -> Self {
        Self::Payload(value)
    }
}

impl ShareClient<HttpTransport> {
    pub fn new(server_url: &str) -> Result<Self, ClientError> {
        Ok(Self {
            transport: HttpTransport::new(server_url)?,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            retry_policy: RetryPolicy::default(),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.transport.timeout = timeout;
        self
    }
}

impl ShareClientPool<HttpTransport> {
    pub fn new<I, S>(server_urls: I) -> Result<Self, ClientError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut clients = Vec::new();
        for url in server_urls {
            clients.push(ShareClient::new(url.as_ref())?);
        }
        Self::from_clients(clients)
    }

    pub fn with_timeout(self, timeout: Duration) -> Self {
        {
            let mut state = self.state.lock().unwrap();
            for client in &mut state.clients {
                client.transport.timeout = timeout;
            }
        }
        self
    }

    pub fn with_retry_policy(
        self,
        attempts: usize,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> Self {
        {
            let mut state = self.state.lock().unwrap();
            for client in &mut state.clients {
                client.retry_policy = RetryPolicy {
                    attempts: attempts.max(1),
                    initial_backoff,
                    max_backoff,
                };
            }
        }
        self
    }

    pub fn from_topology(topology: &ClusterTopology) -> Result<Self, ClientError> {
        topology.validate()?;
        let topology = dedupe_topology(topology.clone());
        let mut clients = Vec::new();
        let mut server_ids = Vec::new();
        for server in &topology.servers {
            clients.push(ShareClient::new(&server.url)?);
            server_ids.push(server.id);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(ShareTopologyState {
                clients,
                server_ids,
                topology: Some(topology.clone()),
                routes: topology.routes.clone(),
                topology_version: topology.version,
                topology_server_urls: topology_urls_from_servers(&topology.servers),
                topology_ttl_ms: DEFAULT_TOPOLOGY_TTL_MS,
                topology_refreshed_ms: unix_ms_now(),
            })),
        })
    }

    pub fn discover(topology_url: &str) -> Result<Self, ClientError> {
        let bytes = HttpTransport::get_topology(topology_url).ok_or_else(|| {
            ClientError::Topology(format!("topology discovery failed for {topology_url}"))
        })?;
        let topology = topology::decode_topology(&bytes)?;
        let pool = Self::from_topology(&topology)?;
        {
            let mut state = pool.state.lock().unwrap();
            let mut topology_server_urls = topology_urls_from_servers(&topology.servers);
            if let Some(topology_url) = topology_url_from_share_url(topology_url) {
                topology_server_urls.push(topology_url);
            }
            state.topology_server_urls = dedupe_urls(topology_server_urls);
            state.topology_refreshed_ms = unix_ms_now();
        }
        Ok(pool)
    }
}

impl<T: Transport> ShareClientPool<T> {
    pub fn from_clients(clients: Vec<ShareClient<T>>) -> Result<Self, ClientError> {
        let server_ids = (0..clients.len())
            .map(|index| index as u8)
            .collect::<Vec<_>>();
        Self::from_clients_with_ids(clients, server_ids, Vec::new())
    }

    pub fn from_clients_with_ids(
        clients: Vec<ShareClient<T>>,
        server_ids: Vec<u8>,
        routes: Vec<TopologyRoute>,
    ) -> Result<Self, ClientError> {
        if clients.is_empty() {
            return Err(ClientError::Url(
                "at least one key server url is required".to_string(),
            ));
        }
        if clients.len() != server_ids.len() {
            return Err(ClientError::Topology(
                "client and server id counts differ".to_string(),
            ));
        }
        for server_id in &server_ids {
            if *server_id >= 36 {
                return Err(ClientError::Topology(format!(
                    "server id must be an index 0..35 (0..9, a..z): {server_id}"
                )));
            }
        }
        let routes = if routes.is_empty() {
            fallback_routes(&server_ids)
        } else {
            routes
        };
        Ok(Self {
            state: Arc::new(Mutex::new(ShareTopologyState {
                clients,
                server_ids,
                routes,
                topology: None,
                topology_version: 0,
                topology_server_urls: Vec::new(),
                topology_ttl_ms: DEFAULT_TOPOLOGY_TTL_MS,
                topology_refreshed_ms: 0,
            })),
        })
    }

    pub fn from_transports(transports: Vec<T>) -> Result<Self, ClientError> {
        let clients = transports
            .into_iter()
            .map(ShareClient::from_transport)
            .collect::<Vec<_>>();
        Self::from_clients(clients)
    }

    pub fn with_max_response_bytes(self, max_response_bytes: usize) -> Self {
        {
            let mut state = self.state.lock().unwrap();
            for client in &mut state.clients {
                client.max_response_bytes = max_response_bytes;
            }
        }
        self
    }

    pub fn share_payload(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        payload: &[u8],
    ) -> Result<ShareResult, ClientError> {
        self.share_payload_with_email(ttl_seconds, max_fetches, payload, None)
    }

    pub fn share_payload_with_email(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        payload: &[u8],
        verification_email: Option<&str>,
    ) -> Result<ShareResult, ClientError> {
        self.try_clients_from(
            self.selection_offset(),
            |client, topology_version| {
                client.share_payload_with_email_with_version(
                    ttl_seconds,
                    max_fetches,
                    payload,
                    verification_email,
                    topology_version,
                )
            },
            retry_share_error,
        )
    }

    pub fn share_contact(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        contact: ContactShare<'_>,
    ) -> Result<ShareResult, ClientError> {
        let payload = payload::encode_contact_share(
            contact.identity,
            contact.public_key,
            contact.signing_public_key,
            contact.fingerprint,
            contact.share_nonce,
            contact.created_at_unix_ms,
            contact.expires_at_unix_ms,
        );
        self.share_payload_with_email(
            ttl_seconds,
            max_fetches,
            &payload,
            contact.verification_email,
        )
    }

    pub fn fetch(&self, share_code: &str) -> Result<FetchedShare, ClientError> {
        self.try_clients_for_code(
            share_code,
            |client, topology_version| client.fetch_with_version(share_code, topology_version),
            retry_fetch_or_delete_error,
        )
    }

    pub fn delete(&self, share_code: &str, delete_token: &[u8]) -> Result<bool, ClientError> {
        let snapshot = self.snapshot();
        if snapshot.clients.is_empty() {
            return Err(ClientError::Url(
                "at least one key server url is required".to_string(),
            ));
        }
        let mut snapshot = self.discover_topology_if_stale(&snapshot);
        let mut last_error = None;
        for _ in 0..2 {
            let topology_version = snapshot.topology_version.if_version_for_request();
            let clients = self.clients_for_code(share_code, &snapshot);
            for client in clients {
                match client.delete_with_version(share_code, delete_token, topology_version) {
                    Ok(response) => {
                        if let Some(topology) = response.topology {
                            let _ = self.apply_topology_update(topology);
                        }
                        if response.value {
                            return Ok(true);
                        }
                        last_error = Some(ClientError::Server {
                            status: Status::ShareNotFound,
                            message: "delete not performed on this server".to_string(),
                        });
                    }
                    Err(err) if retry_fetch_or_delete_error(&err) => {
                        last_error = Some(err);
                    }
                    Err(err) => return Err(err),
                }
            }
            let current = self.snapshot();
            if !self.refresh_topology_from_peers(&current) {
                break;
            }
            snapshot = self.snapshot();
        }
        match last_error {
            Some(ClientError::Server {
                status: Status::ShareNotFound,
                ..
            }) => Ok(false),
            Some(err) => Err(err),
            None => Ok(false),
        }
    }

    fn try_clients_from<R>(
        &self,
        start: usize,
        mut call: impl FnMut(
            &ShareClient<T>,
            Option<u64>,
        ) -> Result<TopologyAwareResponse<R>, ClientError>,
        retry: impl Fn(&ClientError) -> bool,
    ) -> Result<R, ClientError> {
        let snapshot = self.snapshot();
        if snapshot.clients.is_empty() {
            return Err(ClientError::Url(
                "at least one key server url is required".to_string(),
            ));
        }
        let mut snapshot = self.discover_topology_if_stale(&snapshot);
        let mut last_error = None;
        for _ in 0..2 {
            let topology_version = snapshot.topology_version.if_version_for_request();
            let clients = snapshot.clients.clone();
            for offset in 0..clients.len() {
                let index = (start + offset) % clients.len();
                match call(&clients[index], topology_version) {
                    Ok(response) => {
                        if let Some(topology) = response.topology {
                            let _ = self.apply_topology_update(topology);
                        }
                        return Ok(response.value);
                    }
                    Err(err) if retry(&err) => last_error = Some(err),
                    Err(err) => return Err(err),
                }
            }
            let current = self.snapshot();
            if !self.refresh_topology_from_peers(&current) {
                break;
            }
            snapshot = self.snapshot();
        }
        Err(last_error.unwrap_or_else(|| {
            ClientError::Url("at least one key server url is required".to_string())
        }))
    }

    fn selection_offset(&self) -> usize {
        let snapshot = self.snapshot();
        if snapshot.clients.len() <= 1 {
            return 0;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos() as usize % snapshot.clients.len())
            .unwrap_or(0)
    }

    fn try_clients_for_code<R>(
        &self,
        share_code: &str,
        mut call: impl FnMut(
            &ShareClient<T>,
            Option<u64>,
        ) -> Result<TopologyAwareResponse<R>, ClientError>,
        retry: impl Fn(&ClientError) -> bool,
    ) -> Result<R, ClientError> {
        let snapshot = self.snapshot();
        if snapshot.clients.is_empty() {
            return Err(ClientError::Url(
                "at least one key server url is required".to_string(),
            ));
        }
        let mut snapshot = self.discover_topology_if_stale(&snapshot);
        let mut last_error = None;
        for _ in 0..2 {
            let topology_version = snapshot.topology_version.if_version_for_request();
            let clients = self.clients_for_code(share_code, &snapshot);
            for client in clients {
                match call(&client, topology_version) {
                    Ok(response) => {
                        if let Some(topology) = response.topology {
                            let _ = self.apply_topology_update(topology);
                        }
                        return Ok(response.value);
                    }
                    Err(err) if retry(&err) => last_error = Some(err),
                    Err(err) => return Err(err),
                }
            }
            let current = self.snapshot();
            if !self.refresh_topology_from_peers(&current) {
                break;
            }
            snapshot = self.snapshot();
        }
        Err(last_error.unwrap_or_else(|| {
            ClientError::Url("at least one key server url is required".to_string())
        }))
    }

    fn snapshot(&self) -> TopologyStateSnapshot<T> {
        self.state.lock().unwrap().snapshot()
    }

    fn clients_for_code(
        &self,
        share_code: &str,
        snapshot: &TopologyStateSnapshot<T>,
    ) -> Vec<ShareClient<T>> {
        let mut preferred_ids = Vec::new();
        if let Some((owner_id, secondary_id)) = topology::share_code_locator(share_code) {
            if let Some(route) = snapshot
                .routes
                .iter()
                .find(|route| route.owner_id == owner_id)
            {
                preferred_ids.push(route.primary_id);
                preferred_ids.extend(route.failover_ids.iter().copied());
            }
            if preferred_ids.is_empty() {
                preferred_ids.push(owner_id);
                if secondary_id != owner_id {
                    preferred_ids.push(secondary_id);
                }
            }
        }
        let mut selected = HashSet::new();
        let mut out = Vec::with_capacity(snapshot.clients.len());
        for preferred_id in preferred_ids {
            if let Some((index, _)) = snapshot
                .server_ids
                .iter()
                .enumerate()
                .find(|(_, server_id)| **server_id == preferred_id)
            {
                if selected.insert(snapshot.server_ids[index]) {
                    out.push(snapshot.clients[index].clone());
                }
            }
        }
        for index in 0..snapshot.clients.len() {
            let server_id = snapshot.server_ids[index];
            if selected.insert(server_id) {
                out.push(snapshot.clients[index].clone());
            }
        }
        out
    }

    fn apply_topology_update(&self, topology: ClusterTopology) -> Result<(), ClientError> {
        let topology = dedupe_topology(topology);
        let mut state = self.state.lock().unwrap();
        if topology.version != 0 {
            if topology.version <= state.topology_version {
                return Ok(());
            }
        }
        if state
            .topology
            .as_ref()
            .is_some_and(|current| current.version >= topology.version)
            && topology.version != 0
        {
            return Ok(());
        }
        let stale_filter_ms = state.topology_ttl_ms;
        let topology = if stale_filter_ms > 0 {
            let filtered_topology = topology.with_filtered_stale_servers(stale_filter_ms);
            if filtered_topology.servers.is_empty() {
                topology
            } else {
                filtered_topology
            }
        } else {
            topology
        };
        let topology_version = topology.version;
        let routes = if topology.routes.is_empty() {
            build_ring_routes(&topology.servers)
        } else {
            topology.routes.clone()
        };
        let mut clients = Vec::new();
        let mut server_ids = Vec::new();
        for server in &topology.servers {
            if let Some(transport) = T::from_url(&server.url) {
                let mut client = ShareClient::from_transport(transport);
                if let Some(previous) = state.clients.first() {
                    client.max_response_bytes = previous.max_response_bytes;
                    client.retry_policy = previous.retry_policy;
                }
                clients.push(client);
                server_ids.push(server.id);
            }
        }
        if clients.is_empty() {
            return Err(ClientError::Topology(
                "topology update yielded no reachable key servers".to_string(),
            ));
        }
        state.clients = clients;
        state.server_ids = server_ids;
        state.routes = routes;
        state.topology = Some(topology);
        state.topology_version = topology_version;
        state.topology_refreshed_ms = unix_ms_now();
        Ok(())
    }

    fn is_topology_stale(&self, snapshot: &TopologyStateSnapshot<T>) -> bool {
        if snapshot.topology.is_none() || snapshot.topology_refreshed_ms == 0 {
            return false;
        }
        if snapshot.topology_ttl_ms == 0 {
            return false;
        }
        let now = unix_ms_now();
        now.saturating_sub(snapshot.topology_refreshed_ms) > snapshot.topology_ttl_ms
    }

    fn refresh_topology_from_peers(&self, snapshot: &TopologyStateSnapshot<T>) -> bool {
        for topology_url in &snapshot.topology_server_urls {
            let Some(bytes) = T::get_topology(topology_url) else {
                continue;
            };
            match topology::decode_topology(&bytes) {
                Ok(topology) => {
                    if self.apply_topology_update(topology).is_ok() {
                        return true;
                    }
                }
                Err(_) => continue,
            }
        }
        false
    }

    fn discover_topology_if_stale(
        &self,
        snapshot: &TopologyStateSnapshot<T>,
    ) -> TopologyStateSnapshot<T> {
        if !snapshot.topology.is_some() {
            return snapshot.clone();
        }
        if !self.is_topology_stale(snapshot) {
            return snapshot.clone();
        }
        if self.refresh_topology_from_peers(snapshot) {
            return self.snapshot();
        }
        snapshot.clone()
    }
}

trait TopologyVersionExt {
    fn if_version_for_request(&self) -> Option<u64>;
}

impl TopologyVersionExt for u64 {
    fn if_version_for_request(&self) -> Option<u64> {
        if *self == 0 {
            None
        } else {
            Some(*self)
        }
    }
}

impl<T: Transport> ShareClient<T> {
    pub fn from_transport(transport: T) -> Self {
        Self {
            transport,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            retry_policy: RetryPolicy::default(),
        }
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    pub fn with_retry_policy(
        mut self,
        attempts: usize,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> Self {
        self.retry_policy = RetryPolicy {
            attempts: attempts.max(1),
            initial_backoff,
            max_backoff,
        };
        self
    }

    pub fn share_payload(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        payload: &[u8],
    ) -> Result<ShareResult, ClientError> {
        self.share_payload_with_email(ttl_seconds, max_fetches, payload, None)
    }

    pub fn share_payload_with_email(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        payload: &[u8],
        verification_email: Option<&str>,
    ) -> Result<ShareResult, ClientError> {
        Ok(self
            .share_payload_with_email_with_version(
                ttl_seconds,
                max_fetches,
                payload,
                verification_email,
                None,
            )?
            .value)
    }

    pub fn share_payload_with_email_with_version(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        payload: &[u8],
        verification_email: Option<&str>,
        topology_version: Option<u64>,
    ) -> Result<TopologyAwareResponse<ShareResult>, ClientError> {
        payload::validate_payload(payload)?;
        let body = protocol::encode_share_request_with_email(
            ttl_seconds,
            max_fetches,
            payload,
            verification_email,
        );
        let response = self.request_with_retry(
            Operation::Share,
            &body,
            topology_version,
            retry_single_client_error,
        )?;
        let decoded = protocol::decode_share_response_document(&response.value.payload)?;
        Ok(TopologyAwareResponse {
            value: ShareResult {
                share_code: decoded.share_code,
                delete_token: decoded.delete_token,
                expires_at_unix_ms: decoded.expires_at_unix_ms,
                max_fetches: decoded.max_fetches,
                verification_url: decoded.verification_url,
            },
            topology: response.topology,
        })
    }

    pub fn share_contact(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        contact: ContactShare<'_>,
    ) -> Result<ShareResult, ClientError> {
        let payload = payload::encode_contact_share(
            contact.identity,
            contact.public_key,
            contact.signing_public_key,
            contact.fingerprint,
            contact.share_nonce,
            contact.created_at_unix_ms,
            contact.expires_at_unix_ms,
        );
        self.share_payload_with_email(
            ttl_seconds,
            max_fetches,
            &payload,
            contact.verification_email,
        )
    }

    pub fn fetch(&self, share_code: &str) -> Result<FetchedShare, ClientError> {
        Ok(self.fetch_with_version(share_code, None)?.value)
    }

    pub fn fetch_with_version(
        &self,
        share_code: &str,
        topology_version: Option<u64>,
    ) -> Result<TopologyAwareResponse<FetchedShare>, ClientError> {
        let body = protocol::encode_fetch_request(share_code);
        let response = self.request_with_retry(
            Operation::Fetch,
            &body,
            topology_version,
            retry_single_client_error,
        )?;
        let decoded = protocol::decode_fetch_response_document(&response.value.payload)?;
        let payload_type = payload::validate_payload(&decoded.share_payload)?;
        Ok(TopologyAwareResponse {
            value: FetchedShare {
                payload: decoded.share_payload,
                payload_type,
                expires_at_unix_ms: decoded.expires_at_unix_ms,
                remaining_fetches: decoded.remaining_fetches,
                email_verification: decoded.email_verification,
            },
            topology: response.topology,
        })
    }

    pub fn delete(&self, share_code: &str, delete_token: &[u8]) -> Result<bool, ClientError> {
        Ok(self
            .delete_with_version(share_code, delete_token, None)?
            .value)
    }

    pub fn delete_with_version(
        &self,
        share_code: &str,
        delete_token: &[u8],
        topology_version: Option<u64>,
    ) -> Result<TopologyAwareResponse<bool>, ClientError> {
        let body = protocol::encode_delete_request(share_code, delete_token);
        let response = self.request_with_retry(
            Operation::Delete,
            &body,
            topology_version,
            retry_single_client_error,
        )?;
        Ok(TopologyAwareResponse {
            value: protocol::decode_delete_response(&response.value.payload)
                .map_err(ClientError::from)?,
            topology: response.topology,
        })
    }

    fn request_with_retry(
        &self,
        expected: Operation,
        body: &[u8],
        topology_version: Option<u64>,
        retry: impl Fn(&ClientError) -> bool,
    ) -> Result<TopologyAwareResponse<protocol::ResponseEnvelope>, ClientError> {
        let attempts = self.retry_policy.attempts.max(1);
        let mut backoff = self.retry_policy.initial_backoff;
        let mut last_error = None;
        for attempt in 0..attempts {
            match self
                .transport
                .post_binary_with_topology(body, topology_version)
                .and_then(|response| self.success_response_with_topology(expected, &response))
            {
                Ok(response) => return Ok(response),
                Err(err) if retry(&err) && attempt + 1 < attempts => {
                    last_error = Some(err);
                    if !backoff.is_zero() {
                        thread::sleep(backoff);
                    }
                    backoff = next_backoff(backoff, self.retry_policy.max_backoff);
                }
                Err(err) => return Err(err),
            }
        }
        Err(last_error
            .unwrap_or_else(|| ClientError::Url("retry policy has no attempts".to_string())))
    }

    fn success_response_with_topology(
        &self,
        expected: Operation,
        bytes: &[u8],
    ) -> Result<TopologyAwareResponse<protocol::ResponseEnvelope>, ClientError> {
        let mut response_with_tail =
            protocol::decode_response_with_tail(bytes, self.max_response_bytes)?;
        let response = response_with_tail.envelope;
        if response.operation != expected {
            return Err(ClientError::UnexpectedOperation {
                expected,
                actual: response.operation,
            });
        }
        if response.status != Status::Success {
            let message = protocol::decode_error_payload(&response.payload)
                .map(|(_, message)| message)
                .unwrap_or_else(|err| err.to_string());
            return Err(ClientError::Server {
                status: response.status,
                message,
            });
        }
        Ok(TopologyAwareResponse {
            value: response,
            topology: topology_from_tail(&mut response_with_tail.tail),
        })
    }
}

impl HttpTransport {
    pub fn new(server_url: &str) -> Result<Self, ClientError> {
        Ok(Self {
            endpoint: Endpoint::parse(server_url)?,
            timeout: Duration::from_secs(10),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn get(url: &str, max_response_bytes: usize) -> Result<Vec<u8>, ClientError> {
        Endpoint::parse(url)?.get(Duration::from_secs(10), max_response_bytes)
    }

    fn post_binary_std(&self, body: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.post_binary_std_with_topology(body, None)
    }

    fn post_binary_std_with_topology(
        &self,
        body: &[u8],
        topology_version: Option<u64>,
    ) -> Result<Vec<u8>, ClientError> {
        if self.endpoint.scheme == Scheme::Https {
            return tls_request(
                "POST",
                &self.endpoint.url(),
                Some(body),
                self.timeout,
                DEFAULT_MAX_RESPONSE_BYTES,
                topology_version,
            );
        }
        let mut stream = self.endpoint.connect(self.timeout)?;
        let topology_header = topology_version
            .map(|version| format!("{}: {version}\r\n", REQUEST_TOPOLOGY_HEADER))
            .unwrap_or_default();
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\n{topology_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.endpoint.path,
            self.endpoint.host,
            body.len()
        );
        stream.write_all(request.as_bytes())?;
        stream.write_all(body)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        parse_http_response(&response, DEFAULT_MAX_RESPONSE_BYTES)
    }
}

impl Transport for HttpTransport {
    fn post_binary(&self, body: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.post_binary_std(body)
    }

    fn from_url(url: &str) -> Option<Self> {
        Self::new(url).ok()
    }

    fn get_topology(url: &str) -> Option<Vec<u8>> {
        let mut endpoint = Endpoint::parse(url).ok()?;
        endpoint.path = "/v1/topology".to_string();
        endpoint
            .get(Duration::from_secs(10), DEFAULT_MAX_RESPONSE_BYTES)
            .ok()
    }

    fn post_binary_with_topology(
        &self,
        body: &[u8],
        topology_version: Option<u64>,
    ) -> Result<Vec<u8>, ClientError> {
        self.post_binary_std_with_topology(body, topology_version)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ContactShare<'a> {
    pub identity: &'a str,
    pub public_key: &'a [u8],
    pub signing_public_key: &'a [u8],
    pub fingerprint: &'a [u8],
    pub share_nonce: &'a [u8],
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub verification_email: Option<&'a str>,
}

impl Endpoint {
    fn parse(server_url: &str) -> Result<Self, ClientError> {
        let (scheme, rest) = if let Some(rest) = server_url.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else if let Some(rest) = server_url.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else {
            return Err(ClientError::Url(
                "only http:// and https:// urls are supported".to_string(),
            ));
        };
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, "/v1/share".to_string()),
        };
        if authority.is_empty() {
            return Err(ClientError::Url("missing host".to_string()));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| ClientError::Url("invalid port".to_string()))?;
                (host.to_string(), port)
            }
            None => (
                authority.to_string(),
                match scheme {
                    Scheme::Http => 80,
                    Scheme::Https => 443,
                },
            ),
        };
        if host.is_empty() {
            return Err(ClientError::Url("missing host".to_string()));
        }
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    fn connect(&self, timeout: Duration) -> Result<TcpStream, ClientError> {
        if self.scheme != Scheme::Http {
            return Err(ClientError::Url(
                "plain TCP connect is only valid for http:// endpoints".to_string(),
            ));
        }
        let stream = TcpStream::connect((&*self.host, self.port))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(stream)
    }

    fn get(&self, timeout: Duration, max_response_bytes: usize) -> Result<Vec<u8>, ClientError> {
        if self.scheme == Scheme::Https {
            return tls_request("GET", &self.url(), None, timeout, max_response_bytes, None);
        }
        let mut stream = self.connect(timeout)?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/octet-stream\r\nConnection: close\r\n\r\n",
            self.path, self.host
        );
        stream.write_all(request.as_bytes())?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        parse_http_response(&response, max_response_bytes)
    }

    fn url(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        let default_port = match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if self.port == default_port {
            format!("{scheme}://{}{}", self.host, self.path)
        } else {
            format!("{scheme}://{}:{}{}", self.host, self.port, self.path)
        }
    }
}

fn tls_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    timeout: Duration,
    max_response_bytes: usize,
    topology_version: Option<u64>,
) -> Result<Vec<u8>, ClientError> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let request = match method {
        "GET" => agent
            .get(url)
            .set("Accept", "application/octet-stream")
            .set("Connection", "close"),
        "POST" => {
            let mut request = agent
                .post(url)
                .set("Content-Type", "application/octet-stream")
                .set("Accept", "application/octet-stream")
                .set("Connection", "close");
            if let Some(version) = topology_version {
                request = request.set(REQUEST_TOPOLOGY_HEADER, &version.to_string());
            }
            request
        }
        other => return Err(ClientError::Http(format!("unsupported method {other}"))),
    };
    let response = match body {
        Some(body) => request.send_bytes(body),
        None => request.call(),
    }
    .map_err(ureq_error)?;
    if response.status() != 200 {
        return Err(ClientError::Http(format!(
            "HTTP/1.1 {} {}",
            response.status(),
            response.status_text()
        )));
    }
    read_ureq_body(response, max_response_bytes)
}

fn read_ureq_body(
    response: ureq::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, ClientError> {
    let mut reader = response.into_reader().take(max_response_bytes as u64 + 1);
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    if out.len() > max_response_bytes {
        return Err(ClientError::Protocol(ProtocolError::PayloadTooLarge));
    }
    Ok(out)
}

fn ureq_error(err: ureq::Error) -> ClientError {
    match err {
        ureq::Error::Status(status, response) => {
            ClientError::Http(format!("HTTP/1.1 {status} {}", response.status_text()))
        }
        ureq::Error::Transport(transport) => ClientError::Http(transport.to_string()),
    }
}

fn retry_share_error(err: &ClientError) -> bool {
    matches!(
        err,
        ClientError::Io(_)
            | ClientError::Http(_)
            | ClientError::Server {
                status: Status::StoreUnavailable | Status::RateLimited | Status::InternalError,
                ..
            }
    )
}

fn retry_fetch_or_delete_error(err: &ClientError) -> bool {
    matches!(
        err,
        ClientError::Io(_)
            | ClientError::Http(_)
            | ClientError::Server {
                status: Status::ShareNotFound
                    | Status::StoreUnavailable
                    | Status::RateLimited
                    | Status::InternalError,
                ..
            }
    )
}

fn retry_single_client_error(err: &ClientError) -> bool {
    matches!(
        err,
        ClientError::Http(_)
            | ClientError::Server {
                status: Status::StoreUnavailable | Status::RateLimited | Status::InternalError,
                ..
            }
    ) || matches!(err, ClientError::Io(io) if retry_same_endpoint_io_error(io))
}

fn retry_same_endpoint_io_error(err: &std::io::Error) -> bool {
    !matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    )
}

fn next_backoff(current: Duration, max: Duration) -> Duration {
    if current.is_zero() {
        return max.min(DEFAULT_INITIAL_BACKOFF);
    }
    current.saturating_mul(2).min(max)
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_http_response(bytes: &[u8], max_body: usize) -> Result<Vec<u8>, ClientError> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| ClientError::Http("missing response headers".to_string()))?;
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ClientError::Http("response headers are not utf-8".to_string()))?;
    let mut lines = headers.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| ClientError::Http("missing status line".to_string()))?;
    if !status_line.starts_with("HTTP/1.1 200 ") && !status_line.starts_with("HTTP/1.0 200 ") {
        return Err(ClientError::Http(status_line.to_string()));
    }
    let body = &bytes[header_end + 4..];
    if body.len() > max_body {
        return Err(ClientError::Protocol(ProtocolError::PayloadTooLarge));
    }
    Ok(body.to_vec())
}

fn topology_from_tail(tail: &mut Vec<u8>) -> Option<ClusterTopology> {
    if tail.is_empty() {
        return None;
    }
    topology::decode_topology(tail).ok()
}

fn dedupe_topology(mut topology: ClusterTopology) -> ClusterTopology {
    let mut servers = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for server in topology.servers.into_iter() {
        if seen.insert(server.id) {
            servers.push(server);
        }
    }
    topology.servers = servers;
    let mut routes = Vec::new();
    let mut route_seen = std::collections::HashSet::new();
    for route in topology.routes.into_iter() {
        let key = (route.owner_id, route.primary_id);
        if route_seen.insert(key) {
            routes.push(route);
        }
    }
    topology.routes = routes;
    topology
}

fn topology_urls_from_servers(servers: &[TopologyServer]) -> Vec<String> {
    dedupe_urls(
        servers
            .iter()
            .map(|server| topology_url_from_share_url(&server.url))
            .filter_map(|url| url),
    )
}

fn topology_url_from_share_url(url: &str) -> Option<String> {
    let mut endpoint = Endpoint::parse(url).ok()?;
    endpoint.path = "/v1/topology".to_string();
    Some(endpoint.url())
}

fn dedupe_urls<T: AsRef<str>>(values: impl IntoIterator<Item = T>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for value in values {
        let value = value.as_ref().to_string();
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn fallback_routes(server_ids: &[u8]) -> Vec<TopologyRoute> {
    if server_ids.is_empty() {
        return Vec::new();
    }
    let mut ids = server_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    let mut routes = Vec::with_capacity(ids.len());
    for (index, owner_id) in ids.iter().copied().enumerate() {
        let failover_id = if ids.len() > 1 {
            ids[(index + 1) % ids.len()]
        } else {
            owner_id
        };
        routes.push(TopologyRoute {
            owner_id,
            primary_id: owner_id,
            failover_ids: vec![failover_id],
        });
    }
    routes
}
