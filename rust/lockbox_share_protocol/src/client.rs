use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::payload::{self, PayloadType};
use crate::protocol::{self, Operation, ProtocolError, Status};
use crate::topology::{self, ClusterTopology, TopologyRoute};

const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct ShareClient<T = HttpTransport> {
    transport: T,
    max_response_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ShareClientPool<T = HttpTransport> {
    clients: Vec<ShareClient<T>>,
    server_ids: Vec<u8>,
    routes: Vec<TopologyRoute>,
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
}

#[derive(Clone, Debug)]
pub struct FetchedShare {
    pub payload: Vec<u8>,
    pub payload_type: PayloadType,
    pub expires_at_unix_ms: u64,
    pub remaining_fetches: u16,
}

pub trait Transport: Clone {
    fn post_binary(&self, body: &[u8]) -> Result<Vec<u8>, ClientError>;
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
            Self::Url(err) => write!(f, "invalid share server url: {err}"),
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

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        for client in &mut self.clients {
            client.transport.timeout = timeout;
        }
        self
    }

    pub fn from_topology(topology: &ClusterTopology) -> Result<Self, ClientError> {
        topology.validate()?;
        let mut clients = Vec::new();
        let mut server_ids = Vec::new();
        for server in &topology.servers {
            clients.push(ShareClient::new(&server.url)?);
            server_ids.push(server.id);
        }
        Self::from_clients_with_ids(clients, server_ids, topology.routes.clone())
    }

    pub fn discover(topology_url: &str) -> Result<Self, ClientError> {
        let bytes = HttpTransport::get(topology_url, DEFAULT_MAX_RESPONSE_BYTES)?;
        let topology = topology::decode_topology(&bytes)?;
        Self::from_topology(&topology)
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
                "at least one share server url is required".to_string(),
            ));
        }
        if clients.len() != server_ids.len() {
            return Err(ClientError::Topology(
                "client and server id counts differ".to_string(),
            ));
        }
        for server_id in &server_ids {
            if *server_id > 9 {
                return Err(ClientError::Topology(format!(
                    "server id must be a decimal digit from 0 to 9: {server_id}"
                )));
            }
        }
        Ok(Self {
            clients,
            server_ids,
            routes,
        })
    }

    pub fn from_transports(transports: Vec<T>) -> Result<Self, ClientError> {
        let clients = transports
            .into_iter()
            .map(ShareClient::from_transport)
            .collect::<Vec<_>>();
        Self::from_clients(clients)
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        for client in &mut self.clients {
            client.max_response_bytes = max_response_bytes;
        }
        self
    }

    pub fn share_payload(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        payload: &[u8],
    ) -> Result<ShareResult, ClientError> {
        payload::validate_payload(payload)?;
        self.try_clients_from(
            self.selection_offset(),
            |client| client.share_payload(ttl_seconds, max_fetches, payload),
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
            contact.fingerprint,
            contact.share_nonce,
            contact.created_at_unix_ms,
            contact.expires_at_unix_ms,
        );
        self.share_payload(ttl_seconds, max_fetches, &payload)
    }

    pub fn fetch(&self, share_code: &str) -> Result<FetchedShare, ClientError> {
        self.try_clients_for_code(
            share_code,
            |client| client.fetch(share_code),
            retry_fetch_or_delete_error,
        )
    }

    pub fn delete(&self, share_code: &str, delete_token: &[u8]) -> Result<bool, ClientError> {
        let mut last_error = None;
        for client in self.clients_for_code(share_code) {
            match client.delete(share_code, delete_token) {
                Ok(true) => return Ok(true),
                Ok(false) => continue,
                Err(err) if retry_fetch_or_delete_error(&err) => last_error = Some(err),
                Err(err) => return Err(err),
            }
        }
        match last_error {
            Some(err) => Err(err),
            None => Ok(false),
        }
    }

    fn try_clients_from<R>(
        &self,
        start: usize,
        mut call: impl FnMut(&ShareClient<T>) -> Result<R, ClientError>,
        retry: impl Fn(&ClientError) -> bool,
    ) -> Result<R, ClientError> {
        let mut last_error = None;
        for offset in 0..self.clients.len() {
            let index = (start + offset) % self.clients.len();
            let client = &self.clients[index];
            match call(client) {
                Ok(value) => return Ok(value),
                Err(err) if retry(&err) => last_error = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            ClientError::Url("at least one share server url is required".to_string())
        }))
    }

    fn selection_offset(&self) -> usize {
        if self.clients.len() <= 1 {
            return 0;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos() as usize % self.clients.len())
            .unwrap_or(0)
    }

    fn try_clients_for_code<R>(
        &self,
        share_code: &str,
        mut call: impl FnMut(&ShareClient<T>) -> Result<R, ClientError>,
        retry: impl Fn(&ClientError) -> bool,
    ) -> Result<R, ClientError> {
        let mut last_error = None;
        for client in self.clients_for_code(share_code) {
            match call(client) {
                Ok(value) => return Ok(value),
                Err(err) if retry(&err) => last_error = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            ClientError::Url("at least one share server url is required".to_string())
        }))
    }

    fn clients_for_code(&self, share_code: &str) -> Vec<&ShareClient<T>> {
        let owner_id = topology::share_code_owner_id(share_code);
        let preferred_ids = owner_id
            .and_then(|owner_id| self.routes.iter().find(|route| route.owner_id == owner_id))
            .map(|route| {
                let mut ids = vec![route.primary_id];
                ids.extend(route.failover_ids.iter().copied());
                ids
            })
            .or_else(|| owner_id.map(|owner_id| vec![owner_id]))
            .unwrap_or_default();
        let mut out = Vec::with_capacity(self.clients.len());
        for preferred_id in preferred_ids {
            if let Some((index, _)) = self
                .server_ids
                .iter()
                .enumerate()
                .find(|(_, server_id)| **server_id == preferred_id)
            {
                out.push(&self.clients[index]);
            }
        }
        for client in &self.clients {
            if !out.iter().any(|existing| std::ptr::eq(*existing, client)) {
                out.push(client);
            }
        }
        out
    }
}

impl<T: Transport> ShareClient<T> {
    pub fn from_transport(transport: T) -> Self {
        Self {
            transport,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    pub fn share_payload(
        &self,
        ttl_seconds: u32,
        max_fetches: u16,
        payload: &[u8],
    ) -> Result<ShareResult, ClientError> {
        payload::validate_payload(payload)?;
        let body = protocol::encode_share_request(ttl_seconds, max_fetches, payload);
        let response = self.transport.post_binary(&body)?;
        let response = self.success_response(Operation::Share, &response)?;
        let (share_code, delete_token, expires_at_unix_ms, max_fetches) =
            protocol::decode_share_response(&response.payload)?;
        Ok(ShareResult {
            share_code,
            delete_token,
            expires_at_unix_ms,
            max_fetches,
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
            contact.fingerprint,
            contact.share_nonce,
            contact.created_at_unix_ms,
            contact.expires_at_unix_ms,
        );
        self.share_payload(ttl_seconds, max_fetches, &payload)
    }

    pub fn fetch(&self, share_code: &str) -> Result<FetchedShare, ClientError> {
        let body = protocol::encode_fetch_request(share_code);
        let response = self.transport.post_binary(&body)?;
        let response = self.success_response(Operation::Fetch, &response)?;
        let (payload, expires_at_unix_ms, remaining_fetches) =
            protocol::decode_fetch_response(&response.payload)?;
        let payload_type = payload::validate_payload(&payload)?;
        Ok(FetchedShare {
            payload,
            payload_type,
            expires_at_unix_ms,
            remaining_fetches,
        })
    }

    pub fn delete(&self, share_code: &str, delete_token: &[u8]) -> Result<bool, ClientError> {
        let body = protocol::encode_delete_request(share_code, delete_token);
        let response = self.transport.post_binary(&body)?;
        let response = self.success_response(Operation::Delete, &response)?;
        protocol::decode_delete_response(&response.payload).map_err(ClientError::from)
    }

    fn success_response(
        &self,
        expected: Operation,
        bytes: &[u8],
    ) -> Result<protocol::ResponseEnvelope, ClientError> {
        let response = protocol::decode_response(bytes, self.max_response_bytes)?;
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
        Ok(response)
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
        if self.endpoint.scheme == Scheme::Https {
            return tls_request(
                "POST",
                &self.endpoint.url(),
                Some(body),
                self.timeout,
                DEFAULT_MAX_RESPONSE_BYTES,
            );
        }
        let mut stream = self.endpoint.connect(self.timeout)?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
}

#[derive(Clone, Copy, Debug)]
pub struct ContactShare<'a> {
    pub identity: &'a str,
    pub public_key: &'a [u8],
    pub fingerprint: &'a [u8],
    pub share_nonce: &'a [u8],
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
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
            return tls_request("GET", &self.url(), None, timeout, max_response_bytes);
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
) -> Result<Vec<u8>, ClientError> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let request = match method {
        "GET" => agent
            .get(url)
            .set("Accept", "application/octet-stream")
            .set("Connection", "close"),
        "POST" => agent
            .post(url)
            .set("Content-Type", "application/octet-stream")
            .set("Accept", "application/octet-stream")
            .set("Connection", "close"),
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
