use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::client::ClientError;
use crate::protocol::{self, ProtocolError, Reader};

const TOPOLOGY_MAGIC: &[u8; 4] = b"LBST";
const TOPOLOGY_VERSION: u16 = 2;
const TOPOLOGY_CACHE_MAGIC: &[u8; 4] = b"LBTC";
const TOPOLOGY_CACHE_VERSION: u16 = 1;
const TOPOLOGY_REGISTRATION_MAGIC: &[u8; 4] = b"LBTR";
const TOPOLOGY_REGISTRATION_VERSION: u16 = 1;
const STATUS_ACTIVE: u8 = 1;
const STATUS_STANDBY: u8 = 2;
const STATUS_PROMOTED: u8 = 3;
const STATUS_DISABLED: u8 = 4;
const SHARE_CODE_SERVER_ID_ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const SHARE_CODE_LEN: usize = 14;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterTopology {
    pub cluster_id: String,
    pub version: u64,
    pub servers: Vec<TopologyServer>,
    pub routes: Vec<TopologyRoute>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyServer {
    pub id: u8,
    pub url: String,
    pub status: ServerStatus,
    pub last_seen_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyRegistration {
    pub cluster_id: String,
    pub server_id: u8,
    pub server_url: String,
    pub status: ServerStatus,
    pub security_token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyRoute {
    pub owner_id: u8,
    pub primary_id: u8,
    pub failover_ids: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerStatus {
    Active,
    Standby,
    Promoted,
    Disabled,
}

impl ClusterTopology {
    pub fn single_server(server_id: u8, url: impl Into<String>) -> Self {
        Self {
            cluster_id: "default".to_string(),
            version: 1,
            servers: vec![TopologyServer {
                id: server_id,
                url: url.into(),
                status: ServerStatus::Active,
                last_seen_ms: None,
            }],
            routes: vec![TopologyRoute {
                owner_id: server_id,
                primary_id: server_id,
                failover_ids: Vec::new(),
            }],
        }
    }

    pub fn with_filtered_stale_servers(&self, stale_after_ms: u64) -> ClusterTopology {
        if stale_after_ms == 0 {
            return self.clone();
        }
        let now_ms = unix_ms(SystemTime::now());
        let active_server_ids = self
            .servers
            .iter()
            .filter(|server| !is_topology_server_stale(server, now_ms, stale_after_ms))
            .filter(|server| {
                matches!(
                    server.status,
                    ServerStatus::Active | ServerStatus::Promoted | ServerStatus::Standby
                )
            })
            .map(|server| server.id)
            .collect::<HashSet<_>>();
        let servers = self
            .servers
            .iter()
            .filter(|server| active_server_ids.contains(&server.id))
            .cloned()
            .collect::<Vec<_>>();
        let mut routes = self
            .routes
            .iter()
            .filter(|route| active_server_ids.contains(&route.owner_id))
            .filter(|route| active_server_ids.contains(&route.primary_id))
            .filter(|route| {
                route
                    .failover_ids
                    .iter()
                    .all(|id| active_server_ids.contains(id))
            })
            .cloned()
            .collect::<Vec<_>>();
        if routes.is_empty() {
            routes = build_ring_routes(&servers);
        }
        ClusterTopology {
            cluster_id: self.cluster_id.clone(),
            version: self.version,
            servers,
            routes,
        }
    }

    pub fn validate(&self) -> Result<(), ClientError> {
        if self.cluster_id.is_empty() {
            return Err(ClientError::Topology(
                "topology cluster_id must not be empty".to_string(),
            ));
        }
        if self.servers.is_empty() {
            return Err(ClientError::Topology(
                "topology must include at least one server".to_string(),
            ));
        }
        for server in &self.servers {
            validate_server_id(server.id)?;
            if server.url.is_empty() {
                return Err(ClientError::Topology(format!(
                    "server {} url must not be empty",
                    server.id
                )));
            }
        }
        for route in &self.routes {
            validate_server_id(route.owner_id)?;
            validate_server_id(route.primary_id)?;
            if self.server(route.primary_id).is_none() {
                return Err(ClientError::Topology(format!(
                    "route owner {} references unknown primary {}",
                    route.owner_id, route.primary_id
                )));
            }
            for failover_id in &route.failover_ids {
                validate_server_id(*failover_id)?;
                if self.server(*failover_id).is_none() {
                    return Err(ClientError::Topology(format!(
                        "route owner {} references unknown failover {}",
                        route.owner_id, failover_id
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn server(&self, id: u8) -> Option<&TopologyServer> {
        self.servers.iter().find(|server| server.id == id)
    }

    pub fn route(&self, owner_id: u8) -> Option<&TopologyRoute> {
        self.routes.iter().find(|route| route.owner_id == owner_id)
    }

    pub fn urls_for_share_code(&self, share_code: &str) -> Vec<String> {
        let Some(owner_id) = share_code_owner_id(share_code) else {
            return self.active_urls();
        };
        let Some(route) = self.route(owner_id) else {
            return self.active_urls();
        };
        let mut out = Vec::new();
        if let Some(server) = self.server(route.primary_id) {
            out.push(server.url.clone());
        }
        for failover_id in &route.failover_ids {
            if let Some(server) = self.server(*failover_id) {
                if !out.iter().any(|url| url == &server.url) {
                    out.push(server.url.clone());
                }
            }
        }
        for url in self.active_urls() {
            if !out.iter().any(|existing| existing == &url) {
                out.push(url);
            }
        }
        out
    }

    pub fn active_urls(&self) -> Vec<String> {
        self.servers
            .iter()
            .filter(|server| {
                matches!(
                    server.status,
                    ServerStatus::Active | ServerStatus::Promoted | ServerStatus::Standby
                )
            })
            .map(|server| server.url.clone())
            .collect()
    }

    pub fn active_urls_with_ttl(&self, stale_after_ms: u64) -> Vec<String> {
        self.with_filtered_stale_servers(stale_after_ms)
            .servers
            .into_iter()
            .filter(|server| {
                matches!(
                    server.status,
                    ServerStatus::Active | ServerStatus::Promoted | ServerStatus::Standby
                )
            })
            .map(|server| server.url)
            .collect()
    }

    pub fn routes_for_owner(&self, owner_id: u8) -> Option<&TopologyRoute> {
        self.route(owner_id)
    }
}

pub fn build_ring_routes(servers: &[TopologyServer]) -> Vec<TopologyRoute> {
    let mut active_ids = servers
        .iter()
        .filter(|server| {
            matches!(
                server.status,
                ServerStatus::Active | ServerStatus::Promoted | ServerStatus::Standby
            )
        })
        .map(|server| server.id)
        .collect::<Vec<_>>();
    active_ids.sort_unstable();
    active_ids.dedup();
    if active_ids.is_empty() {
        return Vec::new();
    }
    let mut routes = Vec::with_capacity(active_ids.len());
    for (index, owner_id) in active_ids.iter().enumerate() {
        let failover_ids = if active_ids.len() > 1 {
            vec![active_ids[(index + 1) % active_ids.len()]]
        } else {
            vec![*owner_id]
        };
        routes.push(TopologyRoute {
            owner_id: *owner_id,
            primary_id: *owner_id,
            failover_ids,
        });
    }
    routes
}

pub fn is_topology_server_stale(server: &TopologyServer, now_ms: u64, stale_after_ms: u64) -> bool {
    if stale_after_ms == 0 {
        return false;
    }
    match server.last_seen_ms {
        Some(last_seen_ms) => now_ms.saturating_sub(last_seen_ms) > stale_after_ms,
        None => false,
    }
}

pub fn parse_share_locator(value: &str) -> Option<(u8, u8)> {
    share_code_locator(value)
}

pub fn encode_topology(topology: &ClusterTopology) -> Result<Vec<u8>, ClientError> {
    topology.validate()?;
    if topology.servers.len() > u16::MAX as usize || topology.routes.len() > u16::MAX as usize {
        return Err(ClientError::Topology(
            "topology has too many servers or routes".to_string(),
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(TOPOLOGY_MAGIC);
    protocol::put_u16(&mut out, TOPOLOGY_VERSION);
    protocol::put_string(&mut out, &topology.cluster_id);
    protocol::put_u64(&mut out, topology.version);
    protocol::put_u16(&mut out, topology.servers.len() as u16);
    for server in &topology.servers {
        out.push(server.id);
        out.push(server_status_to_u8(&server.status));
        out.push(if server.last_seen_ms.is_some() { 1 } else { 0 });
        if let Some(last_seen_ms) = server.last_seen_ms {
            protocol::put_u64(&mut out, last_seen_ms);
        }
        protocol::put_string(&mut out, &server.url);
    }
    protocol::put_u16(&mut out, topology.routes.len() as u16);
    for route in &topology.routes {
        if route.failover_ids.len() > u16::MAX as usize {
            return Err(ClientError::Topology(
                "topology route has too many failover ids".to_string(),
            ));
        }
        out.push(route.owner_id);
        out.push(route.primary_id);
        protocol::put_u16(&mut out, route.failover_ids.len() as u16);
        out.extend_from_slice(&route.failover_ids);
    }
    Ok(out)
}

pub fn decode_topology(bytes: &[u8]) -> Result<ClusterTopology, ClientError> {
    let mut reader = Reader::new(bytes);
    let magic = reader
        .fixed_bytes(TOPOLOGY_MAGIC.len())
        .map_err(topology_protocol_error)?;
    if magic != TOPOLOGY_MAGIC {
        return Err(ClientError::Topology(
            "topology document has invalid magic".to_string(),
        ));
    }
    let version = reader.u16().map_err(topology_protocol_error)?;
    if version != TOPOLOGY_VERSION {
        return Err(ClientError::Topology(format!(
            "topology version {version} is not supported"
        )));
    }
    let cluster_id = reader.string().map_err(topology_protocol_error)?;
    let topology_version = reader.u64().map_err(topology_protocol_error)?;
    let server_count = reader.u16().map_err(topology_protocol_error)? as usize;
    let mut servers = Vec::with_capacity(server_count);
    for _ in 0..server_count {
        let id = reader.u8().map_err(topology_protocol_error)?;
        let status = server_status_from_u8(reader.u8().map_err(topology_protocol_error)?)?;
        let has_last_seen = reader.u8().map_err(topology_protocol_error)? != 0;
        let last_seen_ms = if has_last_seen {
            Some(reader.u64().map_err(topology_protocol_error)?)
        } else {
            None
        };
        let url = reader.string().map_err(topology_protocol_error)?;
        servers.push(TopologyServer {
            id,
            url,
            status,
            last_seen_ms,
        });
    }
    let route_count = reader.u16().map_err(topology_protocol_error)? as usize;
    let mut routes = Vec::with_capacity(route_count);
    for _ in 0..route_count {
        let owner_id = reader.u8().map_err(topology_protocol_error)?;
        let primary_id = reader.u8().map_err(topology_protocol_error)?;
        let failover_count = reader.u16().map_err(topology_protocol_error)? as usize;
        let mut failover_ids = Vec::with_capacity(failover_count);
        for _ in 0..failover_count {
            failover_ids.push(reader.u8().map_err(topology_protocol_error)?);
        }
        routes.push(TopologyRoute {
            owner_id,
            primary_id,
            failover_ids,
        });
    }
    let topology = ClusterTopology {
        cluster_id,
        version: topology_version,
        servers,
        routes,
    };
    topology.validate()?;
    Ok(topology)
}

pub fn share_code_owner_id(share_code: &str) -> Option<u8> {
    if share_code.len() != SHARE_CODE_LEN {
        return None;
    }
    parse_share_code_server_id(*share_code.as_bytes().first()?)
}

pub fn share_code_locator(share_code: &str) -> Option<(u8, u8)> {
    let bytes = share_code.as_bytes();
    if bytes.len() != SHARE_CODE_LEN {
        return None;
    }
    let owner_id = parse_share_code_server_id(*bytes.first()?)?;
    let secondary_id = parse_share_code_server_id(*bytes.get(1)?)?;
    Some((owner_id, secondary_id))
}

pub fn share_code_server_id_char(id: u8) -> Option<u8> {
    SHARE_CODE_SERVER_ID_ALPHABET.get(id as usize).copied()
}

fn parse_share_code_server_id(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'z' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub fn write_topology_cache(
    path: impl AsRef<Path>,
    topology: &ClusterTopology,
) -> Result<(), ClientError> {
    let topology = encode_topology(topology)?;
    let mut out = Vec::new();
    out.extend_from_slice(TOPOLOGY_CACHE_MAGIC);
    protocol::put_u16(&mut out, TOPOLOGY_CACHE_VERSION);
    protocol::put_u64(&mut out, unix_ms(SystemTime::now()));
    protocol::put_bytes(&mut out, &topology);
    fs::write(path, out).map_err(ClientError::Io)
}

pub fn encode_topology_registration(
    registration: &TopologyRegistration,
) -> Result<Vec<u8>, ClientError> {
    let mut out = Vec::new();
    out.extend_from_slice(TOPOLOGY_REGISTRATION_MAGIC);
    protocol::put_u16(&mut out, TOPOLOGY_REGISTRATION_VERSION);
    protocol::put_string(&mut out, &registration.cluster_id);
    protocol::put_u64(&mut out, registration.server_id as u64);
    protocol::put_string(&mut out, &registration.server_url);
    out.push(server_status_to_u8(&registration.status));
    protocol::put_string(&mut out, &registration.security_token);
    Ok(out)
}

pub fn decode_topology_registration(bytes: &[u8]) -> Result<TopologyRegistration, ClientError> {
    let mut reader = Reader::new(bytes);
    let magic = reader
        .fixed_bytes(TOPOLOGY_REGISTRATION_MAGIC.len())
        .map_err(topology_protocol_error)?;
    if magic != TOPOLOGY_REGISTRATION_MAGIC {
        return Err(ClientError::Topology(
            "topology registration document has invalid magic".to_string(),
        ));
    }
    let version = reader.u16().map_err(topology_protocol_error)?;
    if version != TOPOLOGY_REGISTRATION_VERSION {
        return Err(ClientError::Topology(format!(
            "topology registration version {version} is not supported"
        )));
    }
    let cluster_id = reader.string().map_err(topology_protocol_error)?;
    let server_id = reader.u64().map_err(topology_protocol_error)? as u8;
    let server_url = reader.string().map_err(topology_protocol_error)?;
    let status = server_status_from_u8(reader.u8().map_err(topology_protocol_error)?)?;
    let security_token = reader.string().map_err(topology_protocol_error)?;
    Ok(TopologyRegistration {
        cluster_id,
        server_id,
        server_url,
        status,
        security_token,
    })
}

pub fn read_topology_cache(
    path: impl AsRef<Path>,
    max_age: Duration,
) -> Result<Option<ClusterTopology>, ClientError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(ClientError::Io(err)),
    };
    let mut reader = Reader::new(&bytes);
    let magic = reader
        .fixed_bytes(TOPOLOGY_CACHE_MAGIC.len())
        .map_err(topology_protocol_error)?;
    if magic != TOPOLOGY_CACHE_MAGIC {
        return Err(ClientError::Topology(
            "topology cache has invalid magic".to_string(),
        ));
    }
    let version = reader.u16().map_err(topology_protocol_error)?;
    if version != TOPOLOGY_CACHE_VERSION {
        return Err(ClientError::Topology(format!(
            "topology cache version {version} is not supported"
        )));
    }
    let fetched_at_ms = reader.u64().map_err(topology_protocol_error)?;
    let now_ms = unix_ms(SystemTime::now());
    if now_ms.saturating_sub(fetched_at_ms) > max_age.as_millis() as u64 {
        return Ok(None);
    }
    let topology = reader.bytes().map_err(topology_protocol_error)?;
    decode_topology(&topology).map(Some)
}

fn validate_server_id(id: u8) -> Result<(), ClientError> {
    if id < SHARE_CODE_SERVER_ID_ALPHABET.len() as u8 {
        Ok(())
    } else {
        Err(ClientError::Topology(format!(
            "server id must be an index 0..35 (0..9, a..z): {id}"
        )))
    }
}

fn server_status_to_u8(status: &ServerStatus) -> u8 {
    match status {
        ServerStatus::Active => STATUS_ACTIVE,
        ServerStatus::Standby => STATUS_STANDBY,
        ServerStatus::Promoted => STATUS_PROMOTED,
        ServerStatus::Disabled => STATUS_DISABLED,
    }
}

fn server_status_from_u8(value: u8) -> Result<ServerStatus, ClientError> {
    match value {
        STATUS_ACTIVE => Ok(ServerStatus::Active),
        STATUS_STANDBY => Ok(ServerStatus::Standby),
        STATUS_PROMOTED => Ok(ServerStatus::Promoted),
        STATUS_DISABLED => Ok(ServerStatus::Disabled),
        _ => Err(ClientError::Topology(format!(
            "unknown topology server status {value}"
        ))),
    }
}

fn topology_protocol_error(err: ProtocolError) -> ClientError {
    ClientError::Topology(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_filtered_stale_servers_removes_stale_servers_and_routes() {
        let now_ms = unix_ms(SystemTime::now());
        let topology = ClusterTopology {
            cluster_id: "acme".to_string(),
            version: 1,
            servers: vec![
                TopologyServer {
                    id: 0,
                    url: "http://share0/v1/share".to_string(),
                    status: ServerStatus::Active,
                    last_seen_ms: Some(now_ms),
                },
                TopologyServer {
                    id: 1,
                    url: "http://share1/v1/share".to_string(),
                    status: ServerStatus::Active,
                    last_seen_ms: Some(now_ms - 200),
                },
                TopologyServer {
                    id: 2,
                    url: "http://share2/v1/share".to_string(),
                    status: ServerStatus::Disabled,
                    last_seen_ms: Some(now_ms),
                },
            ],
            routes: vec![
                TopologyRoute {
                    owner_id: 0,
                    primary_id: 0,
                    failover_ids: vec![1],
                },
                TopologyRoute {
                    owner_id: 1,
                    primary_id: 1,
                    failover_ids: vec![0],
                },
                TopologyRoute {
                    owner_id: 2,
                    primary_id: 2,
                    failover_ids: vec![0],
                },
            ],
        };

        let filtered = topology.with_filtered_stale_servers(100);

        assert_eq!(filtered.servers.len(), 1);
        assert_eq!(filtered.servers[0].id, 0);
        assert_eq!(
            filtered.routes,
            vec![TopologyRoute {
                owner_id: 0,
                primary_id: 0,
                failover_ids: vec![0],
            }],
        );
    }

    #[test]
    fn build_ring_routes_ignores_inactive_servers() {
        let routes = build_ring_routes(&[
            TopologyServer {
                id: 0,
                url: "http://share0/v1/share".to_string(),
                status: ServerStatus::Active,
                last_seen_ms: Some(10),
            },
            TopologyServer {
                id: 1,
                url: "http://share1/v1/share".to_string(),
                status: ServerStatus::Disabled,
                last_seen_ms: Some(20),
            },
            TopologyServer {
                id: 2,
                url: "http://share2/v1/share".to_string(),
                status: ServerStatus::Standby,
                last_seen_ms: Some(30),
            },
        ]);

        assert_eq!(
            routes,
            vec![
                TopologyRoute {
                    owner_id: 0,
                    primary_id: 0,
                    failover_ids: vec![2],
                },
                TopologyRoute {
                    owner_id: 2,
                    primary_id: 2,
                    failover_ids: vec![0],
                },
            ]
        );
    }
}

fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
