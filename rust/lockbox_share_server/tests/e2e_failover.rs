use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use lockbox_share_protocol::protocol::{self, Operation, Status};
use lockbox_share_protocol::{
    decode_contact_share, encode_contact_share, encode_replication_request, ClientError,
    HttpTransport, ReplicationEvent, ReplicationEventKind, ReplicationRequest, ServerStatus,
    ShareClient, ShareClientPool, TopologyRoute, TopologyServer, Transport,
};
use lockbox_share_server::server::run_listener;
use lockbox_share_server::store::{ServerConfig, ShareStore};

const REPLICATION_TOKEN: &str = "e2e-replication-token";

#[test]
#[ignore = "requires local TCP sockets; run explicitly on a host with loopback networking"]
fn two_server_failover_fetch_delete_and_edge_cases() {
    let cluster = TwoServerCluster::start("route-failover", PeerMode::BothDirections);
    let primary = ShareClient::new(&cluster.primary.share_url())
        .unwrap()
        .with_timeout(Duration::from_millis(250));
    let payload = contact_payload("route-failover");
    let shared = primary.share_payload(60, 3, &payload).unwrap();
    assert!(shared.share_code.starts_with('0'));
    wait_until("replication to standby", Duration::from_secs(10), || {
        cluster.standby.store.stats().live >= 1
    });

    let failover_pool = cluster.pool_with_dead_primary();
    let fetched = failover_pool.fetch(&shared.share_code).unwrap();
    assert_eq!(fetched.payload, payload);
    assert_eq!(
        decode_contact_share(&fetched.payload).unwrap().identity,
        "route-failover@example.com"
    );

    let bad_code = failover_pool.fetch("x-not-a-share").unwrap_err();
    assert_server_error(bad_code, Status::ShareNotFound);
    let bad_token = failover_pool
        .delete(&shared.share_code, b"wrong-delete-token")
        .unwrap_err();
    assert_server_error(bad_token, Status::DeleteTokenInvalid);

    assert!(failover_pool
        .delete(&shared.share_code, &shared.delete_token)
        .unwrap());
    wait_until(
        "standby delete tombstone replicated to primary",
        Duration::from_secs(10),
        || primary.fetch(&shared.share_code).is_err(),
    );
    assert_server_error(
        primary.fetch(&shared.share_code).unwrap_err(),
        Status::ShareNotFound,
    );

    let single = primary
        .share_payload(60, 1, &contact_payload("single-use"))
        .unwrap();
    wait_until(
        "single-use replicated to standby",
        Duration::from_secs(10),
        || cluster.standby.store.stats().live >= 1,
    );
    assert!(failover_pool.fetch(&single.share_code).is_ok());
    assert_server_error(
        failover_pool.fetch(&single.share_code).unwrap_err(),
        Status::ShareNotFound,
    );
    wait_until(
        "single-use standby tombstone replicated to primary",
        Duration::from_secs(10),
        || primary.fetch(&single.share_code).is_err(),
    );
}

#[test]
#[ignore = "requires local TCP sockets; run explicitly on a host with loopback networking"]
fn resync_recovers_cold_standby_after_missed_replication() {
    let cluster = TwoServerCluster::start("cold-standby", PeerMode::NoAutomaticPeers);
    let primary = ShareClient::new(&cluster.primary.share_url())
        .unwrap()
        .with_timeout(Duration::from_millis(250));
    let standby = ShareClient::new(&cluster.standby.share_url())
        .unwrap()
        .with_timeout(Duration::from_millis(250));

    let mut shared = Vec::new();
    for index in 0..8 {
        shared.push(
            primary
                .share_payload(60, 2, &contact_payload(&format!("resync-{index}")))
                .unwrap(),
        );
    }
    assert_server_error(
        standby.fetch(&shared[0].share_code).unwrap_err(),
        Status::ShareNotFound,
    );

    let sent = cluster
        .primary
        .store
        .resync_peer(&cluster.standby.replicate_url())
        .unwrap();
    assert_eq!(sent, shared.len());
    wait_until("resync applied on standby", Duration::from_secs(10), || {
        cluster.standby.store.stats().live >= shared.len()
    });
    for share in &shared {
        assert_eq!(
            standby.fetch(&share.share_code).unwrap().payload_type as u16,
            1
        );
    }

    let sent_again = cluster
        .primary
        .store
        .resync_peer(&cluster.standby.replicate_url())
        .unwrap();
    assert_eq!(sent_again, shared.len());
    assert_eq!(cluster.standby.store.stats().live, shared.len());

    let request = encode_replication_request(&ReplicationRequest {
        authentication: b"invalid".to_vec(),
        event: ReplicationEvent {
            origin_server_id: 0,
            origin_epoch: 1,
            origin_sequence: 999,
            kind: ReplicationEventKind::Tombstone {
                share_code: shared[0].share_code.clone(),
            },
        },
    });
    let response = HttpTransport::new(&cluster.standby.replicate_url())
        .unwrap()
        .post_binary(&request)
        .unwrap();
    let envelope = protocol::decode_response(&response, 1024).unwrap();
    assert_eq!(envelope.operation, Operation::Replicate);
    assert_eq!(envelope.status, Status::ReplicationUnauthorized);
}

#[test]
#[ignore = "requires local TCP sockets and performs a concurrent failover load test"]
fn heavy_failover_recovery_under_load() {
    let flows = std::env::var("LOCKBOX_SHARE_E2E_FLOWS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50_000);
    let workers = std::env::var("LOCKBOX_SHARE_E2E_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(default_heavy_workers)
        .max(1);

    let cluster = TwoServerCluster::start("heavy-recover", PeerMode::StandbyAppearsLate);
    let created = Arc::new(AtomicUsize::new(0));
    let fetched = Arc::new(AtomicUsize::new(0));
    let monitor = ProgressMonitor::start(
        flows,
        Arc::clone(&created),
        Arc::clone(&fetched),
        Arc::clone(&cluster.primary.store),
        Arc::clone(&cluster.standby.store),
    );
    let primary = ShareClient::new(&cluster.primary.share_url())
        .unwrap()
        .with_timeout(Duration::from_millis(500))
        .with_retry_policy(100, Duration::from_millis(5), Duration::from_millis(250));
    let codes = Arc::new(Mutex::new(Vec::with_capacity(flows)));
    let create_start = Instant::now();
    run_parallel(workers, flows, {
        let primary = primary.clone();
        let codes = Arc::clone(&codes);
        let created = Arc::clone(&created);
        move |index| {
            let shared = primary
                .share_payload(600, 64, &contact_payload(&format!("heavy-{index}")))
                .unwrap();
            codes.lock().unwrap().push(shared.share_code);
            created.fetch_add(1, Ordering::Relaxed);
        }
    });
    let create_elapsed = create_start.elapsed();
    let codes = Arc::try_unwrap(codes).unwrap().into_inner().unwrap();
    assert_eq!(codes.len(), flows);

    cluster.start_late_standby();
    let recover_start = Instant::now();
    wait_until("late standby caught up", Duration::from_secs(60), || {
        cluster.standby.store.stats().live >= flows
    });
    let recover_elapsed = recover_start.elapsed();

    let failover_pool = Arc::new(cluster.pool_with_dead_primary());
    let fetch_start = Instant::now();
    run_parallel(workers, codes.len(), {
        let codes = Arc::new(codes);
        let failover_pool = Arc::clone(&failover_pool);
        let fetched = Arc::clone(&fetched);
        move |index| {
            let share = failover_pool.fetch(&codes[index]).unwrap();
            assert_eq!(share.payload_type as u16, 1);
            fetched.fetch_add(1, Ordering::Relaxed);
        }
    });
    let fetch_elapsed = fetch_start.elapsed();
    assert_eq!(fetched.load(Ordering::Relaxed), flows);
    assert!(cluster.standby.store.stats().fetched >= flows as u64);
    monitor.stop();
    eprintln!(
        "heavy_failover flows={flows} workers={workers} create_rps={} recover_ms={} fetch_rps={}",
        rps(flows, create_elapsed),
        recover_elapsed.as_millis(),
        rps(flows, fetch_elapsed)
    );
}

#[derive(Clone, Copy)]
enum PeerMode {
    BothDirections,
    NoAutomaticPeers,
    StandbyAppearsLate,
}

struct TwoServerCluster {
    _guard: TempDir,
    primary: RunningServer,
    standby: RunningServer,
    late_standby: Mutex<Option<ServerConfig>>,
    topology_servers: Vec<TopologyServer>,
    topology_routes: Vec<TopologyRoute>,
}

impl TwoServerCluster {
    fn start(name: &str, peer_mode: PeerMode) -> Self {
        let guard = TempDir::new(name);
        let primary_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let standby_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let primary_addr = primary_listener.local_addr().unwrap();
        let standby_addr = standby_listener.local_addr().unwrap();
        let primary_url = share_url(primary_addr);
        let standby_url = share_url(standby_addr);
        let primary_replicate_url = replicate_url(primary_addr);
        let standby_replicate_url = replicate_url(standby_addr);
        let topology_servers = vec![
            TopologyServer {
                id: 0,
                url: primary_url.clone(),
                status: ServerStatus::Active,
            },
            TopologyServer {
                id: 1,
                url: standby_url.clone(),
                status: ServerStatus::Promoted,
            },
        ];
        let topology_routes = vec![
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
        ];

        let mut primary_config = config(
            0,
            primary_addr,
            guard.path.join("primary"),
            topology_servers.clone(),
            topology_routes.clone(),
            Vec::new(),
            Vec::new(),
        );
        let mut standby_config = config(
            1,
            standby_addr,
            guard.path.join("standby"),
            topology_servers.clone(),
            topology_routes.clone(),
            vec![0],
            Vec::new(),
        );
        match peer_mode {
            PeerMode::BothDirections => {
                primary_config.replication_peer_urls = vec![standby_replicate_url.clone()];
                standby_config.replication_peer_urls = vec![primary_replicate_url.clone()];
            }
            PeerMode::NoAutomaticPeers => {}
            PeerMode::StandbyAppearsLate => {
                primary_config.replication_peer_urls = vec![standby_replicate_url.clone()];
                standby_config.replication_peer_urls = vec![primary_replicate_url.clone()];
            }
        }

        let primary = RunningServer::start(primary_listener, primary_config);
        let (standby, late_standby) = match peer_mode {
            PeerMode::StandbyAppearsLate => (
                RunningServer::placeholder(standby_addr, standby_config.clone()),
                {
                    drop(standby_listener);
                    Some(standby_config)
                },
            ),
            _ => (RunningServer::start(standby_listener, standby_config), None),
        };

        Self {
            _guard: guard,
            primary,
            standby,
            late_standby: Mutex::new(late_standby),
            topology_servers,
            topology_routes,
        }
    }

    fn start_late_standby(&self) {
        let Some(config) = self.late_standby.lock().unwrap().take() else {
            return;
        };
        self.standby.start_placeholder(config);
    }

    fn pool_with_dead_primary(&self) -> ShareClientPool {
        let mut servers = self.topology_servers.clone();
        servers[0].url = unused_share_url();
        let topology = lockbox_share_protocol::ClusterTopology {
            cluster_id: "e2e".to_string(),
            version: 1,
            servers,
            routes: self.topology_routes.clone(),
        };
        ShareClientPool::from_topology(&topology)
            .unwrap()
            .with_timeout(Duration::from_millis(150))
            .with_retry_policy(100, Duration::from_millis(5), Duration::from_millis(250))
    }
}

struct RunningServer {
    addr: SocketAddr,
    store: Arc<ShareStore>,
}

impl RunningServer {
    fn start(listener: TcpListener, config: ServerConfig) -> Self {
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(ShareStore::open(config).unwrap());
        let server_store = Arc::clone(&store);
        thread::spawn(move || {
            let _ = run_listener(listener, server_store);
        });
        wait_for_http(addr);
        Self { addr, store }
    }

    fn placeholder(addr: SocketAddr, config: ServerConfig) -> Self {
        let store = Arc::new(ShareStore::open(config.clone()).unwrap());
        Self { addr, store }
    }

    fn start_placeholder(&self, config: ServerConfig) {
        let listener = TcpListener::bind(self.addr).unwrap();
        let server_store = Arc::clone(&self.store);
        thread::spawn(move || {
            let _ = run_listener(listener, server_store);
        });
        let _ = config;
        wait_for_http(self.addr);
    }

    fn share_url(&self) -> String {
        share_url(self.addr)
    }

    fn replicate_url(&self) -> String {
        replicate_url(self.addr)
    }
}

fn config(
    server_id: u8,
    addr: SocketAddr,
    state_dir: PathBuf,
    topology_servers: Vec<TopologyServer>,
    topology_routes: Vec<TopologyRoute>,
    promoted_owner_ids: Vec<u8>,
    replication_peer_urls: Vec<String>,
) -> ServerConfig {
    ServerConfig {
        bind_addr: addr.to_string(),
        state_dir,
        server_id,
        cluster_id: "e2e".to_string(),
        public_url: Some(share_url(addr)),
        topology_version: 1,
        topology_servers,
        topology_routes,
        replication_token: Some(REPLICATION_TOKEN.to_string()),
        replication_peer_urls,
        promoted_owner_ids,
        max_payload_bytes: 8 * 1024,
        default_ttl: Duration::from_secs(600),
        max_ttl: Duration::from_secs(600),
        shard_count: 4,
        developer_mode: false,
        benchmark_requests: 0,
        benchmark_payload_bytes: 0,
        benchmark_concurrency: 0,
        benchmark_preload_shares: 0,
        max_fetches_per_share: 64,
        share_code_digits: 12,
        compact_min_bytes: 1024 * 1024,
        index_cache_entries: 100_000,
        rate_limit_per_minute: 0,
        rate_limit_burst: 1_000,
        ..ServerConfig::default()
    }
}

fn run_parallel<F>(workers: usize, jobs: usize, f: F)
where
    F: Fn(usize) + Send + Sync + 'static,
{
    let f = Arc::new(f);
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::new();
    for worker_id in 0..workers {
        let f = Arc::clone(&f);
        let next = Arc::clone(&next);
        handles.push((
            worker_id,
            thread::spawn(move || loop {
                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if index >= jobs {
                    break;
                }
                f(index);
            }),
        ));
    }
    for (worker_id, handle) in handles {
        if let Err(panic) = handle.join() {
            if let Some(message) = panic.downcast_ref::<&str>() {
                panic!("worker {worker_id} panicked: {message}");
            }
            if let Some(message) = panic.downcast_ref::<String>() {
                panic!("worker {worker_id} panicked: {message}");
            }
            panic!("worker {worker_id} panicked with non-string payload");
        }
    }
}

struct ProgressMonitor {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ProgressMonitor {
    fn start(
        flows: usize,
        created: Arc<AtomicUsize>,
        fetched: Arc<AtomicUsize>,
        primary: Arc<ShareStore>,
        standby: Arc<ShareStore>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let started = Instant::now();
            while !thread_stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(1));
                let primary_stats = primary.stats();
                let standby_stats = standby.stats();
                let elapsed = started.elapsed().as_secs().max(1);
                eprintln!(
                    "heavy_failover progress elapsed={}s target={} created={} fetched={} \
                     primary_live={} primary_pending={} standby_live={} standby_pending={} \
                     create_rate={} fetch_rate={}",
                    elapsed,
                    flows,
                    created.load(Ordering::Relaxed),
                    fetched.load(Ordering::Relaxed),
                    primary_stats.live,
                    primary_stats.replication_pending,
                    standby_stats.live,
                    standby_stats.replication_pending,
                    created.load(Ordering::Relaxed) as u64 / elapsed,
                    fetched.load(Ordering::Relaxed) as u64 / elapsed
                );
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ProgressMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn default_heavy_workers() -> usize {
    thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .saturating_mul(8)
        .clamp(32, 128)
}

fn contact_payload(label: &str) -> Vec<u8> {
    encode_contact_share(
        &format!("{label}@example.com"),
        b"public-key-material",
        b"signing-public-key-material",
        &[1_u8; 32],
        &[2_u8; 24],
        1,
        2,
    )
}

fn wait_until(label: &str, timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {label}");
}

fn rps(count: usize, elapsed: Duration) -> u64 {
    let seconds = elapsed.as_secs_f64();
    if seconds == 0.0 {
        return count as u64;
    }
    (count as f64 / seconds) as u64
}

fn wait_for_http(addr: SocketAddr) {
    wait_until("server listener", Duration::from_secs(5), || {
        std::net::TcpStream::connect(addr).is_ok()
    });
}

fn assert_server_error(error: ClientError, status: Status) {
    match error {
        ClientError::Server { status: actual, .. } => assert_eq!(actual, status),
        other => panic!("expected {status:?} server error, got {other:?}"),
    }
}

fn share_url(addr: SocketAddr) -> String {
    format!("http://{addr}/v1/share")
}

fn replicate_url(addr: SocketAddr) -> String {
    format!("http://{addr}/v1/replicate")
}

fn unused_share_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    share_url(addr)
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "lockbox-share-e2e-{name}-{}-{:?}",
            std::process::id(),
            thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
