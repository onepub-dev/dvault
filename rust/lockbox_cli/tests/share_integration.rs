use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use lockbox_key_server::{server::run_listener, store::ServerConfig, store::ShareStore};
use lockbox_share_protocol::{
    decode_contact_share, share_code_locator, ServerStatus, ShareClientPool, TopologyRoute,
    TopologyServer,
};

const REPLICATION_TOKEN: &str = "integration-replication-token";

#[test]
#[ignore = "requires local TCP sockets; run explicitly on a host with loopback networking"]
fn cli_publish_and_receive_with_two_servers() {
    if !has_loopback_sockets() {
        eprintln!("skipping local-socket e2e test in restricted environment");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let cluster = TwoServerCluster::start("cli-integration", PeerMode::BothDirections);
    let (vault_root, agent_root) = temp_roots("cli-publish-receive");
    init_vault_with_email(bin, &vault_root, &agent_root, "alice@example.test");

    let publish = publish_contact(bin, &vault_root, &agent_root, &cluster.topology_url());
    let owner = cluster.owner_store(&publish.share_code);
    let verified = owner.verify_email(&publish.verified_query_code, &publish.verified_query_token);
    assert!(
        verified.success,
        "{}
",
        verified.message
    );

    let receive = run_output_in(
        bin,
        &[
            "vault",
            "contact",
            "receive",
            &publish.share_code,
            "received",
            "--topology-url",
            &cluster.topology_url(),
            "--fingerprint",
            &publish.contact_fingerprint,
            "--fingerprint-channel",
            "phone-call-to-owner",
        ],
        &vault_root,
        &agent_root,
    );
    assert_success(&receive);
    let receive_text = String::from_utf8_lossy(&receive.stdout);
    assert!(receive_text.contains(&format!("share_code={}", publish.share_code)));
    assert!(receive_text.contains("contact=received"));
    assert!(receive_text.contains("fingerprint_verified=yes"));
}

#[test]
#[ignore = "requires local TCP sockets; run explicitly on a host with loopback networking"]
fn cli_publish_can_be_fetched_from_failover_path() {
    if !has_loopback_sockets() {
        eprintln!("skipping local-socket e2e test in restricted environment");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_lockbox");
    let cluster = TwoServerCluster::start("cli-failover", PeerMode::BothDirections);
    let (vault_root, agent_root) = temp_roots("cli-failover");
    init_vault_with_email(bin, &vault_root, &agent_root, "alice@example.test");

    let publish = publish_contact(bin, &vault_root, &agent_root, &cluster.topology_url());
    let owner_store = cluster.owner_store(&publish.share_code);
    let (owner_id, _secondary_id) = cluster
        .share_locator(&publish.share_code)
        .expect("publish share code has valid locator");
    let failover_pool = cluster.pool_with_dead_server(owner_id);
    let non_owner = cluster.non_owner_store(&publish.share_code);

    wait_until(
        "share replicated to standby",
        Duration::from_secs(10),
        || cluster.standby.store.fetch(&publish.share_code).is_ok(),
    );

    let fetched = failover_pool
        .fetch(&publish.share_code)
        .expect("failover fetch");
    let decoded = decode_contact_share(&fetched.payload).expect("decode failover payload");
    assert_eq!(decoded.identity, "default");

    let verify =
        owner_store.verify_email(&publish.verified_query_code, &publish.verified_query_token);
    assert!(verify.success, "{}", verify.message);
    let non_owner_verify =
        non_owner.verify_email(&publish.verified_query_code, &publish.verified_query_token);
    assert!(
        !non_owner_verify.success,
        "non-owner should not verify share code without owner responsibility"
    );
}

impl TwoServerCluster {
    fn share_locator(&self, share_code: &str) -> Option<(u8, u8)> {
        share_code_locator(share_code)
    }

    fn owner_store(&self, share_code: &str) -> &ShareStore {
        let (owner_id, _) = self
            .share_locator(share_code)
            .expect("invalid share locator");
        match owner_id {
            0 => self.primary.store.as_ref(),
            1 => self.standby.store.as_ref(),
            other => panic!("unexpected owner server id {other}"),
        }
    }

    fn non_owner_store(&self, share_code: &str) -> &ShareStore {
        let (owner_id, _) = self
            .share_locator(share_code)
            .expect("invalid share locator");
        match owner_id {
            0 => self.standby.store.as_ref(),
            1 => self.primary.store.as_ref(),
            other => panic!("unexpected owner server id {other}"),
        }
    }
}

struct PublishedShare {
    share_code: String,
    contact_fingerprint: String,
    verified_query_code: String,
    verified_query_token: String,
}

fn publish_contact(
    bin: &str,
    vault_root: &PathBuf,
    agent_root: &PathBuf,
    topology_url: &str,
) -> PublishedShare {
    let publish = run_output_in(
        bin,
        &[
            "vault",
            "identity",
            "publish",
            "--topology-url",
            topology_url,
            "--ttl",
            "300",
            "--max-fetches",
            "10",
        ],
        vault_root,
        agent_root,
    );
    assert_success(&publish);
    parse_publish_output(&String::from_utf8_lossy(&publish.stdout))
}

fn init_vault_with_email(bin: &str, vault_root: &PathBuf, agent_root: &PathBuf, email: &str) {
    run_success(bin, vault_root, agent_root, &["vault", "init"]);
    run_success(
        bin,
        vault_root,
        agent_root,
        &["vault", "identity", "email", "default", email],
    );
}

fn parse_publish_output(text: &str) -> PublishedShare {
    let mut share_code = None;
    let mut contact_fingerprint = None;
    let mut verification_url = None;

    for line in text.lines() {
        if let Some(value) = line.strip_prefix("share_code=") {
            share_code = Some(value.to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix("contact_fingerprint=") {
            contact_fingerprint = Some(value.to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix("verification_url=") {
            verification_url = Some(value.to_string());
        }
    }

    let share_code = share_code.expect("publish output did not include share_code");
    let contact_fingerprint =
        contact_fingerprint.expect("publish output did not include contact_fingerprint");
    let verification_url =
        verification_url.expect("publish output did not include verification_url");
    let (verified_query_code, verified_query_token) = verification_query_parts(&verification_url);

    PublishedShare {
        share_code,
        contact_fingerprint,
        verified_query_code,
        verified_query_token,
    }
}

fn verification_query_parts(url: &str) -> (String, String) {
    let query = url
        .split_once('?')
        .expect("verification url missing query")
        .1;
    let mut code = None;
    let mut token = None;
    for part in query.split('&') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key {
            "code" => code = Some(value.to_string()),
            "token" => token = Some(value.to_string()),
            _ => {}
        }
    }

    (
        code.expect("verification url missing code"),
        token.expect("verification url missing token"),
    )
}

fn run_output_in(bin: &str, args: &[&str], vault_root: &PathBuf, agent_root: &PathBuf) -> Output {
    println!(
        "CLI command: {bin} {}",
        args.iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let started = Instant::now();
    let output = Command::new(bin)
        .args(args)
        .env("LOCKBOX_KEY", "test-key")
        .env("LOCKBOX_VAULT_PASSWORD", "test-vault-password")
        .env("LOCKBOX_SESSION_AGENT_DIR", agent_root)
        .env("LOCKBOX_SESSION_AGENT_LOG", agent_log_path(agent_root))
        .env("LOCKBOX_VAULT_DIR", vault_root)
        .output()
        .unwrap();
    println!("CLI status: {}", output.status);
    println!("CLI duration: {:?}", started.elapsed());
    println!("CLI stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    println!("CLI stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    output
}

fn run_success(bin: &str, vault_root: &PathBuf, agent_root: &PathBuf, args: &[&str]) {
    let output = run_output_in(bin, args, vault_root, agent_root);
    assert_success(&output);
}

fn agent_log_path(agent_root: &PathBuf) -> PathBuf {
    agent_root.join("agent.log")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

enum PeerMode {
    BothDirections,
}

struct TwoServerCluster {
    _guard: TempDir,
    primary: RunningServer,
    standby: RunningServer,
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
                last_seen_ms: None,
            },
            TopologyServer {
                id: 1,
                url: standby_url.clone(),
                status: ServerStatus::Promoted,
                last_seen_ms: None,
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
        }

        let primary = RunningServer::start(primary_listener, primary_config);
        let standby = RunningServer::start(standby_listener, standby_config);

        Self {
            _guard: guard,
            primary,
            standby,
            topology_servers,
            topology_routes,
        }
    }

    fn pool_with_dead_server(&self, dead_server_id: u8) -> ShareClientPool {
        let mut servers = self.topology_servers.clone();
        if let Some(server) = servers
            .iter_mut()
            .find(|server| server.id == dead_server_id)
        {
            server.url = unused_share_url();
        }
        let topology = lockbox_share_protocol::ClusterTopology {
            cluster_id: "cli-integration".to_string(),
            version: 1,
            servers,
            routes: self.topology_routes.clone(),
        };
        ShareClientPool::from_topology(&topology)
            .unwrap()
            .with_timeout(Duration::from_millis(150))
            .with_retry_policy(100, Duration::from_millis(5), Duration::from_millis(250))
    }

    fn primary_url(&self) -> String {
        self.primary.share_url()
    }

    fn topology_url(&self) -> String {
        format!(
            "{}/v1/topology",
            self.primary_url().trim_end_matches("/v1/share")
        )
    }
}

struct RunningServer {
    addr: SocketAddr,
    store: std::sync::Arc<ShareStore>,
}

impl RunningServer {
    fn start(listener: TcpListener, config: ServerConfig) -> Self {
        let addr = listener.local_addr().unwrap();
        let store = std::sync::Arc::new(ShareStore::open(config).unwrap());
        let server_store = std::sync::Arc::clone(&store);
        thread::spawn(move || {
            let _ = run_listener(listener, server_store);
        });
        wait_for_http(addr);
        Self { addr, store }
    }

    fn share_url(&self) -> String {
        share_url(self.addr)
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
        compact_min_bytes: 1024 * 1024,
        index_cache_entries: 100_000,
        rate_limit_per_minute: 0,
        rate_limit_burst: 1_000,
        ..ServerConfig::default()
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

fn wait_for_http(addr: SocketAddr) {
    wait_until("server listener", Duration::from_secs(5), || {
        std::net::TcpStream::connect(addr).is_ok()
    });
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

static TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_roots(label: &str) -> (PathBuf, PathBuf) {
    let vault_root = temp_dir(&format!("{label}-vault"));
    let agent_root = temp_dir(&format!("{label}-agent"));
    let _ = fs::remove_dir_all(&vault_root);
    let _ = fs::remove_dir_all(&agent_root);
    fs::create_dir_all(&vault_root).unwrap();
    fs::create_dir_all(&agent_root).unwrap();
    (vault_root, agent_root)
}

fn has_loopback_sockets() -> bool {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => false,
        Err(error) => panic!("unable to bind 127.0.0.1:0 for local e2e server: {error}"),
    }
}

fn temp_dir(label: &str) -> PathBuf {
    let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!(
            "lockbox-cli-share-{label}-{}-{counter}-{nanos}",
            std::process::id()
        ))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/test-tmp")
            .join(format!(
                "lockbox-share-e2e-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
