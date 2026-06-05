use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lockbox_share_protocol::client::{ContactShare, ShareClient};
use lockbox_share_protocol::protocol::{
    decode_request, encode_delete_request, encode_fetch_request, encode_share_request, Operation,
    Reader, Status,
};
use lockbox_share_protocol::{
    encode_replication_request, sign_replication_event, ReplicationEvent, ReplicationEventKind,
    ReplicationRequest, ServerStatus, TopologyRoute, TopologyServer,
};
use lockbox_share_server::store::{ServerConfig, ShareStore};

fn contact_payload(label: &str) -> Vec<u8> {
    lockbox_share_protocol::payload::encode_contact_share(
        &format!("{label}@example.com"),
        b"public-key-material",
        &[1_u8; 32],
        &[2_u8; 24],
        1,
        2,
    )
}

fn key_replacement_payload(label: &str) -> Vec<u8> {
    lockbox_share_protocol::payload::encode_key_replacement(
        lockbox_share_protocol::payload::KeyReplacement {
            identity: &format!("{label}@example.com"),
            old_fingerprint: &[3_u8; 32],
            new_public_key: b"replacement-public-key-material",
            new_fingerprint: &[4_u8; 32],
            replacement_nonce: &[5_u8; 24],
            signature_by_old_key: b"signature-by-old-key",
            created_at_unix_ms: 1,
            expires_at_unix_ms: 2,
        },
    )
}

#[test]
fn protocol_round_trips_share_request() {
    let request = encode_share_request(900, 3, b"candidate");
    let decoded = decode_request(&request, 1024).unwrap();
    assert_eq!(decoded.operation, Operation::Share);

    let mut reader = Reader::new(&decoded.payload);
    reader.message_version().unwrap();
    assert_eq!(reader.u32().unwrap(), 900);
    assert_eq!(reader.u16().unwrap(), 3);
    assert_eq!(reader.bytes().unwrap(), b"candidate");
}

#[test]
fn store_creates_fetches_and_deletes_share() {
    let (_guard, config) = temp_config("flow");
    let store = ShareStore::open(config).unwrap();
    let payload = contact_payload("flow");

    let create = store
        .create_from_payload(
            &decode_request(&encode_share_request(900, 2, &payload), 2048)
                .unwrap()
                .payload,
        )
        .unwrap();

    let fetched = store.fetch(&create.share_code).unwrap();
    assert_eq!(fetched.payload, payload);
    assert_eq!(fetched.remaining_fetches, 1);

    assert!(store
        .delete(&create.share_code, &create.delete_token)
        .unwrap());
    assert!(store.fetch(&create.share_code).is_err());
}

#[test]
fn store_enforces_fetch_limit() {
    let (_guard, config) = temp_config("fetch-limit");
    let store = ShareStore::open(config).unwrap();
    let payload = contact_payload("fetch-limit");
    let create = store
        .create_from_payload(
            &decode_request(&encode_share_request(900, 1, &payload), 2048)
                .unwrap()
                .payload,
        )
        .unwrap();

    assert!(store.fetch(&create.share_code).is_ok());
    assert!(store.fetch(&create.share_code).is_err());
}

#[test]
fn share_codes_use_configured_digit_count() {
    let (_guard, mut config) = temp_config("code-digits");
    config.server_id = 7;
    config.share_code_digits = 10;
    let store = ShareStore::open(config).unwrap();
    let payload = contact_payload("code-digits");
    let create = store
        .create_from_payload(
            &decode_request(&encode_share_request(900, 1, &payload), 2048)
                .unwrap()
                .payload,
        )
        .unwrap();

    assert_eq!(create.share_code.len(), 11);
    assert!(create.share_code.starts_with('7'));
    assert!(create
        .share_code
        .chars()
        .all(|character| character.is_ascii_digit()));
}

#[test]
fn store_rejects_invalid_server_id() {
    let (_guard, mut config) = temp_config("bad-server-id");
    config.server_id = 10;
    match ShareStore::open(config) {
        Ok(_) => panic!("invalid server id should be rejected"),
        Err(err) => assert!(err.to_string().contains("server id")),
    }
}

#[test]
fn store_publishes_configured_topology() {
    let (_guard, mut config) = temp_config("topology");
    config.cluster_id = "acme".to_string();
    config.topology_version = 7;
    config.topology_servers = vec![
        TopologyServer {
            id: 0,
            url: "http://share0.example/v1/share".to_string(),
            status: ServerStatus::Active,
        },
        TopologyServer {
            id: 1,
            url: "http://share1.example/v1/share".to_string(),
            status: ServerStatus::Standby,
        },
    ];
    config.topology_routes = vec![TopologyRoute {
        owner_id: 0,
        primary_id: 0,
        failover_ids: vec![1],
    }];
    let store = ShareStore::open(config).unwrap();
    let topology = store.topology();

    assert_eq!(topology.cluster_id, "acme");
    assert_eq!(topology.version, 7);
    assert_eq!(topology.servers.len(), 2);
    assert_eq!(topology.routes[0].failover_ids, vec![1]);
    lockbox_share_protocol::encode_topology(&topology).unwrap();
}

#[test]
fn replicated_share_is_served_only_after_owner_promotion() {
    let (_guard, mut config) = temp_config("replica-promote");
    config.server_id = 1;
    config.replication_token = Some("peer-secret".to_string());
    let store = ShareStore::open(config).unwrap();
    let payload = contact_payload("replica-promote");
    let event = ReplicationEvent {
        origin_server_id: 0,
        origin_epoch: 1,
        origin_sequence: 1,
        kind: ReplicationEventKind::PutShare {
            share_code: "0123456789012".to_string(),
            delete_token_hash: vec![9_u8; 16],
            payload: payload.clone(),
            expires_at_unix_ms: unix_ms_now() + 900_000,
            max_fetches: 1,
            fetches: 0,
        },
    };
    let request = encode_replication_request(&ReplicationRequest {
        authentication: sign_replication_event(b"peer-secret", &event),
        event,
    });
    let request = decode_request(&request, 4096).unwrap();
    assert_eq!(request.operation, Operation::Replicate);
    assert!(store.apply_replication_payload(&request.payload).unwrap());

    assert!(store.fetch("0123456789012").is_err());

    let (_guard, mut config) = temp_config("replica-promoted");
    config.server_id = 1;
    config.replication_token = Some("peer-secret".to_string());
    config.promoted_owner_ids.push(0);
    let store = ShareStore::open(config).unwrap();
    let event = ReplicationEvent {
        origin_server_id: 0,
        origin_epoch: 1,
        origin_sequence: 1,
        kind: ReplicationEventKind::PutShare {
            share_code: "0123456789012".to_string(),
            delete_token_hash: vec![9_u8; 16],
            payload: payload.clone(),
            expires_at_unix_ms: unix_ms_now() + 900_000,
            max_fetches: 1,
            fetches: 0,
        },
    };
    let request = encode_replication_request(&ReplicationRequest {
        authentication: sign_replication_event(b"peer-secret", &event),
        event,
    });
    let request = decode_request(&request, 4096).unwrap();
    assert!(store.apply_replication_payload(&request.payload).unwrap());
    assert_eq!(store.fetch("0123456789012").unwrap().payload, payload);
}

#[test]
fn replication_sequence_is_idempotent_after_restart() {
    let (_guard, mut config) = temp_config("replica-idempotent");
    config.server_id = 1;
    config.replication_token = Some("peer-secret".to_string());
    config.promoted_owner_ids.push(0);
    let payload = contact_payload("replica-idempotent");
    let event = ReplicationEvent {
        origin_server_id: 0,
        origin_epoch: 2,
        origin_sequence: 7,
        kind: ReplicationEventKind::PutShare {
            share_code: "0123456789012".to_string(),
            delete_token_hash: vec![9_u8; 16],
            payload: payload.clone(),
            expires_at_unix_ms: unix_ms_now() + 900_000,
            max_fetches: 2,
            fetches: 0,
        },
    };
    let request = encode_replication_request(&ReplicationRequest {
        authentication: sign_replication_event(b"peer-secret", &event),
        event,
    });
    let request = decode_request(&request, 4096).unwrap();
    {
        let store = ShareStore::open(config.clone()).unwrap();
        assert!(store.apply_replication_payload(&request.payload).unwrap());
    }
    let store = ShareStore::open(config).unwrap();
    assert!(!store.apply_replication_payload(&request.payload).unwrap());
    assert_eq!(store.fetch("0123456789012").unwrap().payload, payload);
}

#[test]
fn store_rejects_untyped_payload_bytes() {
    let (_guard, config) = temp_config("reject-untyped");
    let store = ShareStore::open(config).unwrap();
    let request = decode_request(&encode_share_request(900, 1, b"random crap"), 2048).unwrap();

    assert!(store.create_from_payload(&request.payload).is_err());

    let response = store.handle(request.operation, &request.payload);
    assert_status(&response, Status::MalformedRequest);
}

#[test]
fn store_accepts_versioned_key_replacement_payload() {
    let (_guard, config) = temp_config("key-replacement");
    let store = ShareStore::open(config).unwrap();
    let payload = key_replacement_payload("key-replacement");
    let create = store
        .create_from_payload(
            &decode_request(&encode_share_request(900, 1, &payload), 2048)
                .unwrap()
                .payload,
        )
        .unwrap();

    assert_eq!(store.fetch(&create.share_code).unwrap().payload, payload);
}

#[test]
fn payload_validator_rejects_bad_message_version() {
    let mut payload = contact_payload("bad-version");
    payload[4..6].copy_from_slice(&2_u16.to_be_bytes());

    assert!(lockbox_share_protocol::payload::validate_payload(&payload).is_err());
}

#[test]
fn delete_request_rejects_bad_message_version() {
    let (_guard, config) = temp_config("bad-delete-version");
    let store = ShareStore::open(config).unwrap();
    let payload = contact_payload("bad-delete-version");
    let create = store
        .create_from_payload(
            &decode_request(&encode_share_request(900, 1, &payload), 2048)
                .unwrap()
                .payload,
        )
        .unwrap();
    let mut request = decode_request(
        &encode_delete_request(&create.share_code, &create.delete_token),
        1024,
    )
    .unwrap();
    request.payload[0..2].copy_from_slice(&2_u16.to_be_bytes());

    let response = store.handle(request.operation, &request.payload);
    assert_status(&response, Status::MalformedRequest);
}

#[test]
fn store_replays_live_records_from_disk() {
    let (guard, config) = temp_config("replay");
    let payload = contact_payload("replay");
    let share_code = {
        let store = ShareStore::open(config.clone()).unwrap();
        store
            .create_from_payload(
                &decode_request(&encode_share_request(900, 1, &payload), 2048)
                    .unwrap()
                    .payload,
            )
            .unwrap()
            .share_code
    };

    let reopened = ShareStore::open(config).unwrap();
    assert_eq!(reopened.fetch(&share_code).unwrap().payload, payload);
    drop(guard);
}

#[test]
fn store_replays_fetch_count_after_restart() {
    let (_guard, config) = temp_config("fetch-count-replay");
    let payload = contact_payload("fetch-count-replay");
    let share_code = {
        let store = ShareStore::open(config.clone()).unwrap();
        let create = store
            .create_from_payload(
                &decode_request(&encode_share_request(900, 2, &payload), 2048)
                    .unwrap()
                    .payload,
            )
            .unwrap();
        assert_eq!(
            store.fetch(&create.share_code).unwrap().remaining_fetches,
            1
        );
        create.share_code
    };

    let reopened = ShareStore::open(config).unwrap();
    assert_eq!(reopened.fetch(&share_code).unwrap().remaining_fetches, 0);
    assert!(reopened.fetch(&share_code).is_err());
}

#[test]
fn store_does_not_resurrect_exhausted_share_after_restart() {
    let (_guard, config) = temp_config("exhausted-replay");
    let payload = contact_payload("exhausted-replay");
    let share_code = {
        let store = ShareStore::open(config.clone()).unwrap();
        let create = store
            .create_from_payload(
                &decode_request(&encode_share_request(900, 1, &payload), 2048)
                    .unwrap()
                    .payload,
            )
            .unwrap();
        assert_eq!(
            store.fetch(&create.share_code).unwrap().remaining_fetches,
            0
        );
        create.share_code
    };

    let reopened = ShareStore::open(config).unwrap();
    assert!(reopened.fetch(&share_code).is_err());
}

#[test]
fn single_use_share_is_removed_as_soon_as_it_is_fetched() {
    let (_guard, config) = temp_config("single-use-delete");
    let payload = contact_payload("single-use-delete");
    let share_code = {
        let store = ShareStore::open(config.clone()).unwrap();
        let create = store
            .create_from_payload(
                &decode_request(&encode_share_request(900, 0, &payload), 2048)
                    .unwrap()
                    .payload,
            )
            .unwrap();
        assert_eq!(create.max_fetches, 1);
        assert_eq!(
            store.fetch(&create.share_code).unwrap().remaining_fetches,
            0
        );
        assert_eq!(store.stats().live, 0);
        create.share_code
    };

    let reopened = ShareStore::open(config).unwrap();
    assert!(reopened.fetch(&share_code).is_err());
    assert_eq!(reopened.stats().live, 0);
}

#[test]
fn store_replays_large_persistent_store() {
    let (_guard, config) = temp_config("large-replay");
    let mut expected = Vec::with_capacity(20_000);
    {
        let store = ShareStore::open(config.clone()).unwrap();
        for index in 0..20_000_u32 {
            let payload = contact_payload(&format!("large-{index}"));
            let request = encode_share_request(900, 1, &payload);
            let create = store
                .create_from_payload(&decode_request(&request, 2048).unwrap().payload)
                .unwrap();
            if index % 997 == 0 {
                expected.push((create.share_code, payload));
            }
        }
        assert_eq!(store.stats().live, 20_000);
    }

    let reopened = ShareStore::open(config).unwrap();
    assert_eq!(reopened.stats().live, 20_000);
    for (share_code, payload) in expected {
        assert_eq!(reopened.fetch(&share_code).unwrap().payload, payload);
    }
}

#[test]
fn compaction_removes_tombstoned_single_use_backlog() {
    let (_guard, config) = temp_config("compact-empty");
    let store = ShareStore::open(config).unwrap();
    let payload = contact_payload("compact-empty");
    for _ in 0..1_000 {
        let request = encode_share_request(900, 1, &payload);
        let create = store
            .create_from_payload(&decode_request(&request, 2048).unwrap().payload)
            .unwrap();
        assert!(store.fetch(&create.share_code).is_ok());
    }

    assert_eq!(store.stats().live, 0);
    assert!(store.stats().segment_bytes > 0);
    let report = store.compact().unwrap();
    assert!(report.bytes_before > report.bytes_after);
    assert_eq!(store.stats().segment_bytes, 0);
}

#[test]
fn compaction_preserves_live_records() {
    let (_guard, config) = temp_config("compact-live");
    let store = ShareStore::open(config).unwrap();
    let mut live = Vec::new();
    for index in 0..1_000_u32 {
        let payload = contact_payload(&format!("compact-live-{index}"));
        let request = encode_share_request(900, 2, &payload);
        let create = store
            .create_from_payload(&decode_request(&request, 2048).unwrap().payload)
            .unwrap();
        if index % 100 == 0 {
            live.push((create.share_code, payload));
        }
    }

    let before = store.stats().segment_bytes;
    let report = store.compact().unwrap();
    assert!(report.bytes_after <= before);
    for (share_code, payload) in live {
        assert_eq!(store.fetch(&share_code).unwrap().payload, payload);
    }
}

#[test]
fn encoded_requests_are_accepted_by_store_handler() {
    let (_guard, config) = temp_config("handler");
    let store = ShareStore::open(config).unwrap();
    let payload = contact_payload("handler");

    let request = decode_request(&encode_share_request(900, 1, &payload), 2048).unwrap();
    let response = store.handle(request.operation, &request.payload);
    assert_success(&response);
    let mut reader = Reader::new(&response[14..]);
    reader.message_version().unwrap();
    let share_code = reader.string().unwrap();
    let delete_token = reader.bytes().unwrap();

    let request = decode_request(&encode_fetch_request(&share_code), 1024).unwrap();
    let response = store.handle(request.operation, &request.payload);
    assert_success(&response);

    let request = decode_request(&encode_delete_request(&share_code, &delete_token), 1024).unwrap();
    let response = store.handle(request.operation, &request.payload);
    assert_success(&response);
}

#[test]
#[ignore = "requires local TCP sockets, which are blocked in the test sandbox"]
fn client_api_can_share_fetch_and_delete() {
    let (_guard, config) = temp_config("client-api");
    let store = Arc::new(ShareStore::open(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_store = Arc::clone(&store);
    thread::spawn(move || {
        let _ = lockbox_share_server::server::run_listener(listener, server_store);
    });
    thread::sleep(Duration::from_millis(50));

    let client = ShareClient::new(&format!("http://{addr}/v1/share")).unwrap();
    let shared = client
        .share_contact(
            900,
            2,
            ContactShare {
                identity: "client@example.com",
                public_key: b"public-key-material",
                fingerprint: &[1_u8; 32],
                share_nonce: &[2_u8; 24],
                created_at_unix_ms: 1,
                expires_at_unix_ms: 2,
            },
        )
        .unwrap();
    assert_eq!(shared.max_fetches, 2);

    let fetched = client.fetch(&shared.share_code).unwrap();
    assert_eq!(
        fetched.payload_type,
        lockbox_share_protocol::payload::PayloadType::ContactShare
    );
    assert_eq!(fetched.remaining_fetches, 1);

    assert!(client
        .delete(&shared.share_code, &shared.delete_token)
        .unwrap());
}

fn assert_success(response: &[u8]) {
    assert_status(response, Status::Success);
}

fn assert_status(response: &[u8], status: Status) {
    assert_eq!(&response[0..4], b"LBSR");
    assert_eq!(
        u16::from_be_bytes([response[6], response[7]]),
        status as u16
    );
}

fn temp_config(name: &str) -> (TempGuard, ServerConfig) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "lockbox-share-server-{name}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    let config = ServerConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        state_dir: path.clone(),
        server_id: 0,
        cluster_id: "default".to_string(),
        public_url: None,
        topology_version: 1,
        topology_servers: Vec::new(),
        topology_routes: Vec::new(),
        replication_token: None,
        replication_peer_urls: Vec::new(),
        origin_epoch: 1,
        promoted_owner_ids: Vec::new(),
        max_payload_bytes: 1024,
        default_ttl: Duration::from_secs(900),
        max_ttl: Duration::from_secs(3600),
        shard_count: 4,
        developer_mode: false,
        benchmark_requests: 50_000,
        benchmark_payload_bytes: 512,
        benchmark_concurrency: 0,
        benchmark_preload_shares: 0,
        max_fetches_per_share: 8,
        share_code_digits: 12,
        compact_min_bytes: 1,
        index_cache_entries: 65_536,
        rate_limit_per_minute: 120,
        rate_limit_burst: 40,
    };
    (TempGuard(path), config)
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

struct TempGuard(PathBuf);

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
