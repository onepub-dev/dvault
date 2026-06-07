use std::cell::RefCell;
use std::time::Duration;

use lockbox_share_protocol::client::{ContactShare, ShareClient, ShareClientPool, Transport};
use lockbox_share_protocol::protocol::{self, Operation, Status};
use lockbox_share_protocol::{
    decode_replication_request, encode_replication_request, sign_replication_event,
    ReplicationEvent, ReplicationEventKind, ReplicationRequest, ShareServerStatus,
};
use lockbox_share_protocol::{ClusterTopology, ServerStatus, TopologyRoute, TopologyServer};

#[derive(Clone)]
struct MockTransport {
    responses: std::rc::Rc<RefCell<Vec<Vec<u8>>>>,
    calls: std::rc::Rc<RefCell<usize>>,
}

#[derive(Clone)]
struct FlakyTransport {
    response: Vec<u8>,
    calls: std::rc::Rc<RefCell<usize>>,
}

impl FlakyTransport {
    fn new(response: Vec<u8>) -> Self {
        Self {
            response,
            calls: std::rc::Rc::new(RefCell::new(0)),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.borrow()
    }
}

impl Transport for FlakyTransport {
    fn post_binary(&self, _body: &[u8]) -> Result<Vec<u8>, lockbox_share_protocol::ClientError> {
        let mut calls = self.calls.borrow_mut();
        *calls += 1;
        if *calls == 1 {
            return Err(lockbox_share_protocol::ClientError::Io(
                std::io::ErrorKind::WouldBlock.into(),
            ));
        }
        Ok(self.response.clone())
    }
}

impl MockTransport {
    fn new(responses: Vec<Vec<u8>>) -> Self {
        Self {
            responses: std::rc::Rc::new(RefCell::new(responses)),
            calls: std::rc::Rc::new(RefCell::new(0)),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.borrow()
    }
}

impl Transport for MockTransport {
    fn post_binary(&self, _body: &[u8]) -> Result<Vec<u8>, lockbox_share_protocol::ClientError> {
        *self.calls.borrow_mut() += 1;
        Ok(self.responses.borrow_mut().remove(0))
    }
}

#[test]
fn client_decodes_share_fetch_and_delete_responses() {
    let payload = lockbox_share_protocol::encode_contact_share(
        "client@example.com",
        b"public-key-material",
        &[1_u8; 32],
        &[2_u8; 24],
        1,
        2,
    );
    let mut share_response = Vec::new();
    protocol::put_u16(&mut share_response, protocol::MESSAGE_VERSION);
    protocol::put_string(&mut share_response, "123456789012");
    protocol::put_bytes(&mut share_response, b"delete-token");
    protocol::put_u64(&mut share_response, 2);
    protocol::put_u16(&mut share_response, 1);

    let mut fetch_response = Vec::new();
    protocol::put_u16(&mut fetch_response, protocol::MESSAGE_VERSION);
    protocol::put_bytes(&mut fetch_response, &payload);
    protocol::put_u64(&mut fetch_response, 2);
    protocol::put_u16(&mut fetch_response, 0);

    let mut delete_response = Vec::new();
    protocol::put_u16(&mut delete_response, protocol::MESSAGE_VERSION);
    delete_response.push(1);

    let transport = MockTransport::new(vec![
        protocol::encode_response(Operation::Share, Status::Success, &share_response),
        protocol::encode_response(Operation::Fetch, Status::Success, &fetch_response),
        protocol::encode_response(Operation::Delete, Status::Success, &delete_response),
    ]);
    let client = ShareClient::from_transport(transport);

    let shared = client
        .share_contact(
            900,
            1,
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
    assert_eq!(shared.share_code, "123456789012");

    let fetched = client.fetch(&shared.share_code).unwrap();
    assert_eq!(
        fetched.payload_type,
        lockbox_share_protocol::PayloadType::ContactShare
    );
    assert_eq!(fetched.remaining_fetches, 0);

    assert!(client
        .delete(&shared.share_code, &shared.delete_token)
        .unwrap());
}

#[test]
fn client_retries_transient_transport_errors() {
    let mut share_response = Vec::new();
    protocol::put_u16(&mut share_response, protocol::MESSAGE_VERSION);
    protocol::put_string(&mut share_response, "123456789012");
    protocol::put_bytes(&mut share_response, b"delete-token");
    protocol::put_u64(&mut share_response, 2);
    protocol::put_u16(&mut share_response, 1);

    let transport = FlakyTransport::new(protocol::encode_response(
        Operation::Share,
        Status::Success,
        &share_response,
    ));
    let client = ShareClient::from_transport(transport.clone()).with_retry_policy(
        2,
        Duration::ZERO,
        Duration::ZERO,
    );

    let shared = client
        .share_contact(
            900,
            1,
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

    assert_eq!(shared.share_code, "123456789012");
    assert_eq!(transport.calls(), 2);
}

#[test]
fn client_surfaces_versioned_server_errors() {
    let mut error = Vec::new();
    protocol::put_u16(&mut error, protocol::MESSAGE_VERSION);
    protocol::put_u16(&mut error, Status::ShareNotFound as u16);
    protocol::put_string(&mut error, "share not found");

    let client = ShareClient::from_transport(MockTransport::new(vec![protocol::encode_response(
        Operation::Fetch,
        Status::ShareNotFound,
        &error,
    )]));
    let err = client.fetch("123456789012").unwrap_err();

    assert!(err.to_string().contains("ShareNotFound"));
    assert!(err.to_string().contains("share not found"));
}

#[test]
fn client_pool_fetches_from_later_server_when_first_misses() {
    let payload = lockbox_share_protocol::encode_contact_share(
        "cluster@example.com",
        b"public-key-material",
        &[1_u8; 32],
        &[2_u8; 24],
        1,
        2,
    );
    let mut error = Vec::new();
    protocol::put_u16(&mut error, protocol::MESSAGE_VERSION);
    protocol::put_u16(&mut error, Status::ShareNotFound as u16);
    protocol::put_string(&mut error, "share not found");
    let mut fetch_response = Vec::new();
    protocol::put_u16(&mut fetch_response, protocol::MESSAGE_VERSION);
    protocol::put_bytes(&mut fetch_response, &payload);
    protocol::put_u64(&mut fetch_response, 2);
    protocol::put_u16(&mut fetch_response, 0);

    let client = ShareClientPool::from_transports(vec![
        MockTransport::new(vec![protocol::encode_response(
            Operation::Fetch,
            Status::ShareNotFound,
            &error,
        )]),
        MockTransport::new(vec![protocol::encode_response(
            Operation::Fetch,
            Status::Success,
            &fetch_response,
        )]),
    ])
    .unwrap();

    let fetched = client.fetch("123456789012").unwrap();
    assert_eq!(
        fetched.payload_type,
        lockbox_share_protocol::PayloadType::ContactShare
    );
}

#[test]
fn client_pool_prefers_server_id_from_share_code_prefix() {
    let payload = lockbox_share_protocol::encode_contact_share(
        "cluster@example.com",
        b"public-key-material",
        &[1_u8; 32],
        &[2_u8; 24],
        1,
        2,
    );
    let mut fetch_response = Vec::new();
    protocol::put_u16(&mut fetch_response, protocol::MESSAGE_VERSION);
    protocol::put_bytes(&mut fetch_response, &payload);
    protocol::put_u64(&mut fetch_response, 2);
    protocol::put_u16(&mut fetch_response, 0);
    let server_0 = MockTransport::new(vec![protocol::encode_response(
        Operation::Fetch,
        Status::Success,
        &fetch_response,
    )]);
    let server_1 = MockTransport::new(vec![protocol::encode_response(
        Operation::Fetch,
        Status::Success,
        &fetch_response,
    )]);

    let client =
        ShareClientPool::from_transports(vec![server_0.clone(), server_1.clone()]).unwrap();

    let fetched = client.fetch("1123456789012").unwrap();
    assert_eq!(
        fetched.payload_type,
        lockbox_share_protocol::PayloadType::ContactShare
    );
    assert_eq!(server_0.calls(), 0);
    assert_eq!(server_1.calls(), 1);
}

#[test]
fn client_pool_uses_topology_failover_order() {
    let payload = lockbox_share_protocol::encode_contact_share(
        "cluster@example.com",
        b"public-key-material",
        &[1_u8; 32],
        &[2_u8; 24],
        1,
        2,
    );
    let mut error = Vec::new();
    protocol::put_u16(&mut error, protocol::MESSAGE_VERSION);
    protocol::put_u16(&mut error, Status::ShareNotFound as u16);
    protocol::put_string(&mut error, "share not found");
    let mut fetch_response = Vec::new();
    protocol::put_u16(&mut fetch_response, protocol::MESSAGE_VERSION);
    protocol::put_bytes(&mut fetch_response, &payload);
    protocol::put_u64(&mut fetch_response, 2);
    protocol::put_u16(&mut fetch_response, 0);
    let server_0 = MockTransport::new(vec![protocol::encode_response(
        Operation::Fetch,
        Status::Success,
        &fetch_response,
    )]);
    let server_1 = MockTransport::new(vec![protocol::encode_response(
        Operation::Fetch,
        Status::ShareNotFound,
        &error,
    )]);
    let server_2 = MockTransport::new(vec![protocol::encode_response(
        Operation::Fetch,
        Status::Success,
        &fetch_response,
    )]);

    let client = ShareClientPool::from_clients_with_ids(
        vec![
            ShareClient::from_transport(server_0.clone()),
            ShareClient::from_transport(server_1.clone()),
            ShareClient::from_transport(server_2.clone()),
        ],
        vec![0, 1, 2],
        vec![TopologyRoute {
            owner_id: 1,
            primary_id: 1,
            failover_ids: vec![2],
        }],
    )
    .unwrap();

    assert_eq!(client.fetch("1123456789012").unwrap().payload, payload);
    assert_eq!(server_0.calls(), 0);
    assert_eq!(server_1.calls(), 1);
    assert_eq!(server_2.calls(), 1);
}

#[test]
fn topology_binary_round_trips_and_validates_routes() {
    let topology = ClusterTopology {
        cluster_id: "acme".to_string(),
        version: 42,
        servers: vec![
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
        ],
        routes: vec![TopologyRoute {
            owner_id: 0,
            primary_id: 0,
            failover_ids: vec![1],
        }],
    };

    let bytes = lockbox_share_protocol::encode_topology(&topology).unwrap();
    let decoded = lockbox_share_protocol::decode_topology(&bytes).unwrap();
    assert_eq!(decoded, topology);
    assert_eq!(
        decoded.urls_for_share_code("0123456789012"),
        vec![
            "http://share0.example/v1/share".to_string(),
            "http://share1.example/v1/share".to_string()
        ]
    );
}

#[test]
fn topology_cache_round_trips_binary_documents() {
    let topology = ClusterTopology::single_server(0, "http://share0.example/v1/share");
    let path = std::env::temp_dir().join(format!(
        "lockbox-share-topology-cache-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    lockbox_share_protocol::write_topology_cache(&path, &topology).unwrap();

    let cached = lockbox_share_protocol::read_topology_cache(&path, Duration::from_secs(60))
        .unwrap()
        .unwrap();
    assert_eq!(cached, topology);
    assert!(
        lockbox_share_protocol::read_topology_cache(&path, Duration::from_millis(1))
            .unwrap()
            .is_some()
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn replication_request_round_trips_binary_events() {
    let event = ReplicationEvent {
        origin_server_id: 2,
        origin_epoch: 3,
        origin_sequence: 4,
        kind: ReplicationEventKind::PutShare {
            share_code: "2123456789012".to_string(),
            delete_token_hash: vec![9_u8; 16],
            payload: lockbox_share_protocol::encode_contact_share(
                "replica@example.com",
                b"public-key-material",
                &[1_u8; 32],
                &[2_u8; 24],
                1,
                2,
            ),
            expires_at_unix_ms: 123,
            max_fetches: 2,
            fetches: 1,
        },
    };
    let request = ReplicationRequest {
        authentication: sign_replication_event(b"peer-secret", &event),
        event,
    };

    let envelope = protocol::decode_request(&encode_replication_request(&request), 4096).unwrap();
    assert_eq!(envelope.operation, Operation::Replicate);
    assert_eq!(
        decode_replication_request(&envelope.payload).unwrap(),
        request
    );
}

#[test]
fn server_status_round_trips_binary_documents() {
    let status = ShareServerStatus {
        created: 1,
        fetched: 2,
        deleted: 3,
        expired: 4,
        misses: 5,
        live: 6,
        segment_bytes: 7,
        replication_pending: 8,
        replication_last_sequence: 9,
    };
    let bytes = lockbox_share_protocol::encode_status(&status);
    assert_eq!(
        lockbox_share_protocol::decode_status(&bytes).unwrap(),
        status
    );
}

#[test]
fn http_transport_accepts_https_urls() {
    assert!(
        lockbox_share_protocol::HttpTransport::new("https://keyshare.onepub.dev/v1/share").is_ok()
    );
    assert!(lockbox_share_protocol::HttpTransport::new("https://keyshare.onepub.dev").is_ok());
    assert!(lockbox_share_protocol::HttpTransport::new("ftp://keyshare.onepub.dev").is_err());
}

#[test]
fn client_pool_deletes_from_later_server_when_first_misses() {
    let mut delete_miss = Vec::new();
    protocol::put_u16(&mut delete_miss, protocol::MESSAGE_VERSION);
    delete_miss.push(0);
    let mut delete_success = Vec::new();
    protocol::put_u16(&mut delete_success, protocol::MESSAGE_VERSION);
    delete_success.push(1);

    let client = ShareClientPool::from_transports(vec![
        MockTransport::new(vec![protocol::encode_response(
            Operation::Delete,
            Status::Success,
            &delete_miss,
        )]),
        MockTransport::new(vec![protocol::encode_response(
            Operation::Delete,
            Status::Success,
            &delete_success,
        )]),
    ])
    .unwrap();

    assert!(client.delete("123456789012", b"delete-token").unwrap());
}
