use crate::client::ClientError;
use crate::protocol::{self, ProtocolError, Reader};

const STATUS_MAGIC: &[u8; 4] = b"LBSS";
const STATUS_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareServerStatus {
    pub created: u64,
    pub fetched: u64,
    pub deleted: u64,
    pub expired: u64,
    pub misses: u64,
    pub live: u64,
    pub segment_bytes: u64,
    pub replication_pending: u64,
    pub replication_last_sequence: u64,
}

pub fn encode_status(status: &ShareServerStatus) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 + 9 * 8);
    out.extend_from_slice(STATUS_MAGIC);
    protocol::put_u16(&mut out, STATUS_VERSION);
    protocol::put_u64(&mut out, status.created);
    protocol::put_u64(&mut out, status.fetched);
    protocol::put_u64(&mut out, status.deleted);
    protocol::put_u64(&mut out, status.expired);
    protocol::put_u64(&mut out, status.misses);
    protocol::put_u64(&mut out, status.live);
    protocol::put_u64(&mut out, status.segment_bytes);
    protocol::put_u64(&mut out, status.replication_pending);
    protocol::put_u64(&mut out, status.replication_last_sequence);
    out
}

pub fn decode_status(bytes: &[u8]) -> Result<ShareServerStatus, ClientError> {
    let mut reader = Reader::new(bytes);
    let magic = reader
        .fixed_bytes(STATUS_MAGIC.len())
        .map_err(status_protocol_error)?;
    if magic != STATUS_MAGIC {
        return Err(ClientError::Protocol(ProtocolError::BadMagic));
    }
    let version = reader.u16().map_err(status_protocol_error)?;
    if version != STATUS_VERSION {
        return Err(ClientError::Protocol(ProtocolError::UnsupportedVersion));
    }
    Ok(ShareServerStatus {
        created: reader.u64().map_err(status_protocol_error)?,
        fetched: reader.u64().map_err(status_protocol_error)?,
        deleted: reader.u64().map_err(status_protocol_error)?,
        expired: reader.u64().map_err(status_protocol_error)?,
        misses: reader.u64().map_err(status_protocol_error)?,
        live: reader.u64().map_err(status_protocol_error)?,
        segment_bytes: reader.u64().map_err(status_protocol_error)?,
        replication_pending: reader.u64().map_err(status_protocol_error)?,
        replication_last_sequence: reader.u64().map_err(status_protocol_error)?,
    })
}

fn status_protocol_error(err: ProtocolError) -> ClientError {
    ClientError::Protocol(err)
}
