use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{Error, Result};

pub(crate) fn seal(payload: &[u8], key: &[u8], sequence: u64, kind: u8) -> Vec<u8> {
    let mut content_key = derive_content_key(key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&content_key));
    content_key.zeroize();
    let nonce = segment_nonce(sequence, kind);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &segment_aad(sequence, kind),
            },
        )
        .expect("ChaCha20-Poly1305 encryption should not fail")
}

pub(crate) fn open(payload: &[u8], key: &[u8], sequence: u64, kind: u8) -> Result<Vec<u8>> {
    let mut content_key = derive_content_key(key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&content_key));
    content_key.zeroize();
    let nonce = segment_nonce(sequence, kind);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &segment_aad(sequence, kind),
            },
        )
        .map_err(|_| Error::InvalidKey)
}

pub(crate) fn checksum(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn derive_content_key(key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"lockbox-v2-content-key/chacha20poly1305");
    hasher.update((key.len() as u64).to_le_bytes());
    hasher.update(key);
    hasher.finalize().into()
}

fn segment_nonce(sequence: u64, kind: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&sequence.to_le_bytes());
    nonce[8] = kind;
    nonce
}

fn segment_aad(sequence: u64, kind: u8) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0..8].copy_from_slice(&sequence.to_le_bytes());
    aad[8] = kind;
    aad
}
