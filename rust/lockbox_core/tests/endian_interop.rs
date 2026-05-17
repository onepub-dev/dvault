use lockbox_core::{
    EnvName, ListOptions, Lockbox, LockboxPath, LockboxProtection, LockboxUnlock, SecretVec,
};
use std::io::{Read, Result as IoResult};
use std::path::{Path, PathBuf};

const KEY: &[u8] = b"lockbox endian interoperability key";

fn p(path: impl AsRef<str>) -> LockboxPath {
    LockboxPath::new(path).unwrap()
}

fn env(name: impl AsRef<str>) -> EnvName {
    EnvName::new(name).unwrap()
}

#[test]
#[ignore = "CI-only architecture/endian artifact transfer test"]
fn lockbox_artifact_round_trips_across_architectures() {
    let verify_path = std::env::var_os("LOCKBOX_INTEROP_VERIFY_PATH").map(PathBuf::from);
    let create_path = std::env::var_os("LOCKBOX_INTEROP_CREATE_PATH").map(PathBuf::from);

    if verify_path.is_none() && create_path.is_none() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/test-tmp")
            .join(format!("lockbox-endian-interop-{}.lbx", std::process::id()));
        create_fixture(&path);
        verify_fixture(&path);
        let _ = std::fs::remove_file(path);
        return;
    }

    if let Some(path) = verify_path {
        verify_fixture(&path);
    }
    if let Some(path) = create_path {
        create_fixture(&path);
        verify_fixture(&path);
    }
}

fn create_fixture(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let _ = std::fs::remove_file(path);

    let mut lockbox = Lockbox::create_file(
        path,
        LockboxProtection::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
    )
    .unwrap();
    lockbox
        .add_file(
            &p("/docs/readme.txt"),
            b"lockbox endian interoperability fixture\n",
            false,
        )
        .unwrap();
    lockbox
        .add_file(
            &p("/unicode/cafe\u{301}.txt"),
            "cafe\u{301}\n".as_bytes(),
            false,
        )
        .unwrap();
    lockbox
        .add_file_from_reader(
            &p("/data/randomish.bin"),
            PatternReader::new(2 * 1024 * 1024),
            false,
        )
        .unwrap();
    lockbox
        .add_file(&p("/small/repeated.bin"), &vec![b'x'; 128 * 1024], false)
        .unwrap();
    lockbox
        .set_env(&env("INTEROP_MODE"), "cross-endian")
        .unwrap();
    lockbox.commit().unwrap();
}

fn verify_fixture(path: &Path) {
    let lockbox = Lockbox::open_file(
        path,
        LockboxUnlock::ContentKey(SecretVec::try_from_slice(KEY).unwrap()),
    )
    .unwrap();

    assert_eq!(
        lockbox.get_file(&p("/docs/readme.txt")).unwrap(),
        b"lockbox endian interoperability fixture\n"
    );
    assert_eq!(
        std::str::from_utf8(&lockbox.get_file(&p("/unicode/caf\u{e9}.txt")).unwrap()).unwrap(),
        "cafe\u{301}\n"
    );
    assert_eq!(
        lockbox.get_file(&p("/small/repeated.bin")).unwrap(),
        vec![b'x'; 128 * 1024]
    );
    assert_eq!(
        lockbox
            .read_file_range(&p("/data/randomish.bin"), 1024 * 1024 - 17, 4096)
            .unwrap(),
        randomish_bytes(1024 * 1024 - 17, 4096)
    );
    assert_eq!(
        lockbox.get_env(&env("INTEROP_MODE")).unwrap().as_deref(),
        Some("cross-endian")
    );

    let entries = lockbox
        .list(ListOptions {
            recursive: true,
            ..ListOptions::new(&p("/"))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let paths = entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    assert!(paths.contains(&"/docs/readme.txt"));
    assert!(paths.contains(&"/unicode/caf\u{e9}.txt"));
    assert!(paths.contains(&"/data/randomish.bin"));
    assert!(paths.contains(&"/small/repeated.bin"));
}

struct PatternReader {
    remaining: usize,
    offset: usize,
}

impl PatternReader {
    fn new(bytes: usize) -> Self {
        Self {
            remaining: bytes,
            offset: 0,
        }
    }
}

impl Read for PatternReader {
    fn read(&mut self, out: &mut [u8]) -> IoResult<usize> {
        let len = out.len().min(self.remaining);
        if len == 0 {
            return Ok(0);
        }
        out[..len].copy_from_slice(&randomish_bytes(self.offset, len));
        self.offset += len;
        self.remaining -= len;
        Ok(len)
    }
}

fn randomish_bytes(offset: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    for (i, byte) in out.iter_mut().enumerate() {
        let n = (offset + i) as u64;
        let mut x = n.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *byte = (x ^ (x >> 31)) as u8;
    }
    out
}
