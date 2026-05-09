use std::hash::{BuildHasherDefault, Hasher};

pub(crate) type FastBuildHasher = BuildHasherDefault<FastHasher>;

#[derive(Default)]
pub(crate) struct FastHasher(u64);

impl Hasher for FastHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut hash = self.0;
        if hash == 0 {
            hash = 0xcbf2_9ce4_8422_2325;
        }
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.0 = hash;
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }
}
