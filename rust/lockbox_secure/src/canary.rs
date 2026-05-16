use std::sync::OnceLock;

use crate::allocation::Allocation;

pub(crate) const CANARY_LEN: usize = 16;

#[derive(Clone, Copy)]
pub(crate) enum CanarySide {
    Before,
    After,
}

pub(crate) fn expected_canary(allocation: Allocation, side: CanarySide) -> [u8; CANARY_LEN] {
    let side_tag = match side {
        CanarySide::Before => 0xb4f0_1d2c_87e9_aa11,
        CanarySide::After => 0xa17e_5cc9_4382_f00d,
    };
    let mut state = canary_seed()
        ^ side_tag
        ^ ((allocation.arena as u64) << 48)
        ^ ((allocation.slot as u64) << 24)
        ^ allocation.generation
        ^ (allocation.capacity as u64);
    let mut canary = [0u8; CANARY_LEN];
    for chunk in canary.chunks_mut(8) {
        state = splitmix64(state);
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    canary
}

fn canary_seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).expect("secure canary seed random source failed");
        u64::from_le_bytes(bytes)
    })
}

pub(crate) fn canary_offset(allocation: Allocation, side: CanarySide) -> usize {
    match side {
        CanarySide::Before => allocation.offset - CANARY_LEN,
        CanarySide::After => allocation.offset + allocation.capacity,
    }
}

fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
