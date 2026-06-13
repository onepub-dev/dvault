use crate::{Error, Result};

pub(crate) fn read_u16_le(bytes: &[u8]) -> Result<u16> {
    let bytes = array_2(bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

pub(crate) fn read_u32_le(bytes: &[u8]) -> Result<u32> {
    let bytes = array_4(bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn read_u64_le(bytes: &[u8]) -> Result<u64> {
    let bytes = array_8(bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn array_16(bytes: &[u8]) -> Result<[u8; 16]> {
    let mut out = [0_u8; 16];
    copy_exact(bytes, &mut out)?;
    Ok(out)
}

pub(crate) fn array_12(bytes: &[u8]) -> Result<[u8; 12]> {
    let mut out = [0_u8; 12];
    copy_exact(bytes, &mut out)?;
    Ok(out)
}

pub(crate) fn array_32(bytes: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0_u8; 32];
    copy_exact(bytes, &mut out)?;
    Ok(out)
}

fn array_2(bytes: &[u8]) -> Result<[u8; 2]> {
    let mut out = [0_u8; 2];
    copy_exact(bytes, &mut out)?;
    Ok(out)
}

fn array_4(bytes: &[u8]) -> Result<[u8; 4]> {
    let mut out = [0_u8; 4];
    copy_exact(bytes, &mut out)?;
    Ok(out)
}

fn array_8(bytes: &[u8]) -> Result<[u8; 8]> {
    let mut out = [0_u8; 8];
    copy_exact(bytes, &mut out)?;
    Ok(out)
}

fn copy_exact<const N: usize>(bytes: &[u8], out: &mut [u8; N]) -> Result<()> {
    if bytes.len() != N {
        return Err(Error::CorruptRecord);
    }
    out.copy_from_slice(bytes);
    Ok(())
}
