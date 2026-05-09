use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

const GIB: usize = 1024 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = std::env::args_os().nth(1) else {
        eprintln!("usage: compression_corpus <output-directory>");
        std::process::exit(2);
    };
    let root = Path::new(&root);
    fs::create_dir_all(root)?;

    write_zero_file(&root.join("zero-1g.bin"), GIB)?;
    write_randomish_file(&root.join("randomish-1g.bin"), GIB)?;
    write_repeated_file(&root.join("small-repeated-1k.bin"), 1024)?;
    Ok(())
}

fn write_zero_file(path: &Path, len: usize) -> io::Result<()> {
    if file_has_len(path, len as u64)? {
        return Ok(());
    }
    let file = File::create(path)?;
    file.set_len(len as u64)
}

fn write_randomish_file(path: &Path, len: usize) -> io::Result<()> {
    if file_has_len(path, len as u64)? {
        return Ok(());
    }
    let mut file = File::create(path)?;
    let mut offset = 0usize;
    let mut buf = vec![0; 1024 * 1024];
    while offset < len {
        let write_len = buf.len().min(len - offset);
        fill_randomish(offset, &mut buf[..write_len]);
        file.write_all(&buf[..write_len])?;
        offset += write_len;
    }
    Ok(())
}

fn write_repeated_file(path: &Path, len: usize) -> io::Result<()> {
    if file_has_len(path, len as u64)? {
        return Ok(());
    }
    fs::write(path, vec![b'x'; len])
}

fn file_has_len(path: &Path, len: u64) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len() == len),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn fill_randomish(offset: usize, out: &mut [u8]) {
    for (i, byte) in out.iter_mut().enumerate() {
        let n = (offset + i) as u64;
        let mut x = n.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *byte = (x ^ (x >> 31)) as u8;
    }
}
