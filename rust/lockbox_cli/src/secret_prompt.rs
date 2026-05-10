use lockbox_vault::SecretString;
use std::io::{self, BufRead, Write};

pub(crate) fn prompt_secret(prompt: &str) -> io::Result<SecretString> {
    print!("{prompt}");
    io::stdout().flush()?;
    let bytes = read_secret_bytes()?;
    println!();
    Ok(SecretString::from_bytes(bytes))
}

#[cfg(unix)]
fn read_secret_bytes() -> io::Result<Vec<u8>> {
    let fd = libc::STDIN_FILENO;
    let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
    let has_tty = unsafe { libc::tcgetattr(fd, &mut termios) == 0 };
    let original = termios;
    if has_tty {
        termios.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let result = read_line_bytes();

    if has_tty {
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &original);
        }
    }
    result
}

#[cfg(not(any(unix, windows)))]
fn read_secret_bytes() -> io::Result<Vec<u8>> {
    read_line_bytes()
}

fn read_line_bytes() -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io::stdin().lock().read_until(b'\n', &mut bytes)?;
    trim_line_ending(&mut bytes);
    Ok(bytes)
}

fn trim_line_ending(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
}

#[cfg(windows)]
fn read_secret_bytes() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
    };

    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() {
        return read_line_bytes();
    }

    let mut mode = 0u32;
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        return read_line_bytes();
    }
    let original = mode;
    let no_echo = mode & !ENABLE_ECHO_INPUT;
    if unsafe { SetConsoleMode(handle, no_echo) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let result = read_console_utf16(handle);

    unsafe {
        SetConsoleMode(handle, original);
    }
    result
}

#[cfg(windows)]
fn read_console_utf16(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::System::Console::ReadConsoleW;

    let mut units = Vec::new();
    let mut buffer = [0u16; 256];
    loop {
        let mut read = 0u32;
        let ok = unsafe {
            ReadConsoleW(
                handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if read == 0 {
            break;
        }
        units.extend_from_slice(&buffer[..read as usize]);
        if units.ends_with(&[b'\n' as u16]) {
            break;
        }
    }
    while units.last() == Some(&(b'\n' as u16)) || units.last() == Some(&(b'\r' as u16)) {
        units.pop();
    }

    let mut bytes = Vec::new();
    for decoded in char::decode_utf16(units) {
        let ch = decoded.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf16"))?;
        let mut encoded = [0u8; 4];
        bytes.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
    }
    Ok(bytes)
}
