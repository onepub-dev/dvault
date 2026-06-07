use lockbox_vault::SecretString;
use std::io::{self, Read, Write};

pub(crate) fn prompt_secret(prompt: &str) -> io::Result<SecretString> {
    print!("{prompt}");
    io::stdout().flush()?;
    let secret = read_secret_string()?;
    println!();
    Ok(secret)
}

#[cfg(unix)]
fn read_secret_string() -> io::Result<SecretString> {
    let _guard = TerminalEchoGuard::disable()?;
    read_line_secret()
}

#[cfg(unix)]
struct TerminalEchoGuard {
    fd: i32,
    original: libc::termios,
}

#[cfg(unix)]
impl TerminalEchoGuard {
    fn disable() -> io::Result<Option<Self>> {
        let fd = libc::STDIN_FILENO;
        let Some(mut termios) = get_terminal_attributes(fd)? else {
            return Ok(None);
        };
        let original = termios;
        termios.c_lflag &= !libc::ECHO;
        set_terminal_attributes(fd, &termios)?;
        Ok(Some(Self { fd, original }))
    }
}

#[cfg(unix)]
impl Drop for TerminalEchoGuard {
    fn drop(&mut self) {
        let _ = set_terminal_attributes(self.fd, &self.original);
    }
}

#[cfg(unix)]
fn get_terminal_attributes(fd: i32) -> io::Result<Option<libc::termios>> {
    // SAFETY: `termios` is a plain C struct. It is immediately initialized by
    // `tcgetattr` before any successful terminal settings are used.
    let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: `fd` is the process standard input descriptor and `termios`
    // points to valid writable storage for the duration of the call.
    let has_tty = unsafe { libc::tcgetattr(fd, &mut termios) == 0 };
    if has_tty {
        Ok(Some(termios))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn set_terminal_attributes(fd: i32, termios: &libc::termios) -> io::Result<()> {
    // SAFETY: `termios` contains settings returned by `tcgetattr` with limited
    // flag modifications, and the pointer is valid for this call.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, termios) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn read_secret_string() -> io::Result<SecretString> {
    read_line_secret()
}

fn read_line_secret() -> io::Result<SecretString> {
    let mut secret = SecretString::new();
    let mut stdin = io::stdin().lock();
    let mut buffer = [0u8; 1];
    loop {
        let read = stdin.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if matches!(buffer[0], b'\n' | b'\r') {
            break;
        }
        secret
            .try_extend_from_slice(&buffer[..read])
            .map_err(io::Error::other)?;
        clear_buffer(&mut buffer);
    }
    Ok(secret)
}

fn clear_buffer(buffer: &mut [u8]) {
    buffer.fill(0);
    std::hint::black_box(buffer);
}

#[cfg(windows)]
fn read_secret_string() -> io::Result<SecretString> {
    let Some(guard) = ConsoleEchoGuard::disable()? else {
        return read_line_secret();
    };
    read_console_utf16(guard.handle)
}

#[cfg(windows)]
struct ConsoleEchoGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
    original: u32,
}

#[cfg(windows)]
impl ConsoleEchoGuard {
    fn disable() -> io::Result<Option<Self>> {
        use windows_sys::Win32::System::Console::{ENABLE_ECHO_INPUT, STD_INPUT_HANDLE};

        let handle = std_input_handle();
        if handle.is_null() {
            return Ok(None);
        }
        let Some(original) = console_mode(handle)? else {
            return Ok(None);
        };
        set_console_mode(handle, original & !ENABLE_ECHO_INPUT)?;
        Ok(Some(Self { handle, original }))
    }
}

#[cfg(windows)]
impl Drop for ConsoleEchoGuard {
    fn drop(&mut self) {
        let _ = set_console_mode(self.handle, self.original);
    }
}

#[cfg(windows)]
fn std_input_handle() -> windows_sys::Win32::Foundation::HANDLE {
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};

    // SAFETY: `GetStdHandle` does not require Rust-side memory invariants.
    unsafe { GetStdHandle(STD_INPUT_HANDLE) }
}

#[cfg(windows)]
fn console_mode(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<Option<u32>> {
    use windows_sys::Win32::System::Console::GetConsoleMode;

    let mut mode = 0u32;
    // SAFETY: `mode` points to valid writable storage for the duration of the
    // call and `handle` is the console handle returned by `GetStdHandle`.
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        Ok(None)
    } else {
        Ok(Some(mode))
    }
}

#[cfg(windows)]
fn set_console_mode(handle: windows_sys::Win32::Foundation::HANDLE, mode: u32) -> io::Result<()> {
    use windows_sys::Win32::System::Console::SetConsoleMode;

    // SAFETY: `handle` is a console input handle and `mode` is either the
    // original mode or derived from it by clearing the echo bit.
    if unsafe { SetConsoleMode(handle, mode) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn read_console_utf16(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<SecretString> {
    use windows_sys::Win32::System::Console::ReadConsoleW;

    let mut secret = SecretString::new();
    let mut buffer = [0u16; 256];
    loop {
        let mut read = 0u32;
        // SAFETY: `buffer` and `read` are valid writable buffers for the
        // duration of the call, and the console handle is supplied by
        // `read_secret_vec`.
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
        let mut stop = false;
        for decoded in char::decode_utf16(buffer[..read as usize].iter().copied()) {
            let ch = decoded.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf16"))?;
            if matches!(ch, '\n' | '\r') {
                stop = true;
                break;
            }
            secret.try_push_utf8_char(ch).map_err(io::Error::other)?;
        }
        buffer.fill(0);
        if stop {
            break;
        }
    }
    Ok(secret)
}
