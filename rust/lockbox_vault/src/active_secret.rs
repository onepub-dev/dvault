use crate::agent_config::AgentConfig;
use crate::agent_log::log_agent_event;
use crate::agent_protocol::SecretActivityKind;
use crate::sleep_watcher::SleepInhibitor;
use std::collections::BTreeMap;
use std::io;
use std::time::Instant;

#[derive(Debug)]
pub(crate) struct ActiveSecretProcess {
    pub(crate) pid: u32,
    pub(crate) kind: SecretActivityKind,
    started_at: Instant,
}

pub(crate) struct ActiveSecretRegistry {
    config: AgentConfig,
    processes: BTreeMap<u64, ActiveSecretProcess>,
    sleep_inhibitor: Option<SleepInhibitor>,
}

impl ActiveSecretRegistry {
    pub(crate) fn new(config: AgentConfig) -> Self {
        Self {
            config,
            processes: BTreeMap::new(),
            sleep_inhibitor: None,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    pub(crate) fn register(&mut self, pid: u32, kind: SecretActivityKind) -> io::Result<u64> {
        if self.processes.is_empty() && self.config.prevent_sleep {
            match SleepInhibitor::acquire_active("reVault secret operation in progress") {
                Ok(inhibitor) => {
                    self.sleep_inhibitor = Some(inhibitor);
                    log_agent_event("active secret suspend inhibitor acquired");
                }
                Err(err) => log_agent_event(format!(
                    "active secret suspend inhibitor unavailable: {err}"
                )),
            }
        }

        let token = next_token(&self.processes)?;
        self.processes.insert(
            token,
            ActiveSecretProcess {
                pid,
                kind,
                started_at: Instant::now(),
            },
        );
        log_agent_event(format!(
            "secret activity registered pid={pid} kind={}",
            kind.as_str()
        ));
        Ok(token)
    }

    pub(crate) fn unregister(&mut self, pid: u32, token: u64) {
        let Some(process) = self.processes.get(&token) else {
            log_agent_event(format!("secret activity unregister missed pid={pid}"));
            return;
        };
        if process.pid != pid {
            log_agent_event(format!(
                "secret activity unregister rejected pid={pid} token={token}"
            ));
            return;
        }
        let process = self.processes.remove(&token).expect("process existed");
        log_agent_event(format!(
            "secret activity unregistered pid={} kind={} age_ms={}",
            process.pid,
            process.kind.as_str(),
            elapsed_ms(process.started_at)
        ));
        self.release_inhibitor_if_idle();
    }

    pub(crate) fn suspend_requested(&mut self) {
        let count = self.processes.len();
        if count == 0 {
            self.sleep_inhibitor.take();
            return;
        }
        if !self.config.terminate_on_suspend {
            log_agent_event(format!(
                "suspend requested; active secret processes retained count={count}"
            ));
            self.sleep_inhibitor.take();
            return;
        }

        for (_, process) in std::mem::take(&mut self.processes) {
            log_agent_event(format!(
                "suspend requested; terminating active secret process pid={} kind={} age_ms={}",
                process.pid,
                process.kind.as_str(),
                elapsed_ms(process.started_at)
            ));
            if let Err(err) = terminate_process(process.pid) {
                log_agent_event(format!(
                    "active secret process termination failed pid={} kind={} error={err}",
                    process.pid,
                    process.kind.as_str()
                ));
            }
        }
        self.sleep_inhibitor.take();
    }

    fn release_inhibitor_if_idle(&mut self) {
        if self.processes.is_empty() && self.sleep_inhibitor.take().is_some() {
            log_agent_event("active secret suspend inhibitor released");
        }
    }
}

fn next_token(processes: &BTreeMap<u64, ActiveSecretProcess>) -> io::Result<u64> {
    loop {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).map_err(|err| io::Error::other(err.to_string()))?;
        let token = u64::from_le_bytes(bytes);
        if token != 0 && !processes.contains_key(&token) {
            return Ok(token);
        }
    }
}

fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}

#[cfg(unix)]
fn terminate_process(pid: u32) -> io::Result<()> {
    // SAFETY: `kill` is called with a PID supplied by the same-user agent
    // transport and a constant signal value; it does not retain pointers.
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn terminate_process(pid: u32) -> io::Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    // SAFETY: `OpenProcess` receives a PID supplied by the same-user agent
    // transport and returns an owned process handle on success.
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle == INVALID_HANDLE_VALUE || handle == null_mut() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a valid process handle opened for termination.
    let terminated = unsafe { TerminateProcess(handle, 1) };
    // SAFETY: The handle is owned by this function and is not used after close.
    unsafe {
        CloseHandle(handle);
    }
    if terminated == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn terminate_process(_pid: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process termination is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn registry_registers_and_unregisters_without_inhibitor() {
        let config = AgentConfig {
            prevent_sleep: false,
            terminate_on_suspend: false,
        };
        let mut registry = ActiveSecretRegistry::new(config);
        let token = registry.register(1234, SecretActivityKind::Unlock).unwrap();
        assert!(!registry.is_empty());
        registry.unregister(1234, token);
        assert!(registry.is_empty());
    }

    #[test]
    fn suspend_clears_registry_when_termination_disabled() {
        let config = AgentConfig {
            prevent_sleep: false,
            terminate_on_suspend: false,
        };
        let mut registry = ActiveSecretRegistry::new(config);
        registry
            .register(1234, SecretActivityKind::Variables)
            .unwrap();
        registry.suspend_requested();
        assert!(!registry.is_empty());
    }

    #[test]
    fn elapsed_ms_is_monotonic_enough_for_logs() {
        let started = Instant::now() - Duration::from_millis(5);
        assert!(elapsed_ms(started) >= 5);
    }
}
