use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AgentConfig {
    pub(crate) prevent_sleep: bool,
    pub(crate) terminate_on_suspend: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            prevent_sleep: true,
            terminate_on_suspend: true,
        }
    }
}

impl AgentConfig {
    pub(crate) fn load() -> Self {
        let mut config = Self::default();
        if let Some(path) = config_path() {
            if let Ok(text) = fs::read_to_string(path) {
                let _ = config.apply_text(&text);
            }
        }
        config.apply_env();
        config
    }

    fn apply_text(&mut self, text: &str) -> io::Result<()> {
        for raw_line in text.lines() {
            let Some((key, value)) = parse_assignment(raw_line) else {
                continue;
            };
            let Some(value) = parse_bool(value)? else {
                continue;
            };
            match key {
                "agent.prevent_sleep" | "agent.suspend_inhibit" => self.prevent_sleep = value,
                "agent.terminate_on_suspend" => self.terminate_on_suspend = value,
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_env(&mut self) {
        if let Ok(value) = env::var("LOCKBOX_AGENT_PREVENT_SLEEP") {
            if let Ok(Some(value)) = parse_bool(&value) {
                self.prevent_sleep = value;
            }
        }
        if let Ok(value) = env::var("LOCKBOX_AGENT_TERMINATE_ON_SUSPEND") {
            if let Ok(Some(value)) = parse_bool(&value) {
                self.terminate_on_suspend = value;
            }
        }
    }
}

fn parse_assignment(raw_line: &str) -> Option<(&str, &str)> {
    let line = raw_line.split('#').next()?.trim();
    if line.is_empty() || line.starts_with('[') {
        return None;
    }
    let (key, value) = line.split_once('=').or_else(|| line.split_once(':'))?;
    Some((
        key.trim(),
        value.trim().trim_matches('"').trim_matches('\''),
    ))
}

fn parse_bool(value: &str) -> io::Result<Option<bool>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" | "enabled" => Ok(Some(true)),
        "false" | "0" | "no" | "off" | "disabled" => Ok(Some(false)),
        "" => Ok(None),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid boolean value: {other}"),
        )),
    }
}

fn config_path() -> Option<PathBuf> {
    if let Ok(path) = env::var("LOCKBOX_AGENT_CONFIG") {
        return Some(PathBuf::from(path));
    }
    if let Ok(path) = env::var("LOCKBOX_CONFIG") {
        return Some(PathBuf::from(path));
    }
    default_config_path()
}

#[cfg(target_os = "macos")]
fn default_config_path() -> Option<PathBuf> {
    home_dir().map(|home| {
        home.join("Library")
            .join("Application Support")
            .join("reVault")
            .join("config.toml")
    })
}

#[cfg(windows)]
fn default_config_path() -> Option<PathBuf> {
    env::var("APPDATA")
        .or_else(|_| env::var("LOCALAPPDATA"))
        .ok()
        .map(|dir| PathBuf::from(dir).join("reVault").join("config.toml"))
}

#[cfg(all(not(target_os = "macos"), not(windows)))]
fn default_config_path() -> Option<PathBuf> {
    if let Ok(dir) = env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(dir).join("lockbox").join("config.toml"));
    }
    home_dir().map(|home| home.join(".config").join("lockbox").join("config.toml"))
}

fn home_dir() -> Option<PathBuf> {
    env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agent_config_assignments() {
        let mut config = AgentConfig::default();
        config
            .apply_text(
                r#"
                # TOML-style values are accepted.
                agent.prevent_sleep = false
                agent.terminate_on_suspend: yes
                ignored = true
                "#,
            )
            .unwrap();
        assert!(!config.prevent_sleep);
        assert!(config.terminate_on_suspend);
    }
}
