use std::{fs, io::Read};

use lockbox_core::{EnvName, EnvSensitivity, EnvValueRef, Error, SecretString};

use super::context::{open_existing, open_or_create, require_arg, Access, CliResult};
use super::help::usage;
use crate::secret_prompt::prompt_secret;

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let subcommand = require_arg(args, 0, "env command")?;
    let lockbox_path = require_arg(args, 1, "lockbox")?;
    match subcommand {
        "set" => set_env(lockbox_path, &args[2..], access)?,
        "get" => get_env(lockbox_path, &args[2..], access)?,
        "list" => {
            let lb = open_existing(lockbox_path, access)?;
            for (name, sensitivity) in lb.list_env()? {
                if sensitivity == EnvSensitivity::Secret {
                    println!("{name}\tsecret");
                } else {
                    println!("{name}");
                }
            }
        }
        "export" => {
            let format = EnvExportFormat::parse(&args[2..])?;
            let lb = open_existing(lockbox_path, access)?;
            lb.visit_env(|name, value| match value {
                EnvValueRef::Normal(value) => {
                    println!("{}", format.format_assignment(name.as_str(), value));
                    Ok(())
                }
                EnvValueRef::Secret(_) => Ok(()),
            })?;
        }
        "rm" => {
            let name = EnvName::new(require_arg(args, 2, "name")?)?;
            let mut lb = open_existing(lockbox_path, access)?;
            lb.delete_env(&name)?;
            lb.commit()?;
        }
        _ => usage(false),
    }
    Ok(())
}

fn set_env(lockbox_path: &str, args: &[String], access: &Access) -> CliResult<()> {
    let request = EnvSetRequest::parse(args)?;
    let mut lb = open_or_create(lockbox_path, access)?;
    let existing = lb.env_sensitivity(&request.name)?;
    let effective_sensitivity = existing.unwrap_or(if request.secret {
        EnvSensitivity::Secret
    } else {
        EnvSensitivity::Normal
    });

    if let Some(existing) = existing {
        if request.secret && existing == EnvSensitivity::Normal {
            return Err(Error::InvalidOperation(
                "environment variable is not secret; delete and recreate it".to_string(),
            )
            .into());
        }
        if !request.secret && existing == EnvSensitivity::Secret && request.positional.is_some() {
            return Err(Error::InvalidInput(
                "secret environment variables require an explicit value source".to_string(),
            )
            .into());
        }
    }

    match effective_sensitivity {
        EnvSensitivity::Normal => {
            let value = request.read_normal_value()?;
            lb.set_env(&request.name, &value)?;
        }
        EnvSensitivity::Secret => {
            if request.positional.is_some() {
                return Err(Error::InvalidInput(
                    "secret environment variables cannot use positional values".to_string(),
                )
                .into());
            }
            let value = request.read_secret_value()?;
            lb.set_secret_env(&request.name, &value)?;
        }
    }
    lb.commit()?;
    Ok(())
}

fn get_env(lockbox_path: &str, args: &[String], access: &Access) -> CliResult<()> {
    let mut secret = false;
    let mut name = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-s" | "--secret" => secret = true,
            value if name.is_none() => name = Some(value.to_string()),
            _ => {
                return Err(Error::InvalidInput("unexpected env get argument".to_string()).into());
            }
        }
        index += 1;
    }
    let Some(name) = name else {
        return Err(Error::InvalidInput("missing env name".to_string()).into());
    };
    let name = EnvName::new(name)?;
    let lb = open_existing(lockbox_path, access)?;
    if secret {
        if let Some(()) = lb
            .with_secret_env(&name, |value| value.with_str(|value| println!("{value}")))?
            .transpose()?
        {
            return Ok(());
        }
    } else if let Some(value) = lb.get_env(&name)? {
        println!("{value}");
    }
    Ok(())
}

struct EnvSetRequest {
    name: EnvName,
    secret: bool,
    positional: Option<String>,
    source: Option<ValueSource>,
}

impl EnvSetRequest {
    fn parse(args: &[String]) -> CliResult<Self> {
        let mut name = None;
        let mut positional = None;
        let mut secret = false;
        let mut source = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-s" | "--secret" => secret = true,
                "-i" | "--interactive" => set_source(&mut source, ValueSource::Interactive)?,
                "-t" | "--stdin" => set_source(&mut source, ValueSource::Stdin)?,
                "-v" | "--value" => {
                    index += 1;
                    set_source(
                        &mut source,
                        ValueSource::Value(
                            args.get(index)
                                .ok_or_else(|| {
                                    Error::InvalidInput("missing --value argument".to_string())
                                })?
                                .to_string(),
                        ),
                    )?;
                }
                "-f" | "--file" => {
                    index += 1;
                    set_source(
                        &mut source,
                        ValueSource::File(
                            args.get(index)
                                .ok_or_else(|| {
                                    Error::InvalidInput("missing --file argument".to_string())
                                })?
                                .to_string(),
                        ),
                    )?;
                }
                "-e" | "--from-env" => {
                    index += 1;
                    set_source(
                        &mut source,
                        ValueSource::FromEnv(
                            args.get(index)
                                .ok_or_else(|| {
                                    Error::InvalidInput("missing --from-env argument".to_string())
                                })?
                                .to_string(),
                        ),
                    )?;
                }
                value if name.is_none() => name = Some(EnvName::new(value)?),
                value if positional.is_none() => positional = Some(value.to_string()),
                _ => {
                    return Err(
                        Error::InvalidInput("unexpected env set argument".to_string()).into(),
                    );
                }
            }
            index += 1;
        }
        let Some(name) = name else {
            return Err(Error::InvalidInput("missing env name".to_string()).into());
        };
        if source.is_some() == positional.is_some() {
            return Err(Error::InvalidInput(
                "env set requires exactly one value source".to_string(),
            )
            .into());
        }
        Ok(Self {
            name,
            secret,
            positional,
            source,
        })
    }

    fn read_normal_value(&self) -> CliResult<String> {
        if let Some(value) = &self.positional {
            return Ok(value.clone());
        }
        match self
            .source
            .as_ref()
            .ok_or_else(|| Error::InvalidInput("missing value source".to_string()))?
        {
            ValueSource::Interactive => prompt_secret("Value: ")?
                .with_str(str::to_string)
                .map_err(Box::<dyn std::error::Error>::from),
            ValueSource::Value(value) => Ok(value.clone()),
            ValueSource::File(path) => Ok(String::from_utf8(fs::read(path)?)?),
            ValueSource::Stdin => {
                let mut bytes = Vec::new();
                std::io::stdin().lock().read_to_end(&mut bytes)?;
                Ok(String::from_utf8(bytes)?)
            }
            ValueSource::FromEnv(name) => Ok(std::env::var(name)?),
        }
    }

    fn read_secret_value(&self) -> CliResult<SecretString> {
        match self
            .source
            .as_ref()
            .ok_or_else(|| Error::InvalidInput("missing value source".to_string()))?
        {
            ValueSource::Interactive => Ok(prompt_secret("Secret value: ")?),
            ValueSource::Value(value) => {
                let _ = value;
                Err(Error::InvalidInput(
                    "--value is not accepted for secret env values; use --stdin, --file, --interactive, or --from-env"
                        .to_string(),
                )
                .into())
            }
            ValueSource::File(path) => read_secret_file(path),
            ValueSource::Stdin => read_secret_stdin(),
            ValueSource::FromEnv(name) => SecretString::try_from_env(name)?
                .ok_or_else(|| Error::InvalidInput(format!("{name} is not set")).into()),
        }
    }
}

fn read_secret_file(path: &str) -> CliResult<SecretString> {
    let mut file = fs::File::open(path)?;
    read_secret_from(&mut file)
}

fn read_secret_stdin() -> CliResult<SecretString> {
    let mut stdin = std::io::stdin().lock();
    read_secret_from(&mut stdin)
}

fn read_secret_from(input: &mut impl Read) -> CliResult<SecretString> {
    let mut secret = SecretString::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        secret.try_extend_from_slice(&buffer[..read])?;
        buffer[..read].fill(0);
        std::hint::black_box(&mut buffer[..read]);
    }
    Ok(secret)
}

enum ValueSource {
    Interactive,
    Value(String),
    File(String),
    Stdin,
    FromEnv(String),
}

enum EnvExportFormat {
    Posix,
    PowerShell,
    Cmd,
    Json,
}

impl EnvExportFormat {
    fn parse(args: &[String]) -> CliResult<Self> {
        let mut format = Self::Posix;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--format" => {
                    index += 1;
                    format = match args.get(index).map(String::as_str) {
                        Some("posix") => Self::Posix,
                        Some("powershell") => Self::PowerShell,
                        Some("cmd") => Self::Cmd,
                        Some("json") => Self::Json,
                        Some(value) => {
                            return Err(Error::InvalidInput(format!(
                                "unsupported env export format: {value}"
                            ))
                            .into());
                        }
                        None => {
                            return Err(Error::InvalidInput(
                                "missing --format argument".to_string(),
                            )
                            .into());
                        }
                    };
                }
                _ => {
                    return Err(
                        Error::InvalidInput("unexpected env export argument".to_string()).into(),
                    );
                }
            }
            index += 1;
        }
        Ok(format)
    }

    fn format_assignment(&self, name: &str, value: &str) -> String {
        match self {
            Self::Posix => format!("{name}={}", posix_quote(value)),
            Self::PowerShell => format!("$env:{name} = {}", powershell_quote(value)),
            Self::Cmd => format!("set \"{name}={}\"", cmd_quote_value(value)),
            Self::Json => format!(
                "{{\"name\":{},\"value\":{}}}",
                json_quote(name),
                json_quote(value)
            ),
        }
    }
}

fn set_source(target: &mut Option<ValueSource>, source: ValueSource) -> CliResult<()> {
    if target.is_some() {
        return Err(
            Error::InvalidInput("env set accepts exactly one value source".to_string()).into(),
        );
    }
    *target = Some(source);
    Ok(())
}

fn posix_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn cmd_quote_value(value: &str) -> String {
    value.replace('"', "\"\"")
}

fn json_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if ch < ' ' => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
