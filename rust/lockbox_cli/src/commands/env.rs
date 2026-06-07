use std::{
    fs,
    io::{Read, Write},
};

use lockbox_core::{EnvName, EnvNamePattern, EnvSensitivity, EnvValueRef, Error, SecretString};

use super::context::{open_existing, open_or_create, require_arg, Access, CliResult};
use super::help::usage;
use super::output::{output_format_from_args, print_records};
use crate::secret_prompt::prompt_secret;

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let subcommand = require_arg(args, 0, "env command")?;
    let lockbox_path = require_arg(args, 1, "lockbox")?;
    match subcommand {
        "set" => set_env(lockbox_path, &args[2..], access)?,
        "get" => get_env(lockbox_path, &args[2..], access)?,
        "list" => {
            let (args, format) = output_format_from_args(&args[2..])?;
            let pattern = match args.as_slice() {
                [] => None,
                [pattern] => Some(EnvNamePattern::new(pattern)?),
                _ => {
                    return Err(Error::InvalidInput(
                        "env list accepts at most one path or glob pattern".to_string(),
                    )
                    .into());
                }
            };
            let lb = open_existing(lockbox_path, access)?;
            let mut rows = Vec::new();
            for (name, sensitivity) in lb.list_env()? {
                if pattern
                    .as_ref()
                    .is_some_and(|pattern| !name.matches_pattern(pattern))
                {
                    continue;
                }
                rows.push(vec![
                    name.to_string(),
                    sensitivity_name(sensitivity).to_string(),
                ]);
            }
            print_records(&["name", "sensitivity"], rows, format)?;
        }
        "export" => {
            let request = EnvExportRequest::parse(&args[2..])?;
            let lb = open_existing(lockbox_path, access)?;
            lb.visit_env(|name, value| match value {
                EnvValueRef::Normal(value) => {
                    if let Some(name) = request.export_name(name.as_str()) {
                        println!("{}", request.format.format_assignment(name, value));
                    }
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
    let request = EnvGetRequest::parse(args)?;
    let name = EnvName::new(&request.name)?;
    let lb = open_existing(lockbox_path, access)?;
    if request.secret {
        if let Some(write_result) = lb.with_secret_env(&name, |value| {
            value.with_bytes(|value| request.write_value_bytes(value))
        })? {
            write_result??;
        } else {
            return Err(Error::NotFound(format!("env {name}")).into());
        }
    } else if let Some(value) = lb.get_env(&name)? {
        request.write_value(&value)?;
    } else {
        return Err(Error::NotFound(format!("env {name}")).into());
    }
    Ok(())
}

struct EnvGetRequest {
    secret: bool,
    name: String,
    output: Option<String>,
    overwrite: bool,
}

impl EnvGetRequest {
    fn parse(args: &[String]) -> CliResult<Self> {
        let mut secret = false;
        let mut name = None;
        let mut output = None;
        let mut overwrite = false;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-s" | "--secret" => secret = true,
                "--output" => {
                    index += 1;
                    output = Some(
                        args.get(index)
                            .ok_or_else(|| {
                                Error::InvalidInput("missing --output argument".to_string())
                            })?
                            .to_string(),
                    );
                }
                "--overwrite" => overwrite = true,
                value if name.is_none() => name = Some(value.to_string()),
                _ => {
                    return Err(
                        Error::InvalidInput("unexpected env get argument".to_string()).into(),
                    );
                }
            }
            index += 1;
        }
        let Some(name) = name else {
            return Err(Error::InvalidInput("missing env name".to_string()).into());
        };
        if overwrite && output.is_none() {
            return Err(Error::InvalidInput("--overwrite requires --output".to_string()).into());
        }
        Ok(Self {
            secret,
            name,
            output,
            overwrite,
        })
    }

    fn write_value(&self, value: &str) -> CliResult<()> {
        self.write_value_bytes(value.as_bytes())
    }

    fn write_value_bytes(&self, bytes: &[u8]) -> CliResult<()> {
        if let Some(path) = &self.output {
            write_output_file(path, bytes, self.overwrite)?;
        } else {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            stdout.write_all(bytes)?;
            stdout.write_all(b"\n")?;
        }
        Ok(())
    }
}

fn write_output_file(path: &str, bytes: &[u8], overwrite: bool) -> CliResult<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    configure_private_output_file(&mut options);
    let mut file = options.open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            Error::AlreadyExists(path.to_string())
        } else {
            Error::Io(format!("create {path}: {err}"))
        }
    })?;
    set_private_output_permissions(&file)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(unix)]
fn configure_private_output_file(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn configure_private_output_file(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn set_private_output_permissions(file: &fs::File) -> CliResult<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_output_permissions(_file: &fs::File) -> CliResult<()> {
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

struct EnvExportRequest {
    path: String,
    format: EnvExportFormat,
}

impl EnvExportRequest {
    fn parse(args: &[String]) -> CliResult<Self> {
        let mut path = "/".to_string();
        let mut saw_path = false;
        let mut format = EnvExportFormat::Posix;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--format" => {
                    index += 1;
                    format = EnvExportFormat::parse_value(args.get(index).map(String::as_str))?;
                }
                value if !saw_path => {
                    path = validate_export_path(value)?;
                    saw_path = true;
                }
                _ => {
                    return Err(
                        Error::InvalidInput("unexpected env export argument".to_string()).into(),
                    );
                }
            }
            index += 1;
        }
        Ok(Self { path, format })
    }

    fn export_name<'a>(&self, name: &'a str) -> Option<&'a str> {
        if self.path == "/" {
            let name = name.strip_prefix('/')?;
            if name.contains('/') {
                return None;
            }
            return Some(name);
        }
        let rest = name.strip_prefix(&self.path)?;
        let rest = rest.strip_prefix('/')?;
        if rest.contains('/') {
            return None;
        }
        Some(rest)
    }
}

impl EnvExportFormat {
    fn parse_value(value: Option<&str>) -> CliResult<Self> {
        match value {
            Some("posix") => Ok(Self::Posix),
            Some("powershell") => Ok(Self::PowerShell),
            Some("cmd") => Ok(Self::Cmd),
            Some("json") => Ok(Self::Json),
            Some(value) => {
                Err(Error::InvalidInput(format!("unsupported env export format: {value}")).into())
            }
            None => Err(Error::InvalidInput("missing --format argument".to_string()).into()),
        }
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

fn validate_export_path(path: &str) -> CliResult<String> {
    if path == "/" {
        return Ok(path.to_string());
    }
    let name = EnvName::new(path)?;
    Ok(name.as_str().to_string())
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

fn sensitivity_name(sensitivity: EnvSensitivity) -> &'static str {
    match sensitivity {
        EnvSensitivity::Normal => "normal",
        EnvSensitivity::Secret => "secret",
    }
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
