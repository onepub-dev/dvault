use std::{fs, io::Read};

use lockbox_core::{EnvSensitivity, SecretString};

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
            for (name, sensitivity) in lb.list_env_with_sensitivity()? {
                if sensitivity == EnvSensitivity::Secret {
                    println!("{name}\tsecret");
                } else {
                    println!("{name}");
                }
            }
        }
        "export" => {
            let lb = open_existing(lockbox_path, access)?;
            for (name, value) in lb.get_all_env()? {
                println!("{name}={}", shell_quote(&value));
            }
        }
        "rm" => {
            let name = require_arg(args, 2, "name")?;
            let mut lb = open_existing(lockbox_path, access)?;
            lb.delete_env_var(name)?;
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
            return Err("environment variable is not secret; delete and recreate it".into());
        }
        if !request.secret && existing == EnvSensitivity::Secret && request.positional.is_some() {
            return Err("secret environment variables require an explicit value source".into());
        }
    }

    match effective_sensitivity {
        EnvSensitivity::Normal => {
            let value = request.read_normal_value()?;
            lb.set_env(&request.name, &value)?;
        }
        EnvSensitivity::Secret => {
            if request.positional.is_some() {
                return Err("secret environment variables cannot use positional values".into());
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
            _ => return Err("unexpected env get argument".into()),
        }
        index += 1;
    }
    let Some(name) = name else {
        return Err("missing env name".into());
    };
    let lb = open_existing(lockbox_path, access)?;
    if secret {
        if let Some(()) = lb.with_secret_env(&name, |value| println!("{value}"))? {
            return Ok(());
        }
    } else if let Some(value) = lb.get_env(&name)? {
        println!("{value}");
    }
    Ok(())
}

struct EnvSetRequest {
    name: String,
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
                                .ok_or("missing --value argument")?
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
                                .ok_or("missing --file argument")?
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
                                .ok_or("missing --from-env argument")?
                                .to_string(),
                        ),
                    )?;
                }
                value if name.is_none() => name = Some(value.to_string()),
                value if positional.is_none() => positional = Some(value.to_string()),
                _ => return Err("unexpected env set argument".into()),
            }
            index += 1;
        }
        let Some(name) = name else {
            return Err("missing env name".into());
        };
        if source.is_some() == positional.is_some() {
            return Err("env set requires exactly one value source".into());
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
        match self.source.as_ref().ok_or("missing value source")? {
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
        match self.source.as_ref().ok_or("missing value source")? {
            ValueSource::Interactive => Ok(prompt_secret("Secret value: ")?),
            ValueSource::Value(value) => {
                let _ = value;
                Err("--value is not accepted for secret env values; use --stdin, --file, --interactive, or --from-env".into())
            }
            ValueSource::File(path) => read_secret_file(path),
            ValueSource::Stdin => read_secret_stdin(),
            ValueSource::FromEnv(name) => {
                SecretString::try_from_env(name)?.ok_or_else(|| format!("{name} is not set").into())
            }
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

fn set_source(target: &mut Option<ValueSource>, source: ValueSource) -> CliResult<()> {
    if target.is_some() {
        return Err("env set accepts exactly one value source".into());
    }
    *target = Some(source);
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
