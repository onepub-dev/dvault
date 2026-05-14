use super::context::{open_existing, open_or_create, require_arg, Access, CliResult};
use super::help::usage;

pub(crate) fn run(args: &[String], access: &Access) -> CliResult<()> {
    let subcommand = require_arg(args, 0, "env command")?;
    let lockbox_path = require_arg(args, 1, "lockbox")?;
    match subcommand {
        "set" => {
            let name = require_arg(args, 2, "name")?;
            let value = require_arg(args, 3, "value")?;
            let mut lb = open_or_create(lockbox_path, access)?;
            lb.set_env(name, value)?;
            lb.commit()?;
        }
        "get" => {
            let name = require_arg(args, 2, "name")?;
            let lb = open_existing(lockbox_path, access)?;
            if let Some(value) = lb.get_env(name)? {
                println!("{value}");
            }
        }
        "list" => {
            let lb = open_existing(lockbox_path, access)?;
            for name in lb.list_env()? {
                println!("{name}");
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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
