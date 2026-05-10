mod context;
mod env;
mod files;
mod help;
mod keys;
mod recovery;
mod visualize;

use context::{read_access, remove_global_flag, CliResult};

pub(crate) fn run() -> CliResult<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("__agent") {
        return Ok(lockbox_vault::serve_agent()?);
    }

    let verbose_help =
        remove_global_flag(&mut args, "--verbose") || remove_global_flag(&mut args, "-v");
    if remove_global_flag(&mut args, "--help") || remove_global_flag(&mut args, "-h") {
        help::usage(verbose_help);
        return Ok(());
    }
    if args.is_empty() {
        help::usage(verbose_help);
        return Ok(());
    }

    let access = read_access(&mut args)?;
    let Some(command) = args.first().cloned() else {
        help::usage(verbose_help);
        return Ok(());
    };
    args.remove(0);

    match command.as_str() {
        "create" => keys::create(&args, &access)?,
        "open" => keys::open(&args)?,
        "lock" => keys::lock(&args)?,
        "keygen" => keys::keygen(&args)?,
        "open-key" => keys::open_key(&args)?,
        "add-recipient" => keys::add_recipient(&args, &access)?,
        "list-keys" => keys::list_keys(&args, &access)?,
        "remove-key" => keys::remove_key(&args, &access)?,
        "add" => files::add(&args, &access)?,
        "extract" => files::extract(&args, &access)?,
        "cat" => files::cat(&args, &access)?,
        "list" => files::list(&args, &access)?,
        "rm" => files::remove(&args, &access)?,
        "rename" => files::rename(&args, &access)?,
        "env" => env::run(&args, &access)?,
        "recover" => recovery::run(&args, &access)?,
        "visualize" | "visualise" => visualize::run(&args, &access)?,
        _ => help::usage(verbose_help),
    }

    Ok(())
}
