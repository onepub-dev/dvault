use clap::{Arg, ArgAction, Command};

const ABOUT: &str =
    "Create encrypted file archives, store secrets safely, and share access with public keys.";

pub(crate) fn command(verbose: bool) -> Command {
    Command::new("lockbox")
        .about(ABOUT)
        .disable_version_flag(true)
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand_help_heading("Available commands")
        .after_help("Run \"lockbox <command> --help\" for more information about a command.")
        .next_help_heading("Global options")
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Show detailed command forms and advanced options."),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .global(true)
                .value_name("RAW_CONTENT_KEY")
                .hide(!verbose)
                .help("Use a raw content key for this command."),
        )
        .subcommands([
            archive_command("create", "Create a new encrypted lockbox.")
                .after_help(
                    "By default, create prompts for a new lockbox password. Password and recipient lockboxes use the local vault for key recovery metadata, so run `lockbox vault init` first.\n\nExamples:\n  lockbox vault init\n  lockbox create secrets.lbox\n  lockbox create --recipient alice secrets.lbox",
                )
                .arg(
                    Arg::new("recipient")
                        .long("recipient")
                        .value_name("VAULT_KEY_OR_RECIPIENT")
                        .help("Create the lockbox for a vault key or trusted recipient."),
                )
                .arg(required("lockbox", "Lockbox path.")),
            archive_command("open", "Unlock a lockbox for later commands.")
                .arg(
                    Arg::new("list")
                        .long("list")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("lockbox")
                        .help("List lockboxes currently cached as open."),
                )
                .arg(optional("lockbox", "Lockbox path.").required_unless_present("list")),
            archive_command("lock", "Forget cached unlock access.")
                .visible_alias("close")
                .arg(
                    Arg::new("all")
                        .long("all")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("lockbox")
                        .help("Forget cached unlock access for all lockboxes."),
                )
                .arg(
                    optional("lockbox", "Lockbox path.")
                        .required_unless_present("all")
                        .conflicts_with("all"),
                ),
            archive_command(
                "recover",
                "Recover readable entries from a damaged lockbox.",
            )
            .arg(required("lockbox", "Lockbox path.")),
            archive_command("doctor", "Show local vault and agent diagnostics."),
            file_command("add", "Add a file or directory to a lockbox.")
                .arg(
                    Arg::new("jobs")
                        .long("jobs")
                        .value_name("auto|1|N")
                        .hide(!verbose)
                        .help("Set import worker count."),
                )
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("source", "Source file or directory."))
                .arg(optional(
                    "lockbox-path",
                    "Destination path inside the lockbox. Defaults to root.",
                )),
            file_command("extract", "Extract files from a lockbox.")
                .arg(required("lockbox", "Lockbox path."))
                .arg(
                    Arg::new("to")
                        .long("to")
                        .value_name("DESTINATION")
                        .conflicts_with_all(["lockbox-path", "destination"])
                        .help("Extract the full lockbox to a directory."),
                )
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .action(ArgAction::SetTrue)
                        .help("Overwrite existing files."),
                )
                .arg(
                    Arg::new("restore-symlinks")
                        .long("restore-symlinks")
                        .action(ArgAction::SetTrue)
                        .help("Restore symlinks when extracting a directory."),
                )
                .arg(
                    Arg::new("restore-permissions")
                        .long("restore-permissions")
                        .action(ArgAction::SetTrue)
                        .help("Restore file permissions when extracting a directory."),
                )
                .arg(
                    optional("lockbox-path", "Path inside the lockbox.")
                        .required_unless_present("to"),
                )
                .arg(optional("destination", "Destination path.").required_unless_present("to")),
            file_command("cat", "Write a stored file to stdout.")
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("lockbox-path", "Path inside the lockbox.")),
            file_command("list", "List stored entries.")
                .visible_alias("ls")
                .arg(required("lockbox", "Lockbox path."))
                .arg(optional("path", "Path inside the lockbox.")),
            file_command("rm", "Remove a stored entry.")
                .visible_alias("remove")
                .arg(
                    Arg::new("force")
                        .long("force")
                        .visible_alias("noask")
                        .action(ArgAction::SetTrue)
                        .help("Remove without an interactive confirmation."),
                )
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("lockbox-path", "Path inside the lockbox.")),
            file_command("rename", "Rename a stored entry.")
                .visible_alias("mv")
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("from", "Existing path inside the lockbox."))
                .arg(required("to", "New path inside the lockbox.")),
            env_command(),
            recipient_command(),
            sharing_command("add-recipient", "Share a lockbox with another public key.")
                .hide(!verbose)
                .arg(required("lockbox", "Lockbox path."))
                .arg(required(
                    "recipient",
                    "Public key path or trusted recipient name.",
                )),
            sharing_command("list-keys", "List keys that can unlock a lockbox.")
                .hide(!verbose)
                .arg(required("lockbox", "Lockbox path.")),
            sharing_command("remove-key", "Remove a key from a lockbox.")
                .hide(!verbose)
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("slot-id", "Key slot id.")),
            vault_command(verbose),
            developer_command("visualize", "Print internal lockbox structure.")
                .visible_alias("visualise")
                .arg(required("lockbox", "Lockbox path.")),
            developer_command("keygen", "Generate raw recipient key files.")
                .arg(required("private-key", "Private key output path."))
                .arg(required("public-key", "Public key output path.")),
            developer_command("open-key", "Unlock using a vault private key.")
                .arg(required("lockbox", "Lockbox path."))
                .arg(optional("vault-key", "Vault private key name.")),
        ])
}

pub(crate) fn usage(verbose: bool) {
    eprintln!(
        "{ABOUT}

Usage: lockbox <command> [arguments]

Global options:
    --verbose        Show detailed command forms and advanced options.
-h, --help           Print this usage information.

Available commands:

Archives
  create          Create a new encrypted lockbox.
  open            Unlock a lockbox for later commands.
  lock            Forget cached unlock access.
  recover         Recover readable entries from a damaged lockbox.
  doctor          Show local vault and agent diagnostics.

Files
  add             Add a file or directory to a lockbox.
  extract         Extract files from a lockbox.
  cat             Write a stored file to stdout.
  list            List stored entries.
  rm              Remove a stored entry.
  rename          Rename a stored entry.

Environment
  env             Store, retrieve, list, export, or remove environment values.

Sharing
  recipient       Manage recipient access for a lockbox.

Vault
  vault           Manage your private keys and trusted public keys."
    );

    if verbose {
        eprintln!(
            "
Advanced global options:
    --key <raw-content-key>    Use a raw content key for this command.

Advanced command options:
  lockbox add --jobs auto|1|N <lockbox> <source> <lockbox-path>

Developer and compatibility commands:
  add-recipient   Share a lockbox with another public key.
  list-keys       List keys that can unlock a lockbox.
  remove-key      Remove a key from a lockbox.
  keygen          Generate raw recipient key files.
  open-key        Unlock using a vault private key.
  visualize       Print internal lockbox structure.

Environment variables:
  LOCKBOX_KEY=<raw-content-key> lockbox <command> ...
  LOCKBOX_PASSWORD=<password> lockbox open <lockbox>
  LOCKBOX_VAULT_PASSWORD=<password> lockbox vault <command>
  LOCKBOX_PLATFORM_SECRET_STORE=auto|disabled lockbox vault <command>
  LOCKBOX_AGENT_DIR=<dir> lockbox <command> ...
  LOCKBOX_VAULT_DIR=<dir> lockbox <command> ..."
        );
    }

    eprintln!(
        "
Run \"lockbox <command> --help\" for more information about a command."
    );
}

fn archive_command(name: &'static str, about: &'static str) -> Command {
    base_command(name, about)
}

fn file_command(name: &'static str, about: &'static str) -> Command {
    base_command(name, about)
}

fn sharing_command(name: &'static str, about: &'static str) -> Command {
    base_command(name, about)
}

fn developer_command(name: &'static str, about: &'static str) -> Command {
    base_command(name, about).hide(true)
}

fn base_command(name: &'static str, about: &'static str) -> Command {
    Command::new(name).about(about)
}

fn env_command() -> Command {
    base_command(
        "env",
        "Store, retrieve, list, export, or remove environment values.",
    )
    .after_help(
        "Normal values are printed by `env get` and included by `env export`.\nSecret values are encrypted the same way, but are redacted from `env export` and require `env get --secret` to print.",
    )
    .subcommand_required(true)
    .arg_required_else_help(true)
    .subcommand(
        Command::new("set")
            .about("Store an environment value.")
            .arg(required("lockbox", "Lockbox path."))
            .arg(
                Arg::new("secret")
                    .short('s')
                    .long("secret")
                    .action(ArgAction::SetTrue)
                    .help("Store the value as secret."),
            )
            .arg(required("name", "Environment variable name."))
            .arg(
                Arg::new("positional-value")
                    .value_name("VALUE")
                    .allow_hyphen_values(true)
                    .help("Literal value to store."),
            )
            .arg(
                Arg::new("interactive")
                    .short('i')
                    .long("interactive")
                    .action(ArgAction::SetTrue)
                    .help("Prompt for the value."),
            )
            .arg(
                Arg::new("stdin")
                    .short('t')
                    .long("stdin")
                    .action(ArgAction::SetTrue)
                    .help("Read the value from stdin."),
            )
            .arg(
                Arg::new("value")
                    .short('v')
                    .long("value")
                    .value_name("VALUE")
                    .help("Read the value from this argument."),
            )
            .arg(
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .value_name("FILE")
                    .help("Read the value from a file."),
            )
            .arg(
                Arg::new("from-env")
                    .short('e')
                    .long("from-env")
                    .value_name("NAME")
                    .help("Read the value from a process environment variable."),
            ),
    )
    .subcommand(
        Command::new("get")
            .about("Print one stored environment value by name.")
            .after_help(
                "Examples:\n  lockbox env get secrets.lbox APP_MODE\n  lockbox env get --secret secrets.lbox API_TOKEN\n  lockbox env get --secret --output api-token.txt secrets.lbox API_TOKEN",
            )
            .arg(required("lockbox", "Lockbox path."))
            .arg(
                Arg::new("secret")
                    .short('s')
                    .long("secret")
                    .action(ArgAction::SetTrue)
                    .help("Print a secret value."),
            )
            .arg(
                Arg::new("output")
                    .long("output")
                    .value_name("FILE")
                    .help("Write the exact value bytes to a file instead of stdout."),
            )
            .arg(
                Arg::new("overwrite")
                    .long("overwrite")
                    .requires("output")
                    .action(ArgAction::SetTrue)
                    .help("Replace the output file if it already exists."),
            )
            .arg(required("name", "Environment variable name.")),
    )
    .subcommand(
        Command::new("list")
            .about("List environment values.")
            .visible_alias("ls")
            .arg(required("lockbox", "Lockbox path.")),
    )
    .subcommand(
        Command::new("export")
            .about("Print all non-secret environment values in an importable format.")
            .after_help(
                "Examples:\n  eval \"$(lockbox env export secrets.lbox)\"\n  lockbox env export --format posix secrets.lbox > env.sh\n  lockbox env export --format powershell secrets.lbox | Invoke-Expression\n\nFormats:\n  posix       NAME='value' lines for sh, bash, and zsh. Default.\n  powershell  $env:NAME = 'value' lines for PowerShell.\n  cmd         set \"NAME=value\" lines for cmd.exe.\n  json        One JSON object per line with name and value fields.\n\n`env export` writes to stdout. Use shell redirection to write it to a file.",
            )
            .arg(
                Arg::new("format")
                    .long("format")
                    .value_name("posix|powershell|cmd|json")
                    .default_value("posix")
                    .help("Output format."),
            )
            .arg(required("lockbox", "Lockbox path.")),
    )
    .subcommand(
        Command::new("rm")
            .about("Remove an environment value.")
            .visible_alias("remove")
            .arg(required("lockbox", "Lockbox path."))
            .arg(required("name", "Environment variable name.")),
    )
}

fn recipient_command() -> Command {
    sharing_command("recipient", "Manage recipient access for a lockbox.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Share a lockbox with a recipient public key.")
                .arg(required("lockbox", "Lockbox path."))
                .arg(required(
                    "recipient",
                    "Public key path or trusted recipient name.",
                )),
        )
        .subcommand(
            Command::new("list")
                .about("List recipients that can open a lockbox.")
                .visible_alias("ls")
                .arg(required("lockbox", "Lockbox path.")),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove recipient access from a lockbox.")
                .visible_alias("rm")
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("slot-id", "Recipient slot id.")),
        )
}

fn vault_command(verbose: bool) -> Command {
    base_command("vault", "Manage your private keys and trusted public keys.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("init")
                .about("Create or open the local vault.")
                .after_help(
                    "The local vault stores private keys, trusted public keys, and key-directory backups. A new vault also gets a default recipient key. Keep the vault password backed up; Lockbox cannot recover private keys from the vault without it.\n\nIf the vault already exists, init reports the path and makes no changes. Use --verify to validate the password, or --overwrite only when replacing the vault and losing records stored only there.",
                )
                .arg(
                    Arg::new("verify")
                        .long("verify")
                        .conflicts_with("overwrite")
                        .action(ArgAction::SetTrue)
                        .help("Ask for the vault password and verify the existing vault opens."),
                )
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .conflicts_with("verify")
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing local vault."),
                ),
        )
        .subcommand(
            Command::new("list")
                .about("List local vault records.")
                .visible_alias("ls"),
        )
        .subcommand(Command::new("open").about("List lockboxes currently cached as open."))
        .subcommand(
            Command::new("path")
                .about("Print the local vault directory.")
                .hide(!verbose),
        )
        .subcommand(vault_key_command(verbose))
        .subcommand(
            Command::new("keygen")
                .about("Generate a recipient key in the local vault.")
                .hide(!verbose)
                .after_help(
                    "Vault recipient keys let you create and open lockboxes without sharing passwords. The private key stays in the local vault. Share the public key so other users can create lockboxes for you, or export it with `lockbox vault export-public`.\n\nIf no name is supplied, Lockbox uses the default key name: default.",
                )
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .hide(!verbose)
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing private key."),
                )
                .arg(optional("name", "Vault key name."))
                .arg(optional("public-key-output", "Public key output path.")),
        )
        .subcommand(
            Command::new("import-key")
                .about("Import a private key into the local vault.")
                .hide(!verbose)
                .arg(required("name", "Vault key name."))
                .arg(required("private-key", "Private key path."))
                .arg(optional("public-key-output", "Public key output path.")),
        )
        .subcommand(
            Command::new("export-key")
                .about("Export a private key from the local vault.")
                .hide(!verbose)
                .arg(format_arg(verbose))
                .arg(
                    Arg::new("args")
                        .value_names(["name", "private-key-output"])
                        .num_args(1..=2)
                        .required(true)
                        .help("Optional vault key name followed by the private key output path."),
                ),
        )
        .subcommand(
            Command::new("export-public")
                .about("Export a public key from the local vault.")
                .hide(!verbose)
                .arg(format_arg(verbose))
                .arg(
                    Arg::new("args")
                        .value_names(["name", "public-key-output"])
                        .num_args(1..=2)
                        .required(true)
                        .help("Optional vault key name followed by the public key output path."),
                ),
        )
        .subcommand(
            Command::new("trust")
                .about("Store a trusted recipient public key.")
                .subcommand(
                    Command::new("add")
                        .about("Store a trusted recipient public key.")
                        .arg(
                            Arg::new("overwrite")
                                .long("overwrite")
                                .hide(!verbose)
                                .action(ArgAction::SetTrue)
                                .help("Replace an existing trusted recipient."),
                        )
                        .arg(required("name", "Trusted recipient name."))
                        .arg(required("public-key", "Public key path.")),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove a trusted recipient public key.")
                        .visible_alias("rm")
                        .arg(required("name", "Trusted recipient name.")),
                )
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .hide(!verbose)
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing trusted recipient."),
                )
                .arg(optional("name", "Trusted recipient name."))
                .arg(optional("public-key", "Public key path.")),
        )
        .subcommand(
            Command::new("platform-store")
                .about("Manage platform secret-store integration.")
                .arg(
                    Arg::new("command")
                        .value_name("status|enable|disable|forget")
                        .default_value("status")
                        .help("Platform secret-store command."),
                ),
        )
        .subcommand(
            Command::new("remove-key")
                .about("Remove a private key from the local vault.")
                .hide(!verbose)
                .arg(
                    Arg::new("force")
                        .long("force")
                        .visible_alias("noask")
                        .action(ArgAction::SetTrue)
                        .help("Remove the key without an interactive confirmation."),
                )
                .arg(optional("name", "Vault key name.")),
        )
        .subcommand(
            Command::new("remove-trusted")
                .about("Remove a trusted recipient public key.")
                .hide(!verbose)
                .arg(required("name", "Trusted recipient name.")),
        )
}

fn vault_key_command(verbose: bool) -> Command {
    Command::new("key")
        .about("Manage vault recipient keys.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("create")
                .about("Generate a recipient key in the local vault.")
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .hide(!verbose)
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing private key."),
                )
                .arg(optional("name", "Vault key name."))
                .arg(optional("public-key-output", "Public key output path.")),
        )
        .subcommand(
            Command::new("import")
                .about("Import a private key into the local vault.")
                .arg(required("name", "Vault key name."))
                .arg(required("private-key", "Private key path."))
                .arg(optional("public-key-output", "Public key output path.")),
        )
        .subcommand(
            Command::new("export")
                .about("Export a private key from the local vault.")
                .arg(format_arg(verbose))
                .arg(
                    Arg::new("args")
                        .value_names(["name", "private-key-output"])
                        .num_args(1..=2)
                        .required(true)
                        .help("Optional vault key name followed by the private key output path."),
                ),
        )
        .subcommand(
            Command::new("export-public")
                .about("Export a public key from the local vault.")
                .arg(format_arg(verbose))
                .arg(
                    Arg::new("args")
                        .value_names(["name", "public-key-output"])
                        .num_args(1..=2)
                        .required(true)
                        .help("Optional vault key name followed by the public key output path."),
                ),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a private key from the local vault.")
                .visible_alias("rm")
                .arg(
                    Arg::new("force")
                        .long("force")
                        .visible_alias("noask")
                        .action(ArgAction::SetTrue)
                        .help("Remove the key without an interactive confirmation."),
                )
                .arg(optional("name", "Vault key name.")),
        )
}

fn format_arg(verbose: bool) -> Arg {
    Arg::new("format")
        .long("format")
        .hide(!verbose)
        .value_name("lockbox-pem|jwk|jwks|raw-hex")
        .help("Select the key file format.")
}

fn required(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name).value_name(name).required(true).help(help)
}

fn optional(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name).value_name(name).required(false).help(help)
}
