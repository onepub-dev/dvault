use clap::{Arg, ArgAction, Command};

const ABOUT: &str =
    "Create encrypted file archives, store secrets safely, and share access with public keys.";

pub(crate) fn command(verbose: bool) -> Command {
    Command::new("lockbox")
        .about(ABOUT)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
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
                .help("Developer override: unlock with a raw content key supplied out of band."),
        )
        .subcommands([
            archive_command("create", "Create a new encrypted lockbox.")
                .after_help(
                    "By default, create prompts for a new lockbox password. Password and shared lockboxes use the local vault for key recovery metadata, so run `lockbox vault init` first.\n\nExamples:\n  lockbox vault init\n  lockbox create secrets.lbox\n  lockbox create --for alice secrets.lbox",
                )
                .arg(
                    Arg::new("for")
                        .long("for")
                        .value_name("IDENTITY_OR_CONTACT")
                        .help("Create the lockbox for one of your identities or a saved contact."),
                )
                .arg(required("lockbox", "Lockbox path.")),
            archive_command("unlock", "Unlock a lockbox for later commands.")
                .after_help(
                    "Unlocking a lockbox prompts for its password, caches unlock access in the session agent, and lets later commands use the lockbox without prompting again.\n\nExamples:\n  lockbox unlock secrets.lbox\n  lockbox unlock --duration 30m secrets.lbox\n  LOCKBOX_PASSWORD=secret lockbox unlock secrets.lbox\n  printf '%s\\n' \"$LOCKBOX_PASSWORD\" | lockbox unlock --password-stdin secrets.lbox",
                )
                .arg(
                    Arg::new("duration")
                        .short('d')
                        .long("duration")
                        .value_name("DURATION")
                        .help("Keep the lockbox unlocked for this session duration, such as 30s, 30m, 2h, or 1d."),
                )
                .arg(
                    Arg::new("password-env")
                        .long("password-env")
                        .value_name("NAME")
                        .conflicts_with_all(["password-file", "password-stdin"])
                        .help("Read the lockbox password from this environment variable."),
                )
                .arg(
                    Arg::new("password-file")
                        .long("password-file")
                        .value_name("FILE")
                        .conflicts_with_all(["password-env", "password-stdin"])
                        .help("Read the lockbox password from a file."),
                )
                .arg(
                    Arg::new("password-stdin")
                        .long("password-stdin")
                        .action(ArgAction::SetTrue)
                        .conflicts_with_all(["password-env", "password-file"])
                        .help("Read the lockbox password from stdin."),
                )
                .arg(required("lockbox", "Lockbox path.")),
            archive_command("lock", "Forget cached unlock access.")
                .after_help(
                    "Examples:\n  lockbox lock secrets.lbox\n  lockbox lock --all",
                )
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
            archive_command("recover", "Recover readable entries from a damaged lockbox.")
                .after_help(
                    "Recovery writes a new lockbox containing readable entries. Use --report or --dry-run to inspect what can be recovered without writing an output file.\n\nExamples:\n  lockbox recover damaged.lbox --output recovered.lbox\n  lockbox recover --report --format table damaged.lbox",
                )
                .arg(required("lockbox", "Damaged lockbox path."))
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("RECOVERED_LOCKBOX")
                        .required_unless_present_any(["report", "dry-run"])
                        .help("Write recovered entries to this new lockbox."),
                )
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .requires("output")
                        .action(ArgAction::SetTrue)
                        .help("Replace the recovered lockbox output file if it already exists."),
                )
                .arg(
                    Arg::new("report")
                        .long("report")
                        .action(ArgAction::SetTrue)
                        .conflicts_with_all(["output", "overwrite"])
                        .help("Print a recovery report without writing a recovered lockbox."),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .conflicts_with_all(["output", "overwrite", "report"])
                        .help("Alias for --report."),
                )
                .arg(output_format_arg()),
            archive_command("doctor", "Show local vault and session agent diagnostics.")
                .after_help("Examples:\n  lockbox doctor"),
            file_command("add", "Add a file or directory to a lockbox.")
                .after_help(
                    "Examples:\n  lockbox add secrets.lbox ./notes.txt\n  lockbox add secrets.lbox ./project /project\n  lockbox add secrets.lbox ./large-dir /archive",
                )
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
                .after_help(
                    "Examples:\n  lockbox extract secrets.lbox /notes.txt ./notes.txt\n  lockbox extract --to ./restore secrets.lbox\n  lockbox extract --to ./restore --overwrite secrets.lbox",
                )
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
                .after_help(
                    "Examples:\n  lockbox cat secrets.lbox /notes.txt\n  lockbox cat secrets.lbox /notes.txt > notes.txt",
                )
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("lockbox-path", "Path inside the lockbox.")),
            file_command("list", "List stored entries.")
                .visible_alias("ls")
                .after_help(
                    "Examples:\n  lockbox list secrets.lbox\n  lockbox list secrets.lbox /project\n  lockbox list --recursive --format json secrets.lbox",
                )
                .arg(output_format_arg())
                .arg(
                    Arg::new("recursive")
                        .short('R')
                        .long("recursive")
                        .action(ArgAction::SetTrue)
                        .help("List entries below child directories."),
                )
                .arg(required("lockbox", "Lockbox path."))
                .arg(optional("path", "Path inside the lockbox.")),
            file_command("rm", "Remove a stored entry.")
                .visible_alias("remove")
                .after_help(
                    "Examples:\n  lockbox rm secrets.lbox /notes.txt\n  lockbox rm --force secrets.lbox /old.txt",
                )
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
                .after_help(
                    "Examples:\n  lockbox rename secrets.lbox /draft.txt /final.txt\n  lockbox mv secrets.lbox /old-dir /archive/old-dir",
                )
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("from", "Existing path inside the lockbox."))
                .arg(required("to", "New path inside the lockbox.")),
            env_command(),
            access_command(),
            vault_command(verbose),
            developer_command("visualize", "Print internal lockbox structure.")
                .visible_alias("visualise")
                .arg(required("lockbox", "Lockbox path.")),
            developer_command("keygen", "Generate raw keypair files.")
                .arg(required("private-key", "Private key output path."))
                .arg(required("public-key", "Public key output path.")),
            developer_command("unlock-key", "Unlock using a vault private key.")
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
  unlock          Unlock a lockbox for later commands.
  lock            Forget cached unlock access.
  recover         Recover readable entries from a damaged lockbox.
  doctor          Show local vault and session agent diagnostics.

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
  access          Manage who can unlock a lockbox.

Vault
  vault           Manage identities and contacts."
    );

    if verbose {
        eprintln!(
            "
Advanced global options:
    --key <raw-content-key>    Developer override: unlock with a raw content key supplied out of band.

Advanced command options:
  lockbox add --jobs auto|1|N <lockbox> <source> <lockbox-path>

Developer and compatibility commands:
  keygen          Generate raw keypair files.
  unlock-key      Unlock using a vault private key.
  visualize       Print internal lockbox structure.

Environment variables:
  LOCKBOX_KEY=<raw-content-key> lockbox <command> ...
    LOCKBOX_PASSWORD=<password> lockbox unlock <lockbox>
  LOCKBOX_UNLOCK_DURATION=30m lockbox unlock <lockbox>
  LOCKBOX_VAULT_PASSWORD=<password> lockbox vault <command>
  LOCKBOX_PLATFORM_SECRET_STORE=auto|disabled lockbox vault <command>
  LOCKBOX_SESSION_AGENT_DIR=<dir> lockbox <command> ...
  LOCKBOX_VAULT_DIR=<dir> lockbox <command> ...

Raw content keys are for developer recovery and local testing. Lockbox does not
print or export them; normal commands should unlock through the vault session."
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
    Command::new(name)
        .about(about)
        .disable_help_subcommand(true)
}

fn env_command() -> Command {
    base_command(
        "env",
        "Store, retrieve, list, export, or remove environment values.",
    )
    .after_help(
        "Normal values are printed by `env get` and included by `env export`.\nSecret values are encrypted the same way, but are redacted from `env export` and require `env get --secret` to print.\n\nExamples:\n  lockbox env set secrets.lbox APP_MODE production\n  lockbox env get secrets.lbox APP_MODE\n  lockbox env export secrets.lbox",
    )
    .subcommand_required(true)
    .arg_required_else_help(true)
    .subcommand(
        Command::new("set")
            .about("Store an environment value.")
            .after_help(
                "Examples:\n  lockbox env set secrets.lbox APP_MODE production\n  lockbox env set --secret secrets.lbox API_TOKEN --interactive\n  printf '%s' \"$TOKEN\" | lockbox env set --secret --stdin secrets.lbox API_TOKEN",
            )
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
            .after_help(
                "Examples:\n  lockbox env list secrets.lbox\n  lockbox env list --format json secrets.lbox",
            )
            .arg(output_format_arg())
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
            .after_help(
                "Examples:\n  lockbox env rm secrets.lbox APP_MODE\n  lockbox env remove secrets.lbox API_TOKEN",
            )
            .arg(required("lockbox", "Lockbox path."))
            .arg(required("name", "Environment variable name.")),
    )
}

fn access_command() -> Command {
    sharing_command("access", "Manage who can unlock a lockbox.")
        .after_help(
            "Access entries are attached to a lockbox. They name identities or contacts that can unlock that lockbox.\n\nExamples:\n  lockbox access list secrets.lbox\n  lockbox access add secrets.lbox alice\n  lockbox access remove secrets.lbox 2",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Allow an identity or contact to unlock a lockbox.")
                .after_help(
                    "Examples:\n  lockbox access add secrets.lbox alice\n  lockbox access add secrets.lbox ./alice.pub",
                )
                .arg(required("lockbox", "Lockbox path."))
                .arg(required(
                    "identity-or-contact",
                    "Identity name, contact name, or public key path.",
                )),
        )
        .subcommand(
            Command::new("list")
                .about("List who can unlock a lockbox.")
                .visible_alias("ls")
                .after_help(
                    "Examples:\n  lockbox access list secrets.lbox\n  lockbox access list --format json secrets.lbox",
                )
                .arg(output_format_arg())
                .arg(required("lockbox", "Lockbox path.")),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove access from a lockbox.")
                .visible_alias("rm")
                .after_help(
                    "Examples:\n  lockbox access remove secrets.lbox 2\n  lockbox access rm secrets.lbox 2",
                )
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("slot-id", "Access slot id.")),
        )
}

fn vault_command(verbose: bool) -> Command {
    base_command("vault", "Manage identities and contacts.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("init")
                .about("Create or unlock the local vault.")
                .after_help(
                    "The local vault stores identities, contacts, and key-directory backups. A new vault also gets a default identity. Keep the vault password backed up; Lockbox cannot recover identities from the vault without it.\n\nIf the vault already exists, init reports the path and makes no changes. Use --verify to validate the password, or --overwrite only when replacing the vault and losing records stored only there.",
                )
                .arg(
                    Arg::new("verify")
                        .long("verify")
                        .conflicts_with("overwrite")
                        .action(ArgAction::SetTrue)
                        .help("Ask for the vault password and verify the existing vault unlocks."),
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
            Command::new("sessions")
                .about("Manage unlocked lockbox sessions.")
                .disable_help_subcommand(true)
                .arg_required_else_help(false)
                .after_help(
                    "With no subcommand, sessions lists lockboxes currently cached as unlocked.\n\nExamples:\n  lockbox vault sessions\n  lockbox vault sessions lock secrets.lbox\n  lockbox vault sessions auto-unlock status",
                )
                .arg(output_format_arg())
                .subcommand(
                    Command::new("lock")
                        .about("Lock one unlocked lockbox session.")
                        .after_help("Examples:\n  lockbox vault sessions lock secrets.lbox")
                        .arg(required("lockbox", "Lockbox path.")),
                )
                .subcommand(
                    Command::new("lock-all")
                        .about("Lock every unlocked lockbox session.")
                        .after_help("Examples:\n  lockbox vault sessions lock-all"),
                )
                .subcommand(
                    Command::new("stop")
                        .about("Lock every unlocked session and stop the session agent.")
                        .after_help("Examples:\n  lockbox vault sessions stop"),
                )
                .subcommand(
                    Command::new("auto-unlock")
                        .about("Store the vault password in the operating system secret store so Lockbox can unlock the local vault automatically after your OS login session is unlocked.")
                        .disable_help_subcommand(true)
                        .arg_required_else_help(false)
                        .after_help(
                            "Examples:\n  lockbox vault sessions auto-unlock status\n  lockbox vault sessions auto-unlock enable\n  lockbox vault sessions auto-unlock forget",
                        )
                        .subcommand(
                            Command::new("status")
                                .about("Show whether auto-unlock is supported and enabled.")
                                .after_help(
                                    "Examples:\n  lockbox vault sessions auto-unlock status\n  lockbox vault sessions auto-unlock status --format json",
                                )
                                .arg(output_format_arg()),
                        )
                        .subcommand(
                            Command::new("enable")
                                .about("Allow Lockbox to store the vault password for auto-unlock.")
                                .after_help("Examples:\n  lockbox vault sessions auto-unlock enable"),
                        )
                        .subcommand(
                            Command::new("disable")
                                .about("Stop using auto-unlock.")
                                .after_help("Examples:\n  lockbox vault sessions auto-unlock disable"),
                        )
                        .subcommand(
                            Command::new("forget")
                                .about("Delete the stored vault password used for auto-unlock.")
                                .after_help("Examples:\n  lockbox vault sessions auto-unlock forget"),
                        ),
                ),
        )
        .subcommand(
            Command::new("path")
                .about("Print the local vault directory.")
                .hide(!verbose),
        )
        .subcommand(vault_identity_command(verbose))
        .subcommand(
            Command::new("contact")
                .about("Manage contacts that can be given access to a lockbox.")
                .disable_help_subcommand(true)
                .after_help(
                    "Contacts are saved public keys for other people or systems. A contact can be added to a lockbox access list, but cannot unlock lockboxes on this machine unless you also have the matching private identity.\n\nExamples:\n  lockbox vault contact list\n  lockbox vault contact add alice ./alice.pub\n  lockbox vault contact remove alice",
                )
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List saved contacts.")
                        .visible_alias("ls")
                        .after_help(
                            "Examples:\n  lockbox vault contact list\n  lockbox vault contact list --format json",
                        )
                        .arg(output_format_arg()),
                )
                .subcommand(
                    Command::new("add")
                        .about("Save a contact public key.")
                        .after_help(
                            "Examples:\n  lockbox vault contact add alice ./alice.pub\n  lockbox vault contact add --overwrite alice ./alice-new.pub",
                        )
                        .arg(
                            Arg::new("overwrite")
                                .long("overwrite")
                                .hide(!verbose)
                                .action(ArgAction::SetTrue)
                                .help("Replace an existing contact."),
                        )
                        .arg(required("name", "Contact name."))
                        .arg(required("public-key", "Public key path.")),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove a contact.")
                        .visible_alias("rm")
                        .after_help(
                            "Examples:\n  lockbox vault contact remove alice\n  lockbox vault contact rm alice",
                        )
                        .arg(required("name", "Contact name.")),
                ),
        )
}

fn vault_identity_command(verbose: bool) -> Command {
    Command::new("identity")
        .about("Manage identities that can unlock lockboxes on this machine.")
        .disable_help_subcommand(true)
        .after_help(
            "An identity is one of your local unlock identities. It includes private key material, so it can unlock lockboxes that grant access to it. To save someone else's public key, use `lockbox vault contact add`.\n\nExamples:\n  lockbox vault identity list\n  lockbox vault identity create laptop\n  lockbox vault identity export-public laptop ./laptop.pub",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("list")
                .about("List local identities.")
                .visible_alias("ls")
                .after_help(
                    "Examples:\n  lockbox vault identity list\n  lockbox vault identity list --format json",
                )
                .arg(output_format_arg()),
        )
        .subcommand(
            Command::new("create")
                .about("Create one of your identities.")
                .after_help(
                    "With no name, Lockbox creates the `default` identity. To write a shareable public key file, create the identity first and then run `lockbox vault identity export-public`.\n\nExamples:\n  lockbox vault identity create\n  lockbox vault identity create laptop\n  lockbox vault identity export-public laptop ./laptop.pub",
                )
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .hide(!verbose)
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing private key."),
                )
                .arg(optional("name", "Identity name."))
        )
        .subcommand(
            Command::new("import")
                .about("Import a private key into the local vault.")
                .after_help(
                    "Examples:\n  lockbox vault identity import laptop ./laptop.private\n  lockbox vault identity import laptop ./laptop.private ./laptop.pub",
                )
                .arg(required("name", "Identity name."))
                .arg(required("private-key", "Private key path."))
                .arg(optional("public-key-output", "Public key output path.")),
        )
        .subcommand(
            Command::new("export")
                .about("Export a private key from the local vault.")
                .after_help(
                    "Examples:\n  lockbox vault identity export ./default.private\n  lockbox vault identity export laptop ./laptop.private",
                )
                .arg(format_arg(verbose))
                .arg(
                    Arg::new("args")
                        .value_names(["name", "private-key-output"])
                        .num_args(1..=2)
                        .required(true)
                        .help("Optional identity name followed by the private key output path."),
                ),
        )
        .subcommand(
            Command::new("export-public")
                .about("Export a public key from the local vault.")
                .after_help(
                    "Examples:\n  lockbox vault identity export-public ./default.pub\n  lockbox vault identity export-public laptop ./laptop.pub",
                )
                .arg(format_arg(verbose))
                .arg(
                    Arg::new("args")
                        .value_names(["name", "public-key-output"])
                        .num_args(1..=2)
                        .required(true)
                        .help("Optional identity name followed by the public key output path."),
                ),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a private key from the local vault.")
                .visible_alias("rm")
                .after_help(
                    "Examples:\n  lockbox vault identity remove laptop\n  lockbox vault identity remove --force laptop",
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .visible_alias("noask")
                        .action(ArgAction::SetTrue)
                        .help("Remove the key without an interactive confirmation."),
                )
                .arg(optional("name", "Identity name.")),
        )
}

fn format_arg(verbose: bool) -> Arg {
    Arg::new("format")
        .long("format")
        .hide(!verbose)
        .value_name("lockbox-pem|jwk|jwks|raw-hex")
        .help("Select the key file format.")
}

fn output_format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("table|tsv|json")
        .default_value("table")
        .help("Output format.")
}

fn required(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name).value_name(name).required(true).help(help)
}

fn optional(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name).value_name(name).required(false).help(help)
}
