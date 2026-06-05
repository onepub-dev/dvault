use clap::{Arg, ArgAction, Command};

const ABOUT: &str =
    "Create encrypted file archives, store secrets safely, and share access with public keys.";
const VERBOSE_HELP_TEMPLATE: &str = "\
{about-with-newline}
{before-help}
{usage-heading} {usage}

{all-args}{after-help}\
";

pub(crate) fn command(verbose: bool) -> Command {
    let command = Command::new("lockbox")
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault init\n  lockbox create secrets.lbox\n  lockbox create --for alice secrets.lbox",
                    "Context:\n  Use create when starting a new encrypted archive. By default it prompts for a new lockbox password. Password and shared lockboxes use the local vault for key recovery metadata, so initialize the vault before creating important lockboxes.",
                ))
                .arg(
                    Arg::new("for")
                        .long("for")
                        .value_name("IDENTITY_OR_CONTACT")
                        .help("Create the lockbox for one of your identities or a saved contact."),
                )
                .arg(required("lockbox", "Lockbox path.")),
            archive_command("unlock", "Unlock a lockbox for later commands.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox unlock secrets.lbox\n  lockbox unlock --duration 30m secrets.lbox\n  LOCKBOX_PASSWORD=secret lockbox unlock secrets.lbox\n  printf '%s\\n' \"$LOCKBOX_PASSWORD\" | lockbox unlock --password-stdin secrets.lbox",
                    "Context:\n  Unlock prompts for the lockbox password, stores temporary unlock access in the session agent, and lets later commands read or modify the lockbox without prompting again. Use --duration when the session should expire sooner than the default.",
                ))
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox lock secrets.lbox\n  lockbox lock --all",
                    "Context:\n  Lock removes cached unlock access from the session agent. It does not change encrypted lockbox contents; it only makes later commands require unlock access again.",
                ))
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox recover damaged.lbox --output recovered.lbox\n  lockbox recover --report --format table damaged.lbox",
                    "Context:\n  Recover scans a damaged lockbox and writes a new lockbox containing readable entries. Use --report or --dry-run first when you want to inspect what can be recovered without writing an output file.",
                ))
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox doctor",
                    "Context:\n  Doctor reports local configuration and runtime state, including vault path, auto-unlock support, and whether the session agent is reachable. Use it when unlock, auto-unlock, or vault setup behaves unexpectedly.",
                )),
            file_command("add", "Add a file or directory to a lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox add secrets.lbox ./notes.txt\n  lockbox add secrets.lbox ./project /project\n  lockbox add secrets.lbox ./large-dir /archive",
                    "Context:\n  Add imports a host file or directory into an unlocked lockbox. If no destination path is supplied, files keep their filename at the lockbox root and directories import under the root. Use --jobs in verbose mode to tune large imports.",
                ))
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox extract secrets.lbox /notes.txt ./notes.txt\n  lockbox extract --to ./restore secrets.lbox\n  lockbox extract --to ./restore --overwrite secrets.lbox",
                    "Context:\n  Extract copies encrypted content back to the host filesystem. Use the single-file form for one stored path, or --to when restoring the whole lockbox into a directory.",
                ))
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox cat secrets.lbox /notes.txt\n  lockbox cat secrets.lbox /notes.txt > notes.txt",
                    "Context:\n  Cat streams one stored file to stdout. Use it for inspection, piping, or shell redirection when you do not want Lockbox to create a host file directly.",
                ))
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("lockbox-path", "Path inside the lockbox.")),
            file_command("list", "List stored entries.")
                .visible_alias("ls")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox list secrets.lbox\n  lockbox list secrets.lbox /project\n  lockbox list --recursive --format json secrets.lbox",
                    "Context:\n  List shows files and inferred directories stored in a lockbox. The default view mirrors a normal directory listing; use --recursive when scripts or audits need full stored paths.",
                ))
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox rm secrets.lbox /notes.txt\n  lockbox rm --force secrets.lbox /old.txt",
                    "Context:\n  Remove deletes a stored file or directory entry from the lockbox and commits that change. Without --force, Lockbox asks for confirmation before changing the archive.",
                ))
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox rename secrets.lbox /draft.txt /final.txt\n  lockbox mv secrets.lbox /old-dir /archive/old-dir",
                    "Context:\n  Rename changes the path stored inside the lockbox. It does not touch host filesystem paths; both arguments are lockbox paths.",
                ))
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("from", "Existing path inside the lockbox."))
                .arg(required("to", "New path inside the lockbox.")),
            env_command(verbose),
            access_command(verbose),
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
        ]);
    if verbose {
        apply_verbose_help_template(command)
    } else {
        command
    }
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

fn env_command(verbose: bool) -> Command {
    base_command(
        "env",
        "Store, retrieve, list, export, or remove environment values.",
    )
    .after_help(verbose_help(
        verbose,
        "Examples:\n  lockbox env set secrets.lbox APP_MODE production\n  lockbox env get secrets.lbox APP_MODE\n  lockbox env export secrets.lbox",
        "Context:\n  Environment values are named data stored inside a lockbox. Normal values are printed by `env get` and included by `env export`. Secret values are encrypted the same way, but are redacted from `env export` and require `env get --secret` to print.",
    ))
    .subcommand_required(true)
    .arg_required_else_help(true)
    .subcommand(
        Command::new("set")
            .about("Store an environment value.")
            .after_help(verbose_help(
                verbose,
                "Examples:\n  lockbox env set secrets.lbox APP_MODE production\n  lockbox env set --secret secrets.lbox API_TOKEN --interactive\n  printf '%s' \"$TOKEN\" | lockbox env set --secret --stdin secrets.lbox API_TOKEN",
                "Context:\n  Env set writes one named value into a lockbox. Use --secret for values that should not be exported in bulk, such as tokens and passwords. Choose one value source: argument, prompt, stdin, file, or process environment.",
            ))
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
            .after_help(verbose_help(
                verbose,
                "Examples:\n  lockbox env get secrets.lbox APP_MODE\n  lockbox env get --secret secrets.lbox API_TOKEN\n  lockbox env get --secret --output api-token.txt secrets.lbox API_TOKEN",
                "Context:\n  Env get reads one named value from a lockbox. Secret values require --secret so accidental terminal output is an explicit user choice. Use --output when the exact bytes should go to a file.",
            ))
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
            .after_help(verbose_help(
                verbose,
                "Examples:\n  lockbox env list secrets.lbox\n  lockbox env list secrets.lbox /production\n  lockbox env list secrets.lbox '**/API_KEY'\n  lockbox env list --format json secrets.lbox",
                "Context:\n  Env list shows value names and whether each value is normal or secret. It does not print stored values. Pass a path such as /production to list that group, or a glob such as **/API_KEY to match names across groups.",
            ))
            .arg(output_format_arg())
            .arg(required("lockbox", "Lockbox path."))
            .arg(optional("pattern", "Optional env path or glob pattern.")),
    )
    .subcommand(
        Command::new("export")
            .about("Print all non-secret environment values in an importable format.")
            .after_help(verbose_help(
                verbose,
                "Examples:\n  eval \"$(lockbox env export secrets.lbox)\"\n  lockbox env export secrets.lbox /production\n  lockbox env export --format posix secrets.lbox > env.sh\n  lockbox env export --format powershell secrets.lbox | Invoke-Expression\n\nFormats:\n  posix       NAME='value' lines for sh, bash, and zsh. Default.\n  powershell  $env:NAME = 'value' lines for PowerShell.\n  cmd         set \"NAME=value\" lines for cmd.exe.\n  json        One JSON object per line with name and value fields.\n\n`env export` writes to stdout. Use shell redirection to write it to a file.",
                "Context:\n  Env export is intended for shell startup, CI setup, or scripting. It only includes non-secret values; use explicit `env get --secret` for secret values so they are never exported in bulk by accident. When exporting a path such as /production, only direct child names are emitted, so /production/API_KEY becomes API_KEY and nested values are skipped.",
            ))
            .arg(
                Arg::new("format")
                    .long("format")
                    .value_name("posix|powershell|cmd|json")
                    .default_value("posix")
                    .help("Output format."),
            )
            .arg(required("lockbox", "Lockbox path."))
            .arg(optional("path", "Optional env path to export.")),
    )
    .subcommand(
        Command::new("rm")
            .about("Remove an environment value.")
            .visible_alias("remove")
            .after_help(verbose_help(
                verbose,
                "Examples:\n  lockbox env rm secrets.lbox APP_MODE\n  lockbox env remove secrets.lbox API_TOKEN",
                "Context:\n  Env rm removes one named value from a lockbox. It affects only the lockbox record, not the current process environment.",
            ))
            .arg(required("lockbox", "Lockbox path."))
            .arg(required("name", "Environment variable name.")),
    )
}

fn access_command(verbose: bool) -> Command {
    sharing_command("access", "Manage who can unlock a lockbox.")
        .after_help(verbose_help(
            verbose,
            "Examples:\n  lockbox access list secrets.lbox\n  lockbox access add secrets.lbox alice\n  lockbox access remove secrets.lbox 2",
            "Context:\n  Access entries are stored on a lockbox and describe which identities or contacts may unlock it. Use this command when sharing a lockbox or rotating/removing access.",
        ))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Allow an identity or contact to unlock a lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox access add secrets.lbox alice\n  lockbox access add secrets.lbox identity:alice\n  lockbox access add secrets.lbox contact:alice\n  lockbox access add secrets.lbox alice ./alice.pub",
                    "Context:\n  Access add grants unlock access by adding an identity or contact to the lockbox. A bare name can refer to one of your saved identities or saved contacts. If both use the same name, use identity:name or contact:name. For a public key file, provide the contact name first so the lockbox can record who the access entry belongs to.",
                ))
                .arg(required("lockbox", "Lockbox path."))
                .arg(required(
                    "identity-or-contact",
                    "Identity name, contact name, identity:name, contact:name, or contact name for a public key file.",
                ))
                .arg(optional(
                    "public-key",
                    "Public key path. When supplied, the previous argument is stored as the access name.",
                )),
        )
        .subcommand(
            Command::new("list")
                .about("List who can unlock a lockbox.")
                .visible_alias("ls")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox access list secrets.lbox\n  lockbox access list --format json secrets.lbox",
                    "Context:\n  Access list shows the access slots currently attached to a lockbox. Use slot ids from this output when removing access.",
                ))
                .arg(output_format_arg())
                .arg(required("lockbox", "Lockbox path.")),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove access from a lockbox.")
                .visible_alias("rm")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox access remove secrets.lbox 2\n  lockbox access rm secrets.lbox 2",
                    "Context:\n  Access remove deletes one unlock slot from the lockbox. Lockbox prevents removing the last usable access entry because that could make the lockbox inaccessible.",
                ))
                .arg(required("lockbox", "Lockbox path."))
                .arg(required("slot-id", "Access slot id.")),
        )
        .subcommand(
            Command::new("refresh")
                .about("Refresh stale lockbox access entries.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox access refresh project.lbox alice\n  lockbox access refresh --all alice\n  lockbox access refresh --all --dry-run",
                    "Context:\n  Access refresh checks named recipient access entries and rewrites matching entries to the current vault identity key. Use --dry-run first to see the planned changes and missing known lockboxes.",
                ))
                .arg(
                    Arg::new("all")
                        .long("all")
                        .action(ArgAction::SetTrue)
                        .help("Check every lockbox known to the vault."),
                )
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX IDENTITY | IDENTITY")
                        .num_args(0..=2)
                        .help("Without --all, pass lockbox and identity. With --all, optionally pass one identity."),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Print the refresh plan without changing lockboxes."),
                )
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .help("Apply without interactive confirmation."),
                ),
        )
}

fn vault_command(verbose: bool) -> Command {
    base_command("vault", "Manage identities and contacts.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("init")
                .about("Create or unlock the local vault.")
                .after_help(verbose_help(
                    verbose,
                    "If the vault already exists, init reports the path and makes no changes. Use --verify to validate the password, or --overwrite only when replacing the vault and losing records stored only there.",
                    "Context:\n  The local vault stores identities, contacts, and key-directory backups. A new vault also gets a default identity. Keep the vault password backed up; Lockbox cannot recover identities from the vault without it.",
                ))
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault sessions\n  lockbox vault sessions lock secrets.lbox\n  lockbox vault sessions auto-unlock status",
                    "Context:\n  Sessions are temporary unlock records cached by the session agent. With no subcommand, sessions lists lockboxes currently cached as unlocked.",
                ))
                .arg(output_format_arg())
                .subcommand(
                    Command::new("lock")
                        .about("Lock one unlocked lockbox session.")
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault sessions lock secrets.lbox",
                            "Context:\n  Session lock removes cached unlock access for one lockbox. Use it when you are finished working with a lockbox but do not want to stop every session.",
                        ))
                        .arg(required("lockbox", "Lockbox path.")),
                )
                .subcommand(
                    Command::new("lock-all")
                        .about("Lock every unlocked lockbox session.")
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault sessions lock-all",
                            "Context:\n  Lock-all clears every cached lockbox unlock session while leaving the session agent available for future unlocks.",
                        )),
                )
                .subcommand(
                    Command::new("stop")
                        .about("Lock every unlocked session and stop the session agent.")
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault sessions stop",
                            "Context:\n  Stop clears cached unlock sessions and shuts down the session agent process. Later commands can start it again when needed.",
                        )),
                )
                .subcommand(
                    Command::new("auto-unlock")
                        .about("Store the vault password in the operating system secret store so Lockbox can unlock the local vault automatically after your OS login session is unlocked.")
                        .disable_help_subcommand(true)
                        .arg_required_else_help(false)
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault sessions auto-unlock status\n  lockbox vault sessions auto-unlock enable\n  lockbox vault sessions auto-unlock forget",
                            "Context:\n  Auto-unlock stores the vault password in the operating system secret store. After your OS login session unlocks that store, Lockbox can unlock the local vault without prompting for the vault password.",
                        ))
                        .subcommand(
                            Command::new("status")
                                .about("Show whether auto-unlock is supported and enabled.")
                                .after_help(verbose_help(
                                    verbose,
                                    "Examples:\n  lockbox vault sessions auto-unlock status\n  lockbox vault sessions auto-unlock status --format json",
                                    "Context:\n  Status reports whether the current platform supports auto-unlock, which backend is selected, and whether Lockbox is configured to use it.",
                                ))
                                .arg(output_format_arg()),
                        )
                        .subcommand(
                            Command::new("enable")
                                .about("Allow Lockbox to store the vault password for auto-unlock.")
                                .after_help(verbose_help(
                                    verbose,
                                    "Examples:\n  lockbox vault sessions auto-unlock enable",
                                    "Context:\n  Enable allows Lockbox to save the vault password in the operating system secret store so future commands can unlock the vault automatically after OS login.",
                                )),
                        )
                        .subcommand(
                            Command::new("disable")
                                .about("Stop using auto-unlock.")
                                .after_help(verbose_help(
                                    verbose,
                                    "Examples:\n  lockbox vault sessions auto-unlock disable",
                                    "Context:\n  Disable leaves any stored secret untouched but tells Lockbox not to use auto-unlock. Use forget when you want to delete the stored vault password.",
                                )),
                        )
                        .subcommand(
                            Command::new("forget")
                                .about("Delete the stored vault password used for auto-unlock.")
                                .after_help(verbose_help(
                                    verbose,
                                    "Examples:\n  lockbox vault sessions auto-unlock forget",
                                    "Context:\n  Forget removes the vault password from the operating system secret store. Future vault unlocks will prompt again unless auto-unlock is enabled and the password is stored again.",
                                )),
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
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault contact list\n  lockbox vault contact add alice ./alice.pub\n  lockbox vault contact remove alice",
                    "Context:\n  Contacts are saved public keys for other people or systems. A contact can be added to a lockbox access list, but cannot unlock a lockbox by itself; unlocking requires the matching private identity.",
                ))
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List saved contacts.")
                        .visible_alias("ls")
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault contact list\n  lockbox vault contact list --format json",
                            "Context:\n  Contact list shows public keys you have saved for other identities. Use these names with access add when granting lockbox access.",
                        ))
                        .arg(output_format_arg()),
                )
                .subcommand(
                    Command::new("add")
                        .about("Save a contact public key.")
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault contact add alice ./alice.pub\n  lockbox vault contact add --overwrite alice ./alice-new.pub",
                            "Context:\n  Contact add imports someone else's public key into your vault. Saving it as a contact gives you a stable name to use when sharing lockboxes.",
                        ))
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
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault contact remove alice\n  lockbox vault contact rm alice",
                            "Context:\n  Contact remove deletes the saved public key from your vault. It does not remove access already written into any lockbox; use access remove for that.",
                        ))
                        .arg(required("name", "Contact name.")),
                ),
        )
        .subcommand(
            Command::new("share")
                .about("Share vault identity contact details through a share server.")
                .disable_help_subcommand(true)
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault share publish\n  lockbox vault share receive 0123456789012 alice\n  lockbox vault share delete 0123456789012 <delete-token>",
                    "Context:\n  Vault share publishes or receives typed contact-share payloads through the configured binary share server protocol. Configure share.server or share.topology_url in the vault config YAML, or pass --server/--topology-url.",
                ))
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("publish")
                        .about("Publish one vault identity public key as a share.")
                        .arg(share_server_arg())
                        .arg(share_topology_arg())
                        .arg(optional("identity", "Vault identity name. Defaults to default."))
                        .arg(
                            Arg::new("ttl")
                                .long("ttl")
                                .value_name("SECONDS")
                                .help("Share lifetime in seconds."),
                        )
                        .arg(
                            Arg::new("max-fetches")
                                .long("max-fetches")
                                .value_name("N")
                                .help("Maximum successful receives."),
                        ),
                )
                .subcommand(
                    Command::new("receive")
                        .about("Receive a contact share and save it as a contact.")
                        .visible_alias("fetch")
                        .arg(share_server_arg())
                        .arg(share_topology_arg())
                        .arg(
                            Arg::new("overwrite")
                                .long("overwrite")
                                .action(ArgAction::SetTrue)
                                .help("Replace an existing contact."),
                        )
                        .arg(required("share-code", "Share code."))
                        .arg(required("contact-name", "Contact name to save.")),
                )
                .subcommand(
                    Command::new("delete")
                        .about("Delete a pending share with its delete token.")
                        .visible_alias("rm")
                        .arg(share_server_arg())
                        .arg(share_topology_arg())
                        .arg(required("share-code", "Share code."))
                        .arg(required("delete-token", "Delete token printed by publish.")),
                ),
        )
        .subcommand(
            Command::new("lockbox")
                .about("Manage lockboxes remembered by the vault.")
                .disable_help_subcommand(true)
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault lockbox list\n  lockbox vault lockbox forget ./old-project.lbox",
                    "Context:\n  The vault remembers lockboxes it has created, unlocked, or modified so bulk maintenance commands can find them later. Forget removes only the vault reference; it does not delete the lockbox file.",
                ))
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List lockboxes remembered by the vault.")
                        .visible_alias("ls")
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault lockbox list\n  lockbox vault lockbox list --format json",
                            "Context:\n  Lockbox list reports remembered lockbox paths and whether each file is present, missing, or inaccessible.",
                        ))
                        .arg(output_format_arg()),
                )
                .subcommand(
                    Command::new("forget")
                        .about("Forget one remembered lockbox path.")
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault lockbox forget ./old-project.lbox",
                            "Context:\n  Forget removes a stale known-lockbox record from the vault. It does not delete the lockbox file.",
                        ))
                        .arg(required("lockbox", "Lockbox path to forget.")),
                ),
        )
}

fn share_server_arg() -> Arg {
    Arg::new("server")
        .long("server")
        .value_name("URL")
        .help("Share server /v1/share URL or host.")
}

fn share_topology_arg() -> Arg {
    Arg::new("topology-url")
        .long("topology-url")
        .value_name("URL")
        .help("Share server /v1/topology URL.")
}

fn vault_identity_command(verbose: bool) -> Command {
    Command::new("identity")
        .about("Manage your lockbox unlock identities.")
        .disable_help_subcommand(true)
        .after_help(verbose_help(
            verbose,
            "Examples:\n  lockbox vault identity list\n  lockbox vault identity create laptop\n  lockbox vault identity export laptop ./laptop.pub",
            "Context:\n  An identity has a public key and a private key. Share the public key so someone else can grant you access to a lockbox; keep the private key secret because it unlocks lockboxes granted to that identity. To save someone else's public key, use `lockbox vault contact add`.",
        ))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("list")
                .about("List local identities.")
                .visible_alias("ls")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity list\n  lockbox vault identity list --format json",
                    "Context:\n  Identity list shows the private unlock identities stored in your vault. These are the identities Lockbox can use when unlocking lockboxes granted to you.",
                ))
                .arg(output_format_arg()),
        )
        .subcommand(
            Command::new("create")
                .about("Create one of your identities.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity create\n  lockbox vault identity create laptop\n  lockbox vault identity export laptop ./laptop.pub",
                    "Context:\n  Identity create generates a new identity in your vault. With no name, Lockbox creates the `default` identity. To share the identity, create it first and then run `lockbox vault identity export` to write its public key.",
                ))
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .hide(!verbose)
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing identity."),
                )
                .arg(optional("name", "Identity name."))
        )
        .subcommand(
            Command::new("history")
                .about("Show identity key generations.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity history\n  lockbox vault identity history laptop --format json",
                    "Context:\n  Identity history shows the active and retired key generations for one vault identity. Retired generations are retained so older lockboxes can still be opened until their access entries are refreshed.",
                ))
                .arg(output_format_arg())
                .arg(optional("name", "Identity name.")),
        )
        .subcommand(
            Command::new("import")
                .about("Import a private key into the local vault.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity import laptop ./laptop.private\n  lockbox vault identity import laptop ./laptop.private ./laptop.pub",
                    "Context:\n  Identity import restores or moves private unlock material into this vault. Use it when bringing an existing identity onto this installation or recovering from a backup.",
                ))
                .arg(required("name", "Identity name."))
                .arg(required("private-key", "Private key path."))
                .arg(optional("public-key-output", "Public key output path.")),
        )
        .subcommand(
            Command::new("export")
                .about("Export an identity public key.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity export ./default.pub\n  lockbox vault identity export laptop ./laptop.pub",
                    "Context:\n  Identity export writes the public key for one of your identities. Share this file with someone who needs to grant you access to a lockbox. The public key does not unlock lockboxes by itself.",
                ))
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
            Command::new("export-private")
                .about("Export an identity private key.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity export-private ./default.private\n  lockbox vault identity export-private laptop ./laptop.private",
                    "Context:\n  Identity export-private writes private unlock material to a file. Treat the output as highly sensitive; anyone with the private key can unlock lockboxes granted to that identity.",
                ))
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
            Command::new("remove")
                .about("Remove an identity.")
                .visible_alias("rm")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity remove laptop\n  lockbox vault identity remove --force laptop",
                    "Context:\n  Identity remove deletes an identity from your vault. Lockboxes that only grant access to that identity may become inaccessible from this vault.",
                ))
                .arg(
                    Arg::new("force")
                        .long("force")
                        .visible_alias("noask")
                        .action(ArgAction::SetTrue)
                        .help("Remove the key without an interactive confirmation."),
                )
                .arg(optional("name", "Identity name.")),
        )
        .subcommand(
            Command::new("rotate")
                .about("Rotate an identity to a new key generation.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity rotate\n  lockbox vault identity rotate laptop",
                    "Context:\n  Identity rotate creates a new active private key generation and retires the previous active generation. Refresh remembered lockboxes afterward so they grant access to the new key.",
                ))
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

fn verbose_help(verbose: bool, normal: &'static str, context: &'static str) -> String {
    if verbose {
        format!("{context}\n\n{normal}")
    } else {
        normal.to_string()
    }
}

fn apply_verbose_help_template(mut command: Command) -> Command {
    if let Some(after_help) = command.get_after_help().map(|help| help.to_string()) {
        if let Some((context, examples)) = after_help.split_once("\n\nExamples:") {
            if context.starts_with("Context:") {
                command = command
                    .before_help(context.to_string())
                    .after_help(format!("Examples:{examples}"));
            }
        }
    }
    command
        .help_template(VERBOSE_HELP_TEMPLATE)
        .mut_subcommands(apply_verbose_help_template)
}
