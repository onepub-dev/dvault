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
                .help("Developer override: open with a raw content key supplied out of band."),
        )
        .subcommands([
            archive_command("create", "Create a new encrypted lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault init\n  lockbox create secrets.lbox\n  lockbox create --password secrets.lbox\n  lockbox create --for alice secrets.lbox",
                    "Context:\n  Use create when starting a new encrypted archive. By default it creates a lockbox for the vault's default identity. Use --password when you need a password-protected lockbox.",
                ))
                .arg(
                    Arg::new("password")
                        .long("password")
                        .conflicts_with("for")
                        .action(ArgAction::SetTrue)
                        .help("Create a password-protected lockbox."),
                )
                .arg(
                    Arg::new("for")
                        .long("for")
                        .conflicts_with("password")
                        .value_name("IDENTITY_OR_CONTACT")
                        .help("Create the lockbox for one of your identities or a saved contact."),
                )
                .arg(required("lockbox", "Lockbox path.")),
            archive_command("open", "Open a lockbox for later commands.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox open secrets.lbox\n  lockbox open --duration 30m secrets.lbox\n  LOCKBOX_PASSWORD=secret lockbox open secrets.lbox\n  printf '%s\\n' \"$LOCKBOX_PASSWORD\" | lockbox open --password-stdin secrets.lbox",
                    "Context:\n  Open prompts for the lockbox password, stores temporary open access in the session agent, and lets later commands read or modify the lockbox without prompting again. Use --duration when the session should expire sooner than the default.",
                ))
                .arg(
                    Arg::new("duration")
                        .short('d')
                        .long("duration")
                        .value_name("DURATION")
                        .help("Keep the lockbox open for this session duration, such as 30s, 30m, 2h, or 1d."),
                )
                .arg(
                    Arg::new("password-env")
                        .long("password-env")
                        .value_name("NAME")
                        .conflicts_with_all(["password-file", "password-stdin"])
                        .help("Read the lockbox password from this variable."),
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
                .arg(optional("lockbox", "Lockbox path. Defaults to the active lockbox.")),
            archive_command("close", "Close the lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox close secrets.lbox\n  lockbox close --all",
                    "Context:\n  Close removes cached open access from the session agent. It does not change encrypted lockbox contents; it only makes later commands require open access again.",
                ))
                .arg(
                    Arg::new("all")
                        .long("all")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("lockbox")
                        .help("Close all lockboxes."),
                )
                .arg(
                    optional("lockbox", "Lockbox path. Defaults to the active lockbox.")
                        .conflicts_with("all"),
                ),
            archive_command("recover", "Recover readable entries from a damaged lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox recover damaged.lbox --output recovered.lbox\n  lockbox recover --report --format table damaged.lbox",
                    "Context:\n  Recover scans a damaged lockbox and writes a new lockbox containing readable entries. Use --report or --dry-run first when you want to inspect what can be recovered without writing an output file.",
                ))
                .arg(optional(
                    "lockbox",
                    "Damaged lockbox path. Defaults to the active lockbox.",
                ))
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
            file_command("add", "Add a file or directory to a lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox add ./notes.txt\n  lockbox add secrets.lbox ./notes.txt\n  lockbox add --recursive ./project /project\n  lockbox add -r secrets.lbox ./large-dir /archive",
                    "Context:\n  Add imports a host file into an open lockbox. With an active lockbox, omit the lockbox path and pass the source first. Pass --recursive when the source is a directory. If no destination path is supplied, files keep their filename at the lockbox root and recursive directory imports go under the root. Use --jobs in verbose mode to tune large imports.",
                ))
                .arg(
                    Arg::new("recursive")
                        .short('r')
                        .long("recursive")
                        .action(ArgAction::SetTrue)
                        .help("Recursively import a directory source."),
                )
                .arg(
                    Arg::new("jobs")
                        .long("jobs")
                        .value_name("auto|1|N")
                        .hide(!verbose)
                        .help("Set import worker count."),
                )
                .arg(required(
                    "lockbox-or-source",
                    "Lockbox path, or source file/directory when an active lockbox is set.",
                ))
                .arg(optional(
                    "source-or-lockbox-path",
                    "Source file/directory, or destination path when an active lockbox is set.",
                ))
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
                .arg(
                    Arg::new("to")
                        .long("to")
                        .value_name("DESTINATION")
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
                    Arg::new("args")
                        .value_name("LOCKBOX PATH DESTINATION | PATH DESTINATION")
                        .num_args(0..=3)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass path and destination. Otherwise pass lockbox, path, and destination."),
                ),
            file_command("cat", "Write a stored file to stdout.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox cat secrets.lbox /notes.txt\n  lockbox cat secrets.lbox /notes.txt > notes.txt",
                    "Context:\n  Cat streams one stored file to stdout. Use it for inspection, piping, or shell redirection when you do not want reVault to create a host file directly.",
                ))
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH | PATH")
                        .num_args(1..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the stored path."),
                ),
            file_command("list", "List stored entries.")
                .visible_alias("ls")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox list secrets.lbox\n  lockbox list secrets.lbox /project\n  lockbox list secrets.lbox '/project/**/*.txt'\n  lockbox list --recursive --format json secrets.lbox",
                    "Context:\n  List shows files and inferred directories stored in a lockbox. The default view mirrors a normal directory listing; pass a glob pattern to match stored paths, or use --recursive when scripts or audits need full stored paths.",
                ))
                .arg(output_format_arg())
                .arg(
                    Arg::new("recursive")
                        .short('R')
                        .long("recursive")
                        .action(ArgAction::SetTrue)
                        .help("List entries below child directories."),
                )
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH | PATH")
                        .num_args(0..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the optional stored path or glob."),
                ),
            file_command("rm", "Remove a stored entry.")
                .visible_alias("remove")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox rm secrets.lbox /notes.txt\n  lockbox rm --force secrets.lbox /old.txt",
                    "Context:\n  Remove deletes a stored file or directory entry from the lockbox and commits that change. Without --force, reVault asks for confirmation before changing the archive.",
                ))
                .arg(
                    Arg::new("force")
                        .long("force")
                        .visible_alias("noask")
                        .action(ArgAction::SetTrue)
                        .help("Remove without an interactive confirmation."),
                )
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH | PATH")
                        .num_args(1..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the stored path."),
                ),
            file_command("rename", "Rename a stored entry.")
                .visible_alias("mv")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox rename secrets.lbox /draft.txt /final.txt\n  lockbox mv secrets.lbox /old-dir /archive/old-dir",
                    "Context:\n  Rename changes the path stored inside the lockbox. It does not touch host filesystem paths; both arguments are lockbox paths.",
                ))
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX FROM TO | FROM TO")
                        .num_args(2..=3)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the stored source and destination paths."),
                ),
            variables_command(verbose),
            form_command(verbose),
            session_command(verbose),
            access_command(verbose),
            archive_command("doctor", "Show vault, agent, or lockbox diagnostics.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox doctor\n  lockbox doctor secrets.lbox",
                    "Context:\n  With no lockbox path, doctor reports local configuration and runtime state, including vault path, auto-open support, and whether the session agent is reachable. With a lockbox path, doctor inspects public lockbox metadata without opening and adds deeper checks when the lockbox is already open.",
                ))
                .arg(optional(
                    "lockbox",
                    "Lockbox path to inspect without prompting.",
                )),
            vault_command(verbose),
            developer_command("visualize", "Print internal lockbox structure.")
                .visible_alias("visualise")
                .arg(optional("lockbox", "Lockbox path. Defaults to the active lockbox.")),
            developer_command("keygen", "Generate raw keypair files.")
                .arg(required("private-key", "Private key output path."))
                .arg(required("public-key", "Public key output path.")),
            developer_command("open-key", "Open using a vault private key.")
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX VAULT_KEY | VAULT_KEY")
                        .num_args(0..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the optional vault private key name."),
                ),
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
  open            Open a lockbox for later commands.
  close           Close the lockbox.
  recover         Recover readable entries from a damaged lockbox.

Files
  add             Add a file or directory to a lockbox.
  extract         Extract files from a lockbox.
  cat             Write a stored file to stdout.
  list            List stored entries.
  rm              Remove a stored entry.
  rename          Rename a stored entry.

Data
  variables       Store, retrieve, list, export, or remove variable values.
  form            Manage typed multi-field form records.

Session
  session         Manage active and open lockbox sessions.

Sharing
  access          Manage who can open a lockbox.

Vault
  doctor          Show local vault and session agent diagnostics.
  vault           Manage identities and contacts."
    );

    if verbose {
        eprintln!(
            "
Advanced global options:
    --key <raw-content-key>    Developer override: open with a raw content key supplied out of band.

Advanced command options:
  lockbox add --jobs auto|1|N <lockbox> <source> <lockbox-path>

Developer and compatibility commands:
  keygen          Generate raw keypair files.
  open-key        Open using a vault private key.
  visualize       Print internal lockbox structure.

Process variables:
  LOCKBOX_KEY=<raw-content-key> lockbox <command> ...
    LOCKBOX_PASSWORD=<password> lockbox open <lockbox>
  LOCKBOX_OPEN_DURATION=30m lockbox open <lockbox>
  LOCKBOX_VAULT_PASSWORD=<password> lockbox vault <command>
  LOCKBOX_PLATFORM_SECRET_STORE=auto|disabled lockbox vault <command>
  LOCKBOX_SESSION_AGENT_DIR=<dir> lockbox <command> ...
  LOCKBOX_VAULT_DIR=<dir> lockbox <command> ...

Raw content keys are for developer recovery and local testing. reVault does not
print or export them; normal commands should open through the vault session."
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

fn variables_command(verbose: bool) -> Command {
    base_command(
        "variables",
        "Store, retrieve, list, export, or remove variable values.",
    )
    .visible_alias("var")
    .after_help(verbose_help(
        verbose,
        "Examples:\n  lockbox variables set secrets.lbox APP_MODE production\n  lockbox variables get secrets.lbox APP_MODE\n  lockbox variables export secrets.lbox",
        "Context:\n  Variables are named data stored inside a lockbox. Normal values are printed by `variables get` and included by `variables export`. Secret values are encrypted the same way, but are redacted from `variables export` and require `variables get --secret` to print.",
    ))
    .subcommand_required(true)
    .arg_required_else_help(true)
    .subcommand(
        Command::new("set")
            .about("Store a variable value.")
            .after_help(verbose_help(
                verbose,
                "Examples:\n  lockbox variables set secrets.lbox APP_MODE production\n  lockbox variables set --secret secrets.lbox API_TOKEN --interactive\n  printf '%s' \"$TOKEN\" | lockbox variables set --secret --stdin secrets.lbox API_TOKEN",
                "Context:\n  Variables set writes one named value into a lockbox. Use --secret for values that should not be exported in bulk, such as tokens and passwords. Choose one value source: argument, prompt, stdin, file, or process environment. Secret values cannot use --value; use --stdin, --file, --interactive, or --from-env.",
            ))
            .arg(
                Arg::new("secret")
                    .short('s')
                    .long("secret")
                    .action(ArgAction::SetTrue)
                    .help("Store the value as secret."),
            )
            .arg(
                Arg::new("args")
                    .value_name("LOCKBOX NAME VALUE | NAME VALUE")
                    .num_args(1..=3)
                    .action(ArgAction::Append)
                    .help("With an active lockbox, pass name and optional value. Otherwise pass lockbox, name, and optional value."),
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
                    .help("Read a normal value from this argument; not accepted with --secret."),
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
                    .help("Read the value from a process variable."),
            ),
    )
    .subcommand(
        Command::new("get")
            .about("Print one stored variable value by name.")
            .after_help(verbose_help(
                verbose,
                "Examples:\n  lockbox variables get secrets.lbox APP_MODE\n  lockbox variables get --secret secrets.lbox API_TOKEN\n  lockbox variables get --secret --output api-token.txt secrets.lbox API_TOKEN",
                "Context:\n  Variables get reads one named value from a lockbox. Secret values require --secret so accidental terminal output is an explicit user choice. Use --output when the exact bytes should go to a file.",
            ))
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
            .arg(
                Arg::new("args")
                    .value_name("LOCKBOX NAME | NAME")
                    .num_args(1..=2)
                    .action(ArgAction::Append)
                    .help("With an active lockbox, pass only the variable name."),
            ),
    )
    .subcommand(
        Command::new("list")
            .about("List variable values.")
            .visible_alias("ls")
            .after_help(verbose_help(
                verbose,
                "Examples:\n  lockbox variables list secrets.lbox\n  lockbox variables list secrets.lbox /production\n  lockbox variables list secrets.lbox '**/API_KEY'\n  lockbox variables list --format json secrets.lbox",
                "Context:\n  Variables list shows value names and whether each value is normal or secret. It does not print stored values. Pass a path such as /production to list that group, or a glob such as **/API_KEY to match names across groups.",
            ))
            .arg(output_format_arg())
            .arg(
                Arg::new("args")
                    .value_name("LOCKBOX PATTERN | PATTERN")
                    .num_args(0..=2)
                    .action(ArgAction::Append)
                    .help("With an active lockbox, pass only the optional pattern."),
            ),
    )
    .subcommand(
        Command::new("export")
            .about("Print all non-secret variable values in an importable format.")
            .after_help(verbose_help(
                verbose,
                "Examples:\n  eval \"$(lockbox variables export secrets.lbox)\"\n  lockbox variables export secrets.lbox /production\n  lockbox variables export --format posix secrets.lbox > variables.sh\n  lockbox variables export --format powershell secrets.lbox | Invoke-Expression\n\nFormats:\n  posix       NAME='value' lines for sh, bash, and zsh. Default.\n  powershell  $env:NAME = 'value' lines for PowerShell.\n  cmd         set \"NAME=value\" lines for cmd.exe.\n  json        One JSON object per line with name and value fields.\n\n`variables export` writes to stdout. Use shell redirection to write it to a file.",
                "Context:\n  Variables export is intended for shell startup, CI setup, or scripting. It only includes non-secret values; use explicit `variables get --secret` for secret values so they are never exported in bulk by accident. When exporting a path such as /production, only direct child names are emitted, so /production/API_KEY becomes API_KEY and nested values are skipped.",
            ))
            .arg(
                Arg::new("format")
                    .long("format")
                    .value_name("posix|powershell|cmd|json")
                    .default_value("posix")
                    .help("Output format."),
            )
            .arg(
                Arg::new("args")
                    .value_name("LOCKBOX PATH | PATH")
                    .num_args(0..=2)
                    .action(ArgAction::Append)
                    .help("With an active lockbox, pass only the optional variable path."),
            ),
    )
    .subcommand(
        Command::new("rm")
            .about("Remove a variable value.")
            .visible_alias("remove")
            .after_help(verbose_help(
                verbose,
                "Examples:\n  lockbox variables rm secrets.lbox APP_MODE\n  lockbox variables remove secrets.lbox API_TOKEN",
                "Context:\n  Variables rm removes one named value from a lockbox. It affects only the lockbox record, not the current process environment.",
            ))
            .arg(
                Arg::new("args")
                    .value_name("LOCKBOX NAME | NAME")
                    .num_args(1..=2)
                    .action(ArgAction::Append)
                    .help("With an active lockbox, pass only the variable name."),
            ),
    )
}

fn form_command(verbose: bool) -> Command {
    base_command("form", "Manage typed multi-field form records.")
        .after_help(verbose_help(
            verbose,
            "Examples:\n  lockbox form define secrets.lbox login --field username:text --field password:secret\n  lockbox form add secrets.lbox /work/github --type login --name GitHub --set username=bsutton\n  lockbox form add secrets.lbox /work/github --type login --interactive\n  lockbox form show secrets.lbox /work/github",
            "Context:\n  Forms store structured records inside a lockbox. Definitions are versioned by a stable definition id and embedded in the lockbox, so shared lockboxes remain self-describing even when another party uses the same form alias for a different definition.",
        ))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("define")
                .about("Create or revise a form definition.")
                .override_usage(
                    "lockbox form define <lockbox> [alias] --field <NAME[:KIND[:required[:LABEL]]]>...\n\nExample:\n  lockbox form define secrets.lbox login --field username:text --field password:secret",
                )
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox form define secrets.lbox login --field username:text --field password:secret\n  lockbox form define secrets.lbox login --name Login --field username:text:required:User --field password:secret:required:Password\n\nField form:\n  NAME[:KIND[:required[:LABEL]]]\n\nKinds:\n  text, secret, password, url, email, date, month, notes, number",
                    "Context:\n  Define creates a new form definition for a new alias. If the alias already resolves to exactly one definition, define appends a new revision. If an imported shared lockbox has conflicting aliases, pass --definition-id to revise the intended definition explicitly.",
                ))
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX ALIAS | ALIAS")
                        .num_args(0..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the optional form alias."),
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_name("DISPLAY_NAME")
                        .help("Human display name for this form definition."),
                )
                .arg(
                    Arg::new("definition-id")
                        .long("definition-id")
                        .alias("type-id")
                        .value_name("DEFINITION_ID")
                        .help("Revise or create this stable form definition id."),
                )
                .arg(
                    Arg::new("field")
                        .long("field")
                        .value_name("NAME[:KIND[:required[:LABEL]]]")
                        .action(ArgAction::Append)
                        .required(true)
                        .help("Add one field to the definition."),
                ),
        )
        .subcommand(
            Command::new("definitions")
                .about("List form definitions.")
                .visible_alias("types")
                .arg(output_format_arg())
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX")
                        .num_args(0..=1)
                        .action(ArgAction::Append)
                        .help("Lockbox path. Defaults to the active lockbox."),
                ),
        )
        .subcommand(
            Command::new("add")
                .about("Add a form record.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox form add secrets.lbox /work/github --type login --name GitHub\n  lockbox form add secrets.lbox /work/github --type login --set username=bsutton --set site=https://github.com\n  lockbox form add secrets.lbox /work/github --type login --interactive",
                    "Context:\n  Add creates one form record in the lockbox. Use --set for non-secret values known up front. Use --interactive to prompt for remaining fields, including secret fields without echoing them.",
                ))
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH | PATH")
                        .num_args(1..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the form record path."),
                )
                .arg(
                    Arg::new("type")
                        .long("type")
                        .value_name("ALIAS_OR_DEFINITION_ID")
                        .required(true)
                        .help("Form definition alias or stable definition id."),
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_name("RECORD_NAME")
                        .help("Display name for this record. Defaults to the last path component."),
                )
                .arg(
                    Arg::new("set")
                        .long("set")
                        .value_name("FIELD=VALUE")
                        .action(ArgAction::Append)
                        .help("Set one non-secret field while adding the form record."),
                )
                .arg(
                    Arg::new("interactive")
                        .long("interactive")
                        .short('i')
                        .action(ArgAction::SetTrue)
                        .help("Prompt for fields that were not supplied with --set."),
                ),
        )
        .subcommand(
            Command::new("edit")
                .about("Edit a form record.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox form edit secrets.lbox /work/github --set username=bsutton\n  lockbox form edit secrets.lbox /work/github --interactive",
                    "Context:\n  Edit updates an existing form record. Use --interactive after a form definition revision to fill fields that exist in the latest definition but are missing from the stored record.",
                ))
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH | PATH")
                        .num_args(1..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the form record path."),
                )
                .arg(
                    Arg::new("set")
                        .long("set")
                        .value_name("FIELD=VALUE")
                        .action(ArgAction::Append)
                        .help("Set one non-secret field while editing the form record."),
                )
                .arg(
                    Arg::new("interactive")
                        .long("interactive")
                        .short('i')
                        .action(ArgAction::SetTrue)
                        .help("Prompt for fields missing from the current record."),
                ),
        )
        .subcommand(
            Command::new("set")
                .about("Set one form field value.")
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH FIELD VALUE | PATH FIELD VALUE")
                        .num_args(2..=4)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass form record path, field id, and optional value."),
                )
                .arg(
                    Arg::new("secret")
                        .long("secret")
                        .action(ArgAction::SetTrue)
                        .help("Set a secret field value."),
                )
                .arg(
                    Arg::new("explicit-value")
                        .long("value")
                        .short('v')
                        .value_name("VALUE")
                        .conflicts_with_all(["stdin", "file", "from-env", "interactive"])
                        .help("Set a literal non-secret field value."),
                )
                .arg(
                    Arg::new("stdin")
                        .long("stdin")
                        .short('t')
                        .action(ArgAction::SetTrue)
                        .conflicts_with_all(["explicit-value", "file", "from-env", "interactive"])
                        .help("Read the field value from stdin."),
                )
                .arg(
                    Arg::new("file")
                        .long("file")
                        .short('f')
                        .value_name("FILE")
                        .conflicts_with_all(["explicit-value", "stdin", "from-env", "interactive"])
                        .help("Read the field value from a file."),
                )
                .arg(
                    Arg::new("from-env")
                        .long("from-env")
                        .short('e')
                        .value_name("NAME")
                        .conflicts_with_all(["explicit-value", "stdin", "file", "interactive"])
                        .help("Read the field value from an variable."),
                )
                .arg(
                    Arg::new("interactive")
                        .long("interactive")
                        .short('i')
                        .action(ArgAction::SetTrue)
                        .conflicts_with_all(["explicit-value", "stdin", "file", "from-env"])
                        .help("Prompt for the field value."),
                ),
        )
        .subcommand(
            Command::new("get")
                .about("Print one form field value.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox form get secrets.lbox /work/github username\n  lockbox form get --secret secrets.lbox /work/github password\n  lockbox form get --secret --output password.txt secrets.lbox /work/github password",
                    "Context:\n  Form get reads one field from a form record. Secret fields require --secret so accidental terminal output is an explicit user choice. Use --output when the exact bytes should go to a file.",
                ))
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH FIELD | PATH FIELD")
                        .num_args(2..=3)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the form record path and field id."),
                )
                .arg(
                    Arg::new("secret")
                        .long("secret")
                        .action(ArgAction::SetTrue)
                        .help("Print a secret field value."),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .value_name("FILE")
                        .help("Write the field value to this file."),
                )
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .requires("output")
                        .action(ArgAction::SetTrue)
                        .help("Replace the output file if it already exists."),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Show one form record.")
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH | PATH")
                        .num_args(1..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the form record path."),
                ),
        )
        .subcommand(
            Command::new("list")
                .about("List form records.")
                .arg(output_format_arg())
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATTERN | PATTERN")
                        .num_args(0..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the optional pattern."),
                ),
        )
        .subcommand(
            Command::new("rm")
                .about("Remove one form record.")
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX PATH | PATH")
                        .num_args(1..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the form record path."),
                ),
        )
}

fn session_command(verbose: bool) -> Command {
    base_command("session", "Manage active and open lockbox sessions.")
        .disable_help_subcommand(true)
        .arg_required_else_help(false)
        .after_help(verbose_help(
            verbose,
            "Examples:\n  lockbox session\n  lockbox session activate secrets.lbox\n  lockbox session auto-open lockboxes",
            "Context:\n  Session shows the active lockbox and lockboxes currently open in the session agent. The active lockbox is used by commands that can safely omit a lockbox path.",
        ))
        .arg(output_format_arg())
        .subcommand(
            Command::new("activate")
                .about("Set the active lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox session activate secrets.lbox",
                    "Context:\n  Activate sets the active lockbox used by commands that can safely omit a lockbox path.",
                ))
                .arg(required("lockbox", "Lockbox path.")),
        )
        .subcommand(
            Command::new("deactivate")
                .about("Clear the active lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox session deactivate",
                    "Context:\n  Deactivate only clears the active lockbox pointer. It does not close any open lockbox sessions.",
                )),
        )
        .subcommand(
            Command::new("close-all")
                .about("Close all lockboxes.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox session close-all",
                    "Context:\n  Close-all clears every cached lockbox content key from the session agent and clears the active lockbox.",
                )),
        )
        .subcommand(
            Command::new("stop")
                .about("Close all sessions and stop the session agent.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox session stop",
                    "Context:\n  Stop clears cached open sessions, clears the active lockbox, and shuts down the session agent process. Later commands can start it again when needed.",
                )),
        )
        .subcommand(
            Command::new("auto-open")
                .about("Allow reVault to use your OS login to automatically open the vault and lockboxes as required.")
                .disable_help_subcommand(true)
                .arg_required_else_help(false)
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox session auto-open status\n  lockbox session auto-open off\n  lockbox session auto-open vault\n  lockbox session auto-open lockboxes",
                    "Context:\n  Auto-open controls whether reVault may use your OS login to automatically open only the vault, or both the vault and lockboxes as required.",
                ))
                .subcommand(
                    Command::new("status")
                        .about("Show the current auto-open scope.")
                        .arg(output_format_arg()),
                )
                .subcommand(Command::new("off").about(
                    "Disable auto-open and close all open lockbox sessions.",
                ))
                .subcommand(Command::new("vault").about(
                    "Allow reVault to automatically open the vault only.",
                ))
                .subcommand(Command::new("lockboxes").about(
                    "Allow reVault to automatically open the vault and lockboxes.",
                )),
        )
}

fn access_command(verbose: bool) -> Command {
    sharing_command("access", "Manage who can open a lockbox.")
        .after_help(verbose_help(
            verbose,
            "Examples:\n  lockbox access list secrets.lbox\n  lockbox access add secrets.lbox alice\n  lockbox access remove secrets.lbox 2",
            "Context:\n  Access entries are stored on a lockbox and describe which identities or contacts may open it. Use this command when sharing a lockbox or rotating/removing access.",
        ))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Allow an identity or contact to open a lockbox.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox access add secrets.lbox alice\n  lockbox access add secrets.lbox identity:alice\n  lockbox access add secrets.lbox contact:alice\n  lockbox access add secrets.lbox alice ./alice.pub",
                    "Context:\n  Access add grants open access by adding an identity or contact to the lockbox. A bare name can refer to one of your saved identities or saved contacts. If both use the same name, use identity:name or contact:name. For a public key file, provide the contact name first so the lockbox can record who the access entry belongs to.",
                ))
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX IDENTITY PUBLIC_KEY | IDENTITY PUBLIC_KEY")
                        .num_args(1..=3)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass identity/contact and optional public key. Identity name, contact name, identity:name, contact:name, or contact name plus a public key file. Public key path."),
                ),
        )
        .subcommand(
            Command::new("list")
                .about("List who can open a lockbox.")
                .visible_alias("ls")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox access list secrets.lbox\n  lockbox access list --format json secrets.lbox",
                    "Context:\n  Access list shows the access slots currently attached to a lockbox. Use slot ids from this output when removing access.",
                ))
                .arg(output_format_arg())
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX")
                        .num_args(0..=1)
                        .action(ArgAction::Append)
                        .help("Lockbox path. Defaults to the active lockbox."),
                ),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove access from a lockbox.")
                .visible_alias("rm")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox access remove secrets.lbox 2\n  lockbox access rm secrets.lbox 2",
                    "Context:\n  Access remove deletes one open slot from the lockbox. reVault prevents removing the last usable access entry because that could make the lockbox inaccessible.",
                ))
                .arg(
                    Arg::new("args")
                        .value_name("LOCKBOX SLOT_ID | SLOT_ID")
                        .num_args(1..=2)
                        .action(ArgAction::Append)
                        .help("With an active lockbox, pass only the access slot id."),
                ),
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
                        .action(ArgAction::Append)
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
                .about("Create or open the local vault.")
                .after_help(verbose_help(
                    verbose,
                    "If the vault already exists, init reports the path and makes no changes. Use --verify to validate the pass phrase, or --overwrite only when replacing the vault and losing records stored only there.",
                    "Context:\n  The local vault stores identities, contacts, and key-directory backups. New vault pass phrases must be at least 15 characters. A new vault also gets a default identity. Store the vault pass phrase safely; reVault cannot recover the vault without it.",
                ))
                .arg(
                    Arg::new("verify")
                        .long("verify")
                        .conflicts_with("overwrite")
                        .action(ArgAction::SetTrue)
                        .help("Ask for the vault pass phrase and verify the existing vault opens."),
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
            Command::new("backup")
                .about("Create an encrypted backup archive of the local vault.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault backup ./vault-backup.lockbox-backup\n  lockbox vault backup --overwrite ./vault-backup.lockbox-backup",
                    "Context:\n  Backup takes a locked snapshot of the encrypted local-vault.lbox file and stores it with a manifest and checksum. It does not decrypt or export vault records.",
                ))
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing backup file."),
                )
                .arg(required("output", "Backup archive output path.")),
        )
        .subcommand(
            Command::new("restore")
                .about("Restore the local vault from an encrypted backup archive.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault restore ./vault-backup.lockbox-backup\n  lockbox vault restore --overwrite ./vault-backup.lockbox-backup",
                    "Context:\n  Restore verifies the backup checksum before replacing the local vault. Existing vaults are not overwritten unless --overwrite is passed.",
                ))
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .action(ArgAction::SetTrue)
                        .help("Replace the existing local vault."),
                )
                .arg(required("backup", "Backup archive input path.")),
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
                    "Context:\n  Contacts are saved public keys for other people or systems. A contact can be added to a lockbox access list, but cannot open a lockbox by itself; opening requires the matching private identity.",
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
                .about("Share vault identity contact details through a key server.")
                .disable_help_subcommand(true)
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault publish\n  lockbox vault share receive <share-code>\n  lockbox vault share remove <share-code> <delete-token>",
                    "Context:\n  Vault share publishes or receives typed contact-share payloads through the configured binary key server protocol. The publisher verifies their identity email with the key server, and the receiver verifies the printed fingerprint over a second channel they initiate.",
                ))
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("publish")
                        .about("Publish one vault identity public key as a share.")
                        .arg(key_server_arg())
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
                        .visible_alias("recieve")
                        .after_help(verbose_help(
                            verbose,
                            "Examples:\n  lockbox vault receive <share-code>\n  lockbox vault share receive <share-code> alice",
                            concat!(
                                "Context:\n  Receive saves the shared public key and signing key as a local contact. ",
                                "The key server must have verified the publisher email first. Enter the ",
                                "contact fingerprint received through a second trusted channel, such as a phone ",
                                "call you initiated.",
                            ),
                        ))
                        .arg(key_server_arg())
                        .arg(share_topology_arg())
                        .arg(
                            Arg::new("fingerprint")
                                .long("fingerprint")
                                .value_name("HEX")
                                .help("Contact fingerprint from a trusted second channel. Prompts when omitted."),
                        )
                        .arg(
                            Arg::new("overwrite")
                                .long("overwrite")
                                .action(ArgAction::SetTrue)
                                .help("Replace an existing contact."),
                        )
                        .arg(required("share-code", "Published share code."))
                        .arg(optional("contact-name", "Contact name to save.")),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove a pending share with its delete token.")
                        .alias("delete")
                        .visible_alias("rm")
                        .arg(key_server_arg())
                        .arg(share_topology_arg())
                        .arg(required("share-code", "Published share code."))
                        .arg(required("delete-token", "Delete token printed by publish.")),
                ),
        )
        .subcommand(
            Command::new("publish")
                .about("Publish one vault identity public key by verified email.")
                .arg(key_server_arg())
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
                .about("Receive a verified public key by share code.")
                .visible_alias("recieve")
                .visible_alias("fetch")
                .arg(key_server_arg())
                .arg(share_topology_arg())
                .arg(
                    Arg::new("fingerprint")
                        .long("fingerprint")
                        .value_name("HEX")
                        .help("Contact fingerprint from a trusted second channel. Prompts when omitted."),
                )
                .arg(
                    Arg::new("overwrite")
                        .long("overwrite")
                        .action(ArgAction::SetTrue)
                        .help("Replace an existing contact."),
                )
                .arg(required("share-code", "Published share code."))
                .arg(optional("contact-name", "Contact name to save.")),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a pending published key with its delete token.")
                .alias("delete")
                .arg(key_server_arg())
                .arg(share_topology_arg())
                .arg(required("share-code", "Published share code."))
                .arg(required("delete-token", "Delete token printed by publish.")),
        )
        .subcommand(
            Command::new("lockbox")
                .about("Manage lockboxes remembered by the vault.")
                .disable_help_subcommand(true)
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault lockbox list\n  lockbox vault lockbox forget ./old-project.lbox",
                    "Context:\n  The vault remembers lockboxes it has created, opened, or modified so bulk maintenance commands can find them later. Forget removes only the vault reference; it does not delete the lockbox file.",
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
                            "Context:\n  The lockbox list command reports remembered lockbox paths and whether each file is present, missing, or inaccessible.",
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

fn key_server_arg() -> Arg {
    Arg::new("server")
        .long("server")
        .value_name("URL")
        .help("Key server /v1/share URL or host.")
}

fn share_topology_arg() -> Arg {
    Arg::new("topology-url")
        .long("topology-url")
        .value_name("URL")
        .help("Key server /v1/topology URL.")
}

fn vault_identity_command(verbose: bool) -> Command {
    Command::new("identity")
        .about("Manage your lockbox open identities.")
        .disable_help_subcommand(true)
        .after_help(verbose_help(
            verbose,
            "Examples:\n  lockbox vault identity list\n  lockbox vault identity create laptop\n  lockbox vault identity export laptop ./laptop.pub",
            "Context:\n  An identity has a public key and a private key. Share the public key so someone else can grant you access to a lockbox; keep the private key secret because it opens lockboxes granted to that identity. To save someone else's public key, use `lockbox vault contact add`.",
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
                    "Context:\n  Identity list shows the private open identities stored in your vault. These are the identities reVault can use when opening lockboxes granted to you.",
                ))
                .arg(output_format_arg()),
        )
        .subcommand(
            Command::new("create")
                .about("Create one of your identities.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity create\n  lockbox vault identity create laptop\n  lockbox vault identity export laptop ./laptop.pub",
                    "Context:\n  Identity create generates a new identity in your vault. With no name, reVault creates the `default` identity. To share the identity, create it first and then run `lockbox vault identity export` to write its public key.",
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
            Command::new("email")
                .about("Set the email address associated with an identity.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity email alice@example.com\n  lockbox vault identity email laptop alice@example.com",
                    "Context:\n  Publish requires an identity email address. The key server sends a verification link to this address before receivers can fetch the public key by email.",
                ))
                .arg(
                    Arg::new("args")
                        .value_names(["identity", "email"])
                        .num_args(1..=2)
                        .required(true)
                        .help("Optional identity name followed by the identity email address."),
                ),
        )
        .subcommand(
            Command::new("import")
                .about("Import a private key into the local vault.")
                .after_help(verbose_help(
                    verbose,
                    "Examples:\n  lockbox vault identity import laptop ./laptop.private\n  lockbox vault identity import laptop ./laptop.private ./laptop.pub",
                    "Context:\n  Identity import restores or moves private open material into this vault. Use it when bringing an existing identity onto this installation or recovering from a backup.",
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
                    "Context:\n  Identity export writes the public key for one of your identities. Share this file with someone who needs to grant you access to a lockbox. The public key does not open lockboxes by itself.",
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
                    "Context:\n  Identity export-private writes private open material to a file. Treat the output as highly sensitive; anyone with the private key can open lockboxes granted to that identity.",
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
