pub(crate) fn usage(verbose: bool) {
    eprintln!(
        "usage:
  lockbox create <lockbox>
  lockbox open <lockbox>
  lockbox add <lockbox> <source> <lockbox-path>
  lockbox extract <lockbox> <lockbox-path> <destination>
  lockbox extract <lockbox> --to <destination> [--overwrite] [--restore-symlinks] [--restore-permissions]
  lockbox cat <lockbox> <lockbox-path>
  lockbox list <lockbox> [path]
  lockbox rm <lockbox> <lockbox-path>
  lockbox rename <lockbox> <from> <to>
  lockbox env set|get|list|export|rm ...
  lockbox recover <lockbox>
  lockbox lock <lockbox>
  lockbox lock --all
  lockbox keygen <private-key> <public-key>
  lockbox open-key <lockbox> <private-key>
  lockbox add-recipient <lockbox> <public-key>
  lockbox list-keys <lockbox>
  lockbox remove-key <lockbox> <slot-id>
  lockbox vault init
  lockbox vault keygen [name] [public-key-output]
  lockbox vault trust <name> <public-key>
  lockbox vault list"
    );

    if verbose {
        eprintln!(
            "
developer/testing:
  lockbox visualize <lockbox>
  lockbox vault path
  lockbox vault export-public [name] <public-key-output>
  lockbox --key <raw-content-key> <command> ...
  LOCKBOX_KEY=<raw-content-key> lockbox <command> ...
  LOCKBOX_PASSWORD=<password> lockbox open <lockbox>
  LOCKBOX_AGENT_DIR=<dir> lockbox <command> ...
  LOCKBOX_VAULT_DIR=<dir> lockbox <command> ...

help:
  lockbox --help --verbose"
        );
    } else {
        eprintln!(
            "
Use --help --verbose to show developer and less common options."
        );
    }
}
