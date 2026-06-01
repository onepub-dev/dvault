pub(crate) fn usage(verbose: bool) {
    eprintln!(
        "usage:
  lockbox create <lockbox>
  lockbox create --recipient <vault-key-or-recipient> <lockbox>
  lockbox open <lockbox>
  lockbox [--jobs auto|1|N] add <lockbox> <source> <lockbox-path>
  lockbox extract <lockbox> <lockbox-path> <destination>
  lockbox extract <lockbox> --to <destination> [--overwrite] [--restore-symlinks] [--restore-permissions]
  lockbox cat <lockbox> <lockbox-path>
  lockbox list <lockbox> [path]
  lockbox rm <lockbox> <lockbox-path>
  lockbox rename <lockbox> <from> <to>
  lockbox env set [-s] <lockbox> <name> <value|-i|-v value|-f file|-t|-e env>
  lockbox env get [-s] <lockbox> <name>
  lockbox env list|export|rm ...
  lockbox recover <lockbox>
  lockbox doctor
  lockbox lock <lockbox>
  lockbox lock --all
  lockbox open-key <lockbox> [vault-key]
  lockbox add-recipient <lockbox> <public-key-or-trusted-name>
  lockbox list-keys <lockbox>
  lockbox remove-key <lockbox> <slot-id>
  lockbox vault init
  lockbox vault keygen [name] [public-key-output]
  lockbox vault import-key <name> <private-key> [public-key-output]
  lockbox vault export-key [name] <private-key-output>
  lockbox vault trust <name> <public-key>
  lockbox vault list
  lockbox vault platform-store status|enable|disable|forget
  lockbox vault remove-key [name]
  lockbox vault remove-trusted <name>"
    );

    if verbose {
        eprintln!(
            "
developer/testing:
  lockbox visualize <lockbox>
  lockbox keygen <private-key> <public-key>
  lockbox vault path
  lockbox vault export-public [name] <public-key-output>
  lockbox vault keygen --overwrite [name] [public-key-output]
  lockbox vault trust --overwrite <name> <public-key>
  lockbox vault export-public --format <lockbox-pem|jwk|jwks|raw-hex> [name] <public-key-output>
  lockbox vault export-key --format <lockbox-pem|jwk|jwks|raw-hex> [name] <private-key-output>
  lockbox --jobs auto|1|N add <lockbox> <source> <lockbox-path>
  lockbox --key <raw-content-key> <command> ...
  LOCKBOX_KEY=<raw-content-key> lockbox <command> ...
  LOCKBOX_PASSWORD=<password> lockbox open <lockbox>
  LOCKBOX_VAULT_PASSWORD=<password> lockbox vault <command>
  LOCKBOX_PLATFORM_SECRET_STORE=auto|disabled lockbox vault <command>
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
