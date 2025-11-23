# Lockbox - Secure File Encryption

Lockbox (formerly DVault) is designed to make protecting (encrypting) files and directories simple and secure using Public Key Infrastructure (PKI).

When you lock a file or directory with Lockbox, it creates a single self-contained `.lbox` file that can be:
- **Unlocked by you** using your private key
- **Shared with team members** by adding them as recipients
- **Accessed in CI/CD** using machine keys
- **Decrypted in a web browser** for on-demand access

Lockbox works as both an interactive command line tool and can be called by other scripts. It supports Linux, macOS, and Windows.

## Quick Start

### Installation
```bash
dart pub global activate dvault
```

### Initialize Lockbox
After installing, run the one-time initialization to create your PKI key pair:

```bash
lockbox init
  Enter passphrase: ******
  Confirm passphrase: *****
  Generating RSA key pair...
  Keys saved to ~/.dvault

  ⚠️  IMPORTANT: Backup ~/.dvault - it's critical for accessing your lockboxes!
```

This creates an RSA public/private key pair in `~/.dvault`. The private key is encrypted with your passphrase.

### Lock a File
```bash
lockbox lock important.txt
  Stored and locked in important.txt.lbox
```

The original file is (optionally) deleted and replaced with `important.txt.lbox`.

### Unlock a File
```bash
lockbox unlock important.txt.lbox
  Passphrase: ******
  Unlocked to important.txt
```

## Advanced Features

### Team Sharing
Add team members as recipients to a lockbox so they can decrypt it with their own keys:

```bash
lockbox recipient add important.txt.lbox user@example.com
  Fetching public key for user@example.com from OnePub...
  Added user@example.com as recipient
```

Team members can then unlock the lockbox using their own `~/.dvault` key.

### CI/CD Integration
Generate a machine key for CI/CD environments:

```bash
lockbox ci generate
  Machine key generated: ci-key-2024-01-15.pem
  
  Add this key to your lockbox:
  lockbox recipient add secrets.lbox --key ci-key-2024-01-15.pem
  
  In your CI environment, set:
  export DVAULT_KEY=$(cat ci-key-2024-01-15.pem)
```

Your CI pipeline can then decrypt lockboxes without a passphrase:

```bash
lockbox unlock secrets.lbox  # Uses DVAULT_KEY environment variable
```

### Password-Based Sharing (Legacy)
For one-time sharing with someone who doesn't have Lockbox set up:

```bash
lockbox share important.txt
  ⚠️  DO NOT USE YOUR NORMAL LOCKBOX PASSPHRASE ⚠️
  Enter one-time passphrase: *****
  Confirm passphrase: *****
  Stored and locked in important.txt.lbox
  
  Share the passphrase securely (phone call, Signal, etc.)
  ⚠️  DO NOT EMAIL OR TWEET THE PASSPHRASE! ⚠️
```

Send `important.txt.lbox` to your recipient along with instructions to:
1. Install Lockbox: `dart pub global activate dvault`
2. Unlock with the shared passphrase: `lockbox unlock important.txt.lbox`

## Technical Architecture

### PKI-Based Encryption

Lockbox uses a hybrid encryption approach:

1. **User Keys**: Each user has an RSA-2048 public/private key pair stored in `~/.dvault`
   - Private key is encrypted with the user's passphrase (Argon2id)
   - Public key can be shared via OnePub for team collaboration

2. **Session Keys**: Each lockbox has a unique AES-256 session key
   - Generated randomly when the lockbox is created
   - Encrypted separately for each recipient using their public key
   - Stored in the lockbox header

3. **File Encryption**: Files are encrypted using AES-256-GCM
   - Each page (64KB block) uses a unique random nonce
   - Allows partial file access without decrypting the entire lockbox

### Lockbox File Format

A `.lbox` file contains:

```
[Header]
  - Magic bytes: "DVAULT"
  - Version: 1
  - Page size: 64KB (configurable)
  - Recipients: List of authorized users/keys
    - Type: PKI (RSA) or Password
    - Key ID: Public key hash or password salt
    - Encrypted Session Key

[Environment Page]
  - Encrypted key-value pairs
  - Metadata about the lockbox

[File Pages]
  - Each page: [Nonce (12B)] + [Ciphertext] + [Auth Tag (16B)]
  - Files can span multiple pages
  - Random access without full decryption

[Table of Contents]
  - File paths, offsets, lengths
  - Timestamps (created, modified)
```

### Security Features

- **AES-256-GCM**: Authenticated encryption for all data
- **RSA-2048**: Public key encryption for session keys
- **Argon2id**: Memory-hard key derivation for passphrases
- **Random Nonces**: Cryptographically secure random nonces for each page
- **No Key Reuse**: Each lockbox has a unique session key

### Multi-Recipient Support

A single lockbox can have multiple recipients:
- **Users**: Team members with their own `~/.dvault` keys
- **Machine Keys**: CI/CD agents with standalone RSA keys
- **Passwords**: Legacy/share mode for one-time access

Each recipient has the session key encrypted with their specific key, allowing independent access without sharing private keys.

## Browser Integration

Lockbox files can be decrypted in a web browser:

1. Upload your `~/.dvault` file (stays client-side)
2. Enter your passphrase to decrypt your private key
3. Browse and decrypt files on-demand

All decryption happens in the browser - your private key never leaves your device.

## Backup & Recovery

**Critical**: Backup your `~/.dvault` file!

- Without it, you cannot decrypt any lockboxes created with your key
- Store it securely (password manager, encrypted backup, etc.)
- Consider printing a paper backup of the private key for disaster recovery

## Migration from DVault

If you have existing DVault files, they will continue to work. The new PKI features are opt-in:

- Old password-based lockboxes: Still work with `lockbox unlock`
- New PKI lockboxes: Use the enhanced features above

## Contributing

Lockbox is open source. Contributions welcome!

Repository: https://github.com/onepub-dev/dvault

## License

MIT License - see LICENSE file for details
