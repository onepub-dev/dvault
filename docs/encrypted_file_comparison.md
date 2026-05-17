# Encrypted File Comparison

Lockbox competes most directly with encrypted-file workflows such as
GPG-encrypted blobs, SOPS-managed secret files, age-encrypted files, and
repository-local encrypted `.env` archives. Those tools are usually simpler than
a full online secret-management service, but they are also widely understood and
easy to fit into CI/CD pipelines.

Lockbox should not be positioned as a replacement for every encrypted-file
workflow. Its strongest position is as a structured, portable encrypted bundle
for many files and environment variables, with private metadata, recovery
support, and both password and recipient-key access.

## Comparison Summary

- Basic model: Lockbox is a structured `.lbox` container. GPG usually
  encrypts one file or blob. SOPS and age-style workflows usually encrypt
  structured files or simple blobs.
- Best fit: Lockbox fits multi-file and env-var bundles. GPG fits a single
  file or tarball. SOPS fits YAML, JSON, dotenv, and config-secret files.
- Metadata privacy: Lockbox hides paths, env names, and small-object sizes
  inside encrypted pages. GPG usually leaks the outer filename and blob size.
  SOPS often leaves keys or document structure visible, depending on mode.
- Random access: Lockbox is designed for selected file and range reads. GPG,
  SOPS, and age workflows usually decrypt the whole encrypted file.
- CI availability: Lockbox requires its own install step. GPG is common on CI
  images. SOPS and age are common in infrastructure teams, but are often
  installed explicitly.
- Key ecosystem: Lockbox uses password slots and ML-KEM recipient slots. GPG
  has the mature OpenPGP key ecosystem. SOPS can use age, PGP, and cloud KMS
  identities.
- Signing and provenance: GPG has mature signing workflows. Lockbox
  authenticates encrypted content internally but is not currently positioned as
  a signing tool.
- Maturity: Lockbox is pre-1.0 and still requires third-party crypto review.
  GPG, SOPS, and age have much wider production adoption.
- Secret-service features: none of these encrypted-file approaches replace
  Vault, cloud secret managers, dynamic credentials, rotation, or audit logs.

## Where Lockbox Is Stronger

- Lockbox can store many files, symlinks, and environment variables in one
  encrypted container instead of requiring a tarball or directory convention.
- Paths, file names, environment variable names, values, and TOC entries
  are private metadata rather than cleartext indexes.
- Fixed-size encrypted pages hide the exact size of tiny files and env entries
  better than a simple encrypted file.
- The format is designed for range reads, browser/WASM access, and extracting
  selected files without decrypting a whole archive.
- The recovery model can scan valid pages and salvage data when headers,
  TOCs, or records are damaged.
- Password slots and public-key recipient slots can coexist in the same
  container.
- The UX can be domain-specific: `lockbox env export`,
  `lockbox add-recipient`, `lockbox remove-key`, and local unlock caching are
  clearer for secret bundles than raw GPG commands.

## Where Lockbox Is Weaker

### Ecosystem Trust

GPG and OpenPGP have decades of production use, existing security review,
familiar operational patterns, and broad institutional acceptance. Lockbox is
newer, the format is still pre-1.0, and third-party cryptographic review remains
a release blocker.

This matters most when a security team needs to approve a tool quickly. GPG,
SOPS, and age are already recognizable. Lockbox needs stronger documentation,
test vectors, independent review, and repeatable threat-model notes before it
can earn the same level of trust.

### Installation Friction

GPG is already present or easy to install in many CI images. SOPS and age are
also common in infrastructure teams. Lockbox requires its own binary, package,
checksum, install instructions, and bootstrap story.

For a simple CI workflow, the difference between these commands is material:

```bash
gpg --decrypt secrets.env.gpg
```

```bash
lockbox env export secrets.lbox
```

The Lockbox command may be better once installed, but GPG often wins the first
adoption step because the dependency is already available.

### Key Management Expectations

GPG has mature support for keyrings, subkeys, expiration, revocation
certificates, trust models, smartcards, YubiKeys, and agent integration. SOPS
can delegate access to age keys, PGP keys, or cloud KMS identities.

Lockbox intentionally uses a narrower model:

- password slots derived with Argon2id
- recipient slots using ML-KEM-1024
- a local encrypted vault for private keys and trusted public keys
- an in-memory unlock agent for cached content keys

That model is cleaner for Lockbox's use case, but it does not yet match the
broader operational ecosystem that OpenPGP and KMS-backed SOPS deployments
already have.

### Interoperability

A `.gpg`, `.asc`, `.age`, or SOPS-managed YAML file can be handled by many
existing tools and libraries. A `.lbox` file requires Lockbox-compatible code.

That is the tradeoff for richer semantics. Lockbox can provide private paths,
env pages, recovery, and range access because it owns the container format. The
cost is that users cannot fall back to standard OpenPGP tooling to inspect,
decrypt, or rewrap the file.

### Simple Cases

For one encrypted `.env` file, one encrypted tarball, or one binary secret blob,
Lockbox may be heavier than the job requires. GPG, age, or SOPS can be easier to
explain:

```bash
gpg --symmetric secrets.env
age -r recipient public.txt
sops -d secrets.yaml
```

Lockbox becomes more compelling when the secret artifact is a bundle, not a
single file.

### Signing And Provenance

GPG is commonly used for both encryption and signatures. Teams may already have
processes for detached signatures, release signing, key verification, and
provenance checks.

Lockbox authenticates encrypted content internally, but it is not currently
positioned as a signing system that proves who created, reviewed, or approved a
secret bundle. If provenance matters, Lockbox needs either a native signing
story or clear guidance for signing `.lbox` artifacts externally.

### Hardware-Backed Keys

OpenPGP has mature smartcard and YubiKey workflows. Cloud-backed SOPS can rely
on hardware- or HSM-backed KMS keys through the cloud provider.

Lockbox currently stores private recipient material in the local encrypted
vault. Hardware-backed recipient keys, platform keychain integration, or KMS
recipient wrapping would improve enterprise credibility.

### CI/CD Examples

Encrypted-file workflows are already documented in many CI systems. For Lockbox
to compete, it needs first-class examples for:

- GitHub Actions
- GitLab CI
- Azure DevOps
- Docker and BuildKit
- Kubernetes init containers and jobs
- air-gapped build systems

The examples should show where the unlock secret comes from, how values are
exported, how masking is handled, and how decrypted files are removed after use.

## Product Implications

Lockbox should lean into the things GPG-style files do poorly:

- encrypted metadata, not just encrypted bytes
- one portable bundle for files and env vars
- easy recipient management without exposing human labels by default
- good recovery behavior
- browser/WASM/range-read support
- ergonomic commands for CI export and local development

Lockbox should avoid claiming generic superiority over GPG, SOPS, or age. Those
tools remain stronger for simple single-file encryption, existing OpenPGP/KMS
workflows, signature-heavy processes, and low-friction CI bootstrap.

## Recommended Positioning

Use this framing:

> Lockbox is a portable encrypted secret bundle for teams that need files,
> environment variables, private metadata, and offline operation in one
> artifact.

Avoid this framing:

> Lockbox replaces GPG, SOPS, Vault, or cloud secret managers.

The practical message is that Lockbox is not trying to be the universal
cryptographic primitive. It is trying to be the better product experience when
the encrypted object is a structured CI/CD secret bundle.

## Roadmap Items To Close Gaps

- Publish format test vectors and reproducible interoperability tests.
- Complete independent cryptographic review before a stable format release.
- Add an explicit signing/provenance story for `.lbox` artifacts.
- Add CI/CD quick-start examples for common platforms.
- Provide package-manager installation paths and checksum verification.
- Document key rotation, recipient removal, recovery, and emergency access
  playbooks.
- Consider hardware-backed or KMS-backed recipient integrations.
- Add a migration guide from GPG-encrypted tarballs and SOPS-managed `.env`
  files.

## Related Tools And References

- GnuPG: https://gnupg.org/
- SOPS: https://github.com/getsops/sops
- age: https://age-encryption.org/
- GitHub Actions encrypted secrets and encrypted-file workaround:
  https://docs.github.com/actions/reference/encrypted-secrets
- Lockbox CI secret storage comparison:
  [ci_secret_storage_comparison.md](ci_secret_storage_comparison.md)
