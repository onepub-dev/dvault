# CI Secret Storage Comparison

Lockbox env vars are useful when a team wants a portable encrypted bundle that
travels with build inputs, test fixtures, or deployment artifacts. They are not
a full replacement for an online secret-management service.

## Lockbox Fit

Good uses:

- Store a versioned set of non-rotating or rarely rotated CI variables beside an
  encrypted artifact.
- Share the same encrypted bundle across local development, CI, and air-gapped
  environments.
- Keep paths, env names, and values private inside the lockbox until a workflow
  unlocks it.
- Use password sharing plus public-key recipients for a small number of trusted
  operators or automation identities.

Weak uses:

- Dynamic credentials that must be minted per job.
- Central policy enforcement across many repositories or organizations.
- Automatic rotation with audit logs and per-workload identity.
- Fine-grained read auditing of individual secret values.

## Compared With Common CI Options

GitHub Actions encrypted secrets are simple and native to GitHub workflows. They
work well for repository, environment, and organization scoped values, but they
are tied to GitHub and are not a portable archive format. GitHub also documents
using an encrypted file such as a GPG-encrypted blob for larger secret payloads,
which is close to the "encrypted bundle in the repo" use case that Lockbox
targets.

HashiCorp Vault is stronger for production secret operations. It centralizes
identity-based access, can generate dynamic credentials, rotates secrets, and
audits interactions. Lockbox should not try to compete with that server-side
control plane; it is closer to a portable encrypted artifact.

AWS Secrets Manager is stronger when workloads already run in AWS and need
managed secret versions, IAM policy, TLS retrieval, and rotation workflows.
Lockbox is more useful when the same encrypted bundle must run outside one cloud
account or without a network dependency.

1Password Secrets Automation is stronger when an organization already manages
human and machine secrets in 1Password and wants CI/CD integrations. Lockbox is
more self-contained, but does not provide organization-level vault governance.

## Design Implications

- Keep env vars lazy-loaded and private: listing files must not reveal env
  names, and env values must never appear in visualization output.
- Provide shell-friendly export, but make workflows explicitly opt into using
  those values.
- Do not pretend Lockbox replaces dynamic secret engines. Document Vault,
  Secrets Manager, and 1Password as better choices for rotation, central audit,
  and active workload identity.
- Treat Lockbox as an encrypted, recoverable, cross-platform bundle that can
  carry secrets when central infrastructure is unavailable or deliberately out
  of scope.

## Sources

- GitHub Actions encrypted secrets: https://docs.github.com/actions/reference/encrypted-secrets
- HashiCorp Vault overview: https://docs.hashicorp.com/vault/docs/about-vault/how-vault-works
- AWS Secrets Manager overview: https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html
- 1Password Secrets Automation: https://developer.1password.com/docs/secrets-automation/
