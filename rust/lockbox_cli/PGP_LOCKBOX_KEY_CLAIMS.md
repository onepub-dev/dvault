# PGP-Signed Lockbox Key Claims

## Purpose

A PGP-signed Lockbox key claim lets a user bind an existing OpenPGP identity to
a Lockbox public key.

This can remove the need for person-to-person verification of the Lockbox key
when the recipient already trusts the signer's PGP identity.

## Trust Model

PGP signing shifts the trust decision. It does not remove it.

Without PGP:

```text
Verify Alice's Lockbox public key directly.
```

With PGP:

```text
Verify Alice's PGP key, then trust the Lockbox key it signs.
```

This is useful when one of these is true:

- Bob already trusts Alice's PGP fingerprint.
- Alice's PGP key is published through a company WKD and Bob trusts that domain.
- Alice's PGP key is signed by a trusted organization or introducer.
- Enterprise policy says keys from a specific domain directory are authoritative.

If Bob does not already trust Alice's PGP key, the signature only proves that the
Lockbox key was signed by the fetched PGP key. It does not prove that the PGP key
belongs to Alice.

## Proposed CLI

Alice creates a signed claim:

```bash
lockbox contact claim alice@example.com --lockbox-key alice.pub --sign-with-pgp
```

The claim contains:

```text
identity: alice@example.com
lockbox_public_key: ...
lockbox_fingerprint: ...
pgp_fingerprint: ...
created_at: ...
signature: ...
```

Bob imports the claim:

```bash
lockbox contact add alice@example.com --method pgp-signed
```

Lockbox should:

1. Fetch Alice's PGP public key from WKD, a configured keyserver, or a supplied
   local key file.
2. Verify the signed Lockbox-key claim.
3. Check whether the PGP key is trusted by local policy or prior verification.
4. Store Alice's Lockbox public key with an appropriate trust state.

## Trust States

If the PGP key is trusted:

```text
trust: pgp-validated
```

If the PGP key is not trusted:

```text
trust: unverified
reason: lockbox key is signed, but the signing PGP identity is not trusted
```

In the untrusted case, Lockbox should still require an explicit verification
step before using the key without warnings.

## Key Point

A PGP-signed claim can avoid manual verification of the Lockbox key only when
the PGP identity is already trusted through another mechanism.
