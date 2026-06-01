# Browser and WASM Unlock Design

This records the browser unlock plan for GitHub issue #28. Native vault
unlocking can delegate to the user's platform secret store, but browser WASM
cannot call macOS Keychain, Windows Credential Manager, Linux Secret Service,
or KWallet directly. Browser support therefore needs its own trust model.

## Position

Browser builds should treat `lockbox_core` as the portable format and crypto
engine. They should not depend on the native `lockbox_vault` agent or platform
secret-store integrations.

The default browser unlock mode is prompt-only:

```text
user password or private key material
  -> WASM lockbox_core unlock
  -> content key held in page memory only
  -> key is discarded on explicit lock, page close, navigation, or timeout
```

Persistent browser unlock is optional and opt-in. It stores browser-specific
unlock state for one origin and browser profile; it is not a replacement for a
native user-session keychain.

## Browser Trust Model

Browser unlock state is protected primarily by:

- the browser origin boundary
- the user's browser profile boundary
- HTTPS and the application's content-security posture
- the browser's storage-clearing and private-mode behavior

This is weaker and different from native keychains. Script injection in the
origin must be treated like code execution inside the unlock boundary. If
hostile script runs in the Lockbox web origin, it can ask WebCrypto to unwrap
state, read decrypted lockbox data that the app has opened, or replace stored
browser metadata.

Persistent browser unlock state can be lost when the user clears site data, the
browser evicts best-effort storage, the user switches browser profiles, or a
private/incognito session ends. Recovery must always be possible by re-entering
the lockbox password, importing private key material, or using another
configured lockbox access method.

## Storage Model

Use IndexedDB for browser-local metadata because it can store structured app
records and serialized `CryptoKey` objects. Store only per-origin browser
unlock state, not archive contents and not plaintext content keys by default.

Recommended records:

```text
lockbox-browser-unlock-v1
  origin_id
  lockbox_uuid
  created_utc
  last_used_utc
  mode
  wrapping_key_id
  wrapped_unlock_secret
  key_slot_hint
  storage_persistence_state
```

`wrapped_unlock_secret` should be one of:

- an encrypted copy of the vault unlock secret, when the product is unlocking a
  browser-side vault concept
- an encrypted recipient private-key seed for browser-only key ownership
- no value in prompt-only mode

Do not persist unwrapped lockbox content keys by default. A content key is the
direct authority to decrypt a lockbox and is a poor persistent browser secret.

The browser app should call `navigator.storage.persisted()` and, when the user
opts into persistent unlock, request `navigator.storage.persist()`. Failure to
obtain persistent storage is not fatal, but the UI and bindings must treat the
result as advisory and expect re-prompting.

## WebCrypto Wrapping

Use WebCrypto for browser-held wrapping keys:

```text
generate non-extractable AES-KW or AES-GCM CryptoKey
  -> store CryptoKey in IndexedDB
  -> wrap the browser unlock secret
  -> store wrapped bytes in IndexedDB
```

The `CryptoKey` should be generated as non-extractable and limited to the
minimum `wrapKey`/`unwrapKey` or `encrypt`/`decrypt` usages needed by the
chosen mode. Non-extractable keys reduce accidental export, but they do not
make browser storage equivalent to a native keychain. The same origin can still
use the key while the browser profile retains it.

The WASM boundary should receive plaintext unlock material only at the moment
of unlock. It should immediately construct the existing secret wrappers on the
Rust side and zero temporary JS-owned byte buffers where the host API permits
it. JS strings should remain a documented weaker path because their copies
cannot be reliably scrubbed.

## Passkeys and WebAuthn

Passkeys are useful as a user-mediated unlock factor, not as a general-purpose
secret store.

Use WebAuthn only for modes that can be expressed as an authentication or PRF
workflow supported by current browsers:

- Detect `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`
  before offering platform-authenticator enrollment.
- Detect `PublicKeyCredential.isConditionalMediationAvailable()` before using
  conditional sign-in or unlock prompts.
- Store passkey credential IDs and public metadata in IndexedDB.
- Keep a prompt-only recovery path because passkeys can be unavailable on a
  device, removed from the account, or unsupported by the browser.

Do not describe a passkey assertion by itself as decrypting a lockbox. A normal
WebAuthn assertion proves user presence or verification to a relying party; it
does not hand the application a symmetric wrapping key. If the implementation
later uses WebAuthn PRF-style extensions, that must be designed and tested as a
separate cryptographic mode with explicit browser compatibility gates.

## API Shape

Expose browser unlock as a host-side policy around `lockbox_core`, not as a
native-vault feature compiled to WASM.

Suggested binding concepts:

```rust
enum BrowserUnlockMode {
    PromptOnly,
    IndexedDbWrappedSecret,
    WebAuthnAssisted,
}

struct BrowserUnlockPolicy {
    mode: BrowserUnlockMode,
    persist_storage: bool,
    ttl_seconds: Option<u64>,
}
```

The Rust core should continue accepting explicit unlock material. JS or Dart
web bindings own:

- IndexedDB record storage
- WebCrypto key generation and wrapping calls
- WebAuthn/passkey ceremonies
- private-mode and storage-persistence detection
- user-facing disable/forget controls

## Disable and Forget Controls

Persistent browser unlock must be easy to disable:

- A global setting disables persistent browser unlock for the origin.
- Per-lockbox controls delete that lockbox's IndexedDB unlock record.
- A full "forget this browser" action deletes all Lockbox IndexedDB unlock
  records and any stored WebCrypto wrapping keys.

Disabling persistent unlock does not remove key slots from portable lockboxes.
It only removes local browser convenience state.

## Open Questions

- Whether WebAuthn PRF support is broad and stable enough to justify a real
  passkey-derived wrapping-key mode.
- Whether browser apps need a separate browser-local vault file or only
  per-lockbox unlock records.
- Whether mobile web views need stricter defaults because their storage and
  WebAuthn behavior varies by host app.

## References

- W3C Web Cryptography API, especially `CryptoKey` storage and extractability:
  https://www.w3.org/TR/webcrypto/
- W3C Web Authentication Level 3 capability detection:
  https://www.w3.org/TR/webauthn-3/
- WHATWG Storage Standard persistence model:
  https://storage.spec.whatwg.org/
