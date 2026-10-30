# CTAP 2.2 Compliance Notes

This document is the maintained protocol checklist for `tpm-passkey`. It is
intended to prevent implementation work from relying on memory, comments, or
client-library permissiveness.

Normative source: [Client to Authenticator Protocol 2.2, FIDO Proposed Standard,
14 July 2025](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html).
Section numbers below refer to that version. When changing the target version,
update the source link and re-audit every table marked complete.

## Audit Method

For each command:

1. Copy its numeric request and response keys into this document.
2. Record mandatory fields, exact CBOR types, cryptographic inputs, and relevant
   state transitions.
3. Compare the implementation against the normative authenticator steps, not
   against existing tests.
4. Add strict tests for successful wire shape, missing fields, wrong field
   types, invalid cryptography, permissions, and status codes.
5. Add at least one end-to-end VM flow for browser-critical behavior.

An audit is complete only when both the implementation and independent tests
match this checklist.

## Current scope and gaps

This is an ongoing audit, **not a full conformance claim**. Section completion
markers describe scoped wire/behavior checks, not certification or security
assurance. Known remaining gaps include TPM-equivalent protection of PIN state,
complete TPM-bound credential-record integrity and rollback protection. These
require follow-up work.

### Version and feature boundary (§9)

The wire profile remains `FIDO_2_1` / `FIDO_2_0`, not `FIDO_2_2`.
Auditing behavior against the 2.2 text does not itself justify advertising 2.2.
For a future `FIDO_2_2` profile, §9 requires:

| Requirement | Current implementation |
| --- | --- |
| `hmac-secret` | **Missing** |
| PIN or built-in UV when `rk=true` | Client PIN implemented; storage assurance gap below |
| Credential management when `rk=true` | Implemented |
| `credProtect` when UV is supported, unless all credentials are level 3 | **Missing**; credentials are not implicitly level 3 |
| `pinUvAuthToken=true` when PIN/UV configured | Implemented |
| Protocol 2 when PIN/UV protocols are advertised | Implemented |

USB/UHID is the implemented transport. NFC, BLE, hybrid, and CTAP1/U2F are
not implemented; `CAPABILITY_NMSG` explicitly signals the absence of U2F.
This is a scope limitation, not evidence of compliance with those sections.

## Common Rules

- A successful CTAP2 response starts with status `0x00`; the remaining bytes are
  the command's CBOR response map.
- Error responses contain only the one-byte CTAP status.
- `clientDataHash` is exactly 32 bytes. Missing required top-level MC/GA fields
  return `MISSING_PARAMETER`; a present value of the wrong CBOR type returns
  `CBOR_UNEXPECTED_TYPE`.
- In MC/GA, `pinUvAuthProtocol` only triggers protocol/authentication validation
  when `pinUvAuthParam` accompanies it (§6.1.2/§6.2.2 step 2). A protocol-only
  field does not invent a missing token requirement.
- PIN/UV Auth Protocols 1 and 2 use 32-byte tokens. Protocol 1 derives its
  shared key with SHA-256, uses AES-CBC with a zero IV and no IV prefix, and
  truncates HMAC to 16 bytes. Protocol 2 authenticators prefer Protocol 2.
- Protocol 2 `kdf(Z)` is two independent HKDF-SHA-256 invocations with a 32-byte
  zero salt. The logical shared secret is `HMAC key || AES key`; info strings are
  `CTAP2 HMAC key` and `CTAP2 AES key` without trailing NUL bytes.
- Protocol 2 encryption is `random 16-byte IV || AES-256-CBC plaintext`, without
  padding. Inputs therefore have block-aligned plaintext lengths.
- Protocol 2 authentication is full HMAC-SHA-256, not a 16-byte truncation.

## `authenticatorClientPIN` (`0x06`)

Normative sections: 6.5.5 through 6.5.7.

### Request and response keys

| Request key | Name | Type |
| --- | --- | --- |
| `0x01` | `pinUvAuthProtocol` | unsigned integer |
| `0x02` | `subCommand` | unsigned integer |
| `0x03` | `keyAgreement` | COSE key |
| `0x04` | `pinUvAuthParam` | byte string |
| `0x05` | `newPinEnc` | byte string |
| `0x06` | `pinHashEnc` | byte string |
| `0x09` | `permissions` | nonzero unsigned integer |
| `0x0a` | `rpId` | text string |

These are top-level fields. There is no nested subcommand-parameter map.

| Response key | Name | Type |
| --- | --- | --- |
| `0x01` | `keyAgreement` | COSE key |
| `0x02` | `pinUvAuthToken` | byte string |
| `0x03` | `pinRetries` | unsigned integer |
| `0x04` | `powerCycleState` | boolean |
| `0x05` | `uvRetries` | unsigned integer |

A token response contains encrypted `pinUvAuthToken` at key `0x02`. It does not
contain a response-side `pinUvAuthParam`; key `0x03` is `pinRetries`.

### Subcommands

| Value | Name | Required request fields | Success fields |
| --- | --- | --- | --- |
| `0x01` | `getPINRetries` | `subCommand` | `pinRetries`, optional `powerCycleState` |
| `0x02` | `getKeyAgreement` | protocol, `subCommand` | `keyAgreement` |
| `0x03` | `setPIN` | protocol, subcommand, key agreement, auth parameter, encrypted new PIN | empty map |
| `0x04` | `changePIN` | protocol, subcommand, key agreement, auth parameter, encrypted new PIN and old PIN hash | empty map |
| `0x05` | `getPinToken` (legacy) | protocol, subcommand, key agreement, encrypted PIN hash | encrypted token |
| `0x06` | `getPinUvAuthTokenUsingUvWithPermissions` | unsupported: no built-in UV | `INVALID_SUBCOMMAND` |
| `0x07` | `getUVRetries` | unsupported: no built-in UV | `INVALID_SUBCOMMAND` |
| `0x09` | `getPinUvAuthTokenUsingPinWithPermissions` | protocol, subcommand, key agreement, encrypted PIN hash, permissions; RP ID where required | encrypted token |

Permission bits are `mc=0x01`, `ga=0x02`, `cm=0x04`, `be=0x08`, `lbw=0x10`,
`acfg=0x20`, and `pcmr=0x40`. `mc` and `ga` require an RP ID for permissioned
token subcommands. The wire value accepts the full unsigned CBOR integer range;
undefined bits, including high bits above one byte, are ignored without granting
permissions. A literal zero permissions value on any subcommand is
`CTAP1_ERR_INVALID_PARAMETER`. Negative protocol, subcommand, or permissions
integers are `CBOR_UNEXPECTED_TYPE`. Permissions for unadvertised functionality
produce `CTAP2_ERR_UNAUTHORIZED_PERMISSION`.

`setPIN` authenticates `newPinEnc`. `changePIN` authenticates
`newPinEnc || pinHashEnc`. Decrypted `newPinEnc` is exactly 64 bytes before
trailing zero padding is removed. Decrypted `pinHashEnc` is exactly 16 bytes.

Initialize a key-agreement secret at authenticator power-up. Repeated
`getKeyAgreement` calls return that current key; they do not invalidate an
already obtained shared secret. A wrong PIN or PIN-hash decryption failure
regenerates the secret rather than leaving key agreement uninitialized.

Check blocked PIN state before decapsulation/MAC processing. For `changePIN`,
verify the integrity MAC before charging a PIN attempt. Persist the retry charge
before decrypting/verifying `pinHashEnc`; malformed ciphertext follows the same
failure/rekey path as a wrong PIN. A correct PIN restores retries before checking
a replacement PIN. Uncertain persistence latches PIN handling closed. Three
consecutive mismatches in one power cycle produce `CTAP2_ERR_PIN_AUTH_BLOCKED`;
zero retries produce `CTAP2_ERR_PIN_BLOCKED`.

PIN-issued tokens have no cached user presence. New token issuance invalidates
previous tokens across protocols, as required by §6.5.5.7; the active token is
protocol-tagged, and cross-protocol authentication is rejected even with a valid
MAC of the requested protocol's length. Tokens are permission- and RP-scoped.
Under the single-user-machine assumption, tokens are not bound to login sessions.

Malformed fields, missing integrity MACs, missing/unreadable integrity keys, or
invalid MACs in stored PIN state do not mean "no PIN". Credential/PIN operations
return `CTAP2_ERR_INTEGRITY_FAILURE` until repair and restart or successful
explicit reset. GetInfo conservatively reports configured PIN protection so
standard clients can still discover the authenticator and request reset.

Audit status: **complete for ClientPIN request/response handling and token
issuance**. Permission consumption and user-presence state during subsequent
commands are tracked by the makeCredential/getAssertion audits.

## `authenticatorMakeCredential` (`0x01`)

Normative section: 6.1.

Request keys:

| Key | Name | Type | Required |
| --- | --- | --- | --- |
| `0x01` | `clientDataHash` | 32-byte string | yes |
| `0x02` | `rp` | map | yes |
| `0x03` | `user` | map | yes |
| `0x04` | `pubKeyCredParams` | array | yes |
| `0x05` | `excludeList` | non-empty array | no |
| `0x06` | `extensions` | map | no |
| `0x07` | `options` | map | no |
| `0x08` | `pinUvAuthParam` | byte string | no |
| `0x09` | `pinUvAuthProtocol` | unsigned integer | with auth parameter |
| `0x0a` | `enterpriseAttestation` | unsigned integer | no |
| `0x0b` | `attestationFormatsPreference` | array of strings | no |

Response keys are `fmt=0x01` (required string), `authData=0x02` (required byte
string), `attStmt=0x03` (optional map), `epAtt=0x04` (optional boolean),
`largeBlobKey=0x05` (optional byte string), and
`unsignedExtensionOutputs=0x06` (optional map).

Normative behavior retained here:

- Validate every `pubKeyCredParams` entry even after selecting a supported
  algorithm; reject malformed and duplicate entries.
- `excludeList`, when present, is non-empty. For an eligible matching credential,
  wait for UP if it is not cached; return `CREDENTIAL_EXCLUDED` whether UP is
  obtained or the wait times out (§6.1.2 step 12). Preserve transport cancellation
  as `KEEPALIVE_CANCEL`. Exclusion precedes normal token consumption and resident
  capacity checks; it does not consume cached UP or token permissions.
- CTAP options are `rk`, `up`, and `uv`, all booleans. `up=false` is
  `CTAP2_ERR_INVALID_OPTION`; unknown keys are ignored. WebAuthn fields such as
  `residentKey` are not CTAP options.
- A discoverable (`rk=true`) credential requires a PIN token when a PIN is
  configured. Without a PIN, discoverable enrollment is permitted with UP only.
  An effective `uv=true` option without a token returns `INVALID_OPTION` (no
  built-in UV). A valid PIN token takes precedence over the option. Creating another discoverable credential
  for the same RP ID and user ID overwrites the old credential.
- Verify `authenticate(pinUvAuthToken, clientDataHash)`. The RP ID is not
  appended to the HMAC input. Separately require `mc` permission and enforce or
  associate the token's permissions RP ID.
- A zero-length `pinUvAuthParam` performs authenticator selection and then
  returns `PIN_NOT_SET` or `PIN_INVALID`.
- User presence consumes cached UP, UV, and all token permissions except `lbw`.

No authenticator extensions are implemented. Unknown extension inputs are
ignored without producing signed outputs. In particular, `credProps` is a
[WebAuthn client registration extension](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension),
with no authenticator input, processing, or output (§10.1.3).

Audit status: **complete for implemented algorithms and extensions**.

## `authenticatorGetAssertion` (`0x02`)

Normative sections: 6.2 and 6.3.

| Request key | Name | Type | Required |
| --- | --- | --- | --- |
| `0x01` | `rpId` | string | yes |
| `0x02` | `clientDataHash` | 32-byte string | yes |
| `0x03` | `allowList` | non-empty array | no |
| `0x04` | `extensions` | map | no |
| `0x05` | `options` | map | no |
| `0x06` | `pinUvAuthParam` | byte string | no |
| `0x07` | `pinUvAuthProtocol` | unsigned integer | with auth parameter |

Response keys are `credential=0x01`, `authData=0x02`, `signature=0x03`, optional
`user=0x04`, optional `numberOfCredentials=0x05`, optional `userSelected=0x06`,
optional `largeBlobKey=0x07`, and optional `unsignedExtensionOutputs=0x08`.

- Verify the PIN/UV parameter over `clientDataHash`, require `ga`, and enforce or
  associate RP-ID scope separately.
- `up` defaults to true and may be false for silent/pre-flight assertions. `uv`
  defaults to false. An `rk` option is `CTAP2_ERR_UNSUPPORTED_OPTION`.
- With an allow list, select one matching credential, omit the count, and do
  not initialize GetNextAssertion state. Discoverable credentials still return
  their user handle (§6.1.3 and §6.2 response table), even though §6.2.2 step 11
  skips step 12's account-selection flow. Omit names in this case; a
  non-discoverable credential may omit the user entity.
- Without an allow list, consider discoverable credentials only, newest first.
  Persistent reloads retain creation order using monotonically assigned local
  IDs, not random credential-ID order or second-resolution timestamps; the
  assertion path reverses that order. Local IDs survive rewrites of existing
  credentials. Store regression and restart VM checks cover this behavior.
  Return user ID, omit identifying names without UV, and return
  `numberOfCredentials` when more than one credential matches.
- GetNextAssertion has no input, omits the count, resets its 30-second timer per
  response, and returns `CTAP2_ERR_NOT_ALLOWED` for absent, exhausted, or expired
  state.
- User presence consumes cached UP, UV, and all token permissions except `lbw`.

Audit status: **complete for implemented algorithms and extensions**.

## `authenticatorGetInfo` (`0x04`)

Normative section: 6.4. The command has no input parameters. Current advertised
members are:

- versions: `FIDO_2_1`, then `FIDO_2_0`;
- no authenticator extensions (the extensions list is omitted);
- the project AAGUID (16 bytes);
- options: `plat=false`, `rk=true`, `up=true`, `clientPin` and `pinUvAuthToken`
  reflecting whether a PIN is configured, `credMgmt=true`, and
  `makeCredUvNotRqd=true`; `uv` is absent (host approval is not built-in UV);
- maximum message size 1200 bytes;
- PIN/UV Auth Protocols `[2, 1]`, in preference order;
- transport `usb`;
- ES256 public-key credential creation;
- minimum PIN length of four Unicode code points.

Every advertised option must have a working command path. Unsupported options,
extensions, preview features, enterprise attestation, large blobs, and bio
enrollment are omitted. Lists are non-empty and contain no duplicates.

Audit status: **complete**.

## `authenticatorCredentialManagement` (`0x0a`)

Normative section: 6.8.

Request keys are `subCommand=0x01` (required unsigned integer),
`subCommandParams=0x02` (subcommand-specific map), `pinUvAuthProtocol=0x03`
(unsigned integer), and `pinUvAuthParam=0x04` (byte string). Subcommands and
parameter requirements are:

| Value | Subcommand | Parameters | Authentication |
| --- | --- | --- | --- |
| `0x01` | `getCredsMetadata` | none | `cm`, no permissions RP ID |
| `0x02` | `enumerateRPsBegin` | none | `cm`, no permissions RP ID |
| `0x03` | `enumerateRPsGetNextRP` | none | continuation state |
| `0x04` | `enumerateCredentialsBegin` | `rpIDHash=0x01`, 32-byte string | `cm`, no permissions RP ID |
| `0x05` | `enumerateCredentialsGetNextCredential` | none | continuation state |
| `0x06` | `deleteCredential` | `credentialID=0x02`, descriptor | `cm`, unscoped or matching RP ID |
| `0x07` | `updateUserInformation` | descriptor plus `user=0x03` | `cm`, unscoped or matching RP ID |

Authenticated requests compute `authenticate(pinUvAuthToken, subCommand ||
canonical-CBOR(subCommandParams))`. A missing authentication parameter is
`CTAP2_ERR_PUAT_REQUIRED`; an unknown subcommand is
`CTAP2_ERR_INVALID_SUBCOMMAND`.

Response keys are metadata count `0x01`, remaining count `0x02`, RP `0x03`, RP
ID hash `0x04`, total RPs `0x05`, user `0x06`, credential descriptor `0x07`,
public key `0x08`, and total credentials `0x09`. Optional implemented-feature
fields begin at `0x0a`. Totals occur only in the corresponding begin response.

RP and credential continuation requests do not repeat token authentication.
Their state is bound to the initiating token, expires after 30 seconds without
a matching continuation, and is interrupted by
any other operation. Missing, mismatched, expired, interrupted, or exhausted
state returns `CTAP2_ERR_NOT_ALLOWED`; each successful continuation resets the
30-second interval.

Updating user information requires the supplied user ID to equal the stored user
ID. It changes only `name` and `displayName`; absent or empty names remove those
fields. Deletion and update validate a public-key credential descriptor and
return `CTAP2_ERR_NO_CREDENTIALS` when no matching discoverable credential
exists.

Audit status: **complete for implemented credential-management fields**.

## Reset, selection, and unsupported commands

`authenticatorReset` (`0x07`, section 6.6) and `authenticatorSelection` (`0x0b`,
section 6.9) have no input parameters and return only the `CTAP2_OK` status byte
on success. Both collect fresh user presence, return
`CTAP2_ERR_OPERATION_DENIED` for refusal, and `CTAP2_ERR_USER_ACTION_TIMEOUT`
(`0x2f`, not `ACTION_TIMEOUT`) for a user-action deadline. Because this USB authenticator
has no physical display, reset is accepted only during the first 10 seconds of
a new daemon/UHID authenticator generation; a later request returns
`CTAP2_ERR_NOT_ALLOWED` without prompting.

Reset deletes all credential rows and client-PIN state in one SQLite transaction,
including credentials not successfully loaded into memory. It clears ephemeral
token, retry-throttle, key-agreement, assertion, and credential-management state
only after commit. Persistence failures roll back both PIN and credential
deletion and return `CTAP2_ERR_OPERATION_DENIED`. Selection does not cache presence
for a later command.

Recognized but unimplemented bio-enrollment, large-blob, configuration, and
preview command codes return `CTAP1_ERR_INVALID_COMMAND`. In particular,
credential-management preview (`0x41`) is rejected because only the final
`credMgmt` feature is advertised. Unknown command bytes have the same status.

Audit status: **complete**.

## CTAPHID USB transport

Normative sections: 11.2.2 through 11.2.9.

The 64-byte HID reports carry a 57-byte initialization-packet fragment followed
by up to 128 ordered 59-byte continuation fragments, for a maximum 7609-byte
message. CIDs zero and `0xffffffff` are reserved; broadcast is accepted only for
channel-allocating `CTAPHID_INIT`. Continuations use sequence values `0x00`
through `0x7f` and spurious continuations without an active message are ignored.

Only one transaction is active globally. A request initialization packet from
another allocated channel receives `ERR_CHANNEL_BUSY`. An `INIT` on the active
CID aborts buffered or processing work, flushes state through the authenticator
worker, echoes the nonce, and resynchronizes that CID. A valid `INIT` on an idle
allocated CID also discards authenticator continuation state. Validate its exact
eight-byte nonce before allocating a CID or discarding state. An incomplete packet
sequence times out after three seconds with `ERR_MSG_TIMEOUT`; a wrong expected
sequence returns `ERR_INVALID_SEQ` and aborts assembly.

CBOR execution runs on a persistent worker that exclusively owns the
Authenticator and TPM context. The UHID thread emits `CTAPHID_KEEPALIVE` at
100-ms intervals with `STATUS_PROCESSING` or `STATUS_UPNEEDED`, and on the next
UHID-loop poll when status changes. Empty CBOR transport messages return
`ERR_INVALID_LEN` without dispatching a CTAP command. A zero-length
`CTAPHID_CANCEL` has no direct response; inactive or malformed CANCEL packets
are ignored without unsolicited responses. On the active CBOR CID it marks the
operation cancelled, queues state cleanup, and the original CBOR transaction
returns `CTAP2_ERR_KEEPALIVE_CANCEL`; on a non-active CID it is ignored.

Production approval has one 30-second user-action budget covering asynchronous
system-bus checks and the directed GTK-agent request. CANCEL is observed
at most every 20 ms; explicit remote dialog cancellation has a separate 100-ms
cleanup bound and uses the same unique connection and request ID. Missing helper,
refusal/deadline/cancel/disconnection never trigger fallback. Host approval is a
plain acknowledgement, not polkit/PAM re-authentication; polkit only gates agent
registration and management. PIN/token requirements and CTAP error mappings
remain independent and unchanged. Reset/selection map deadlines to `USER_ACTION_TIMEOUT`;
makeCredential/getAssertion UP and zero-length-auth selection map them to
`OPERATION_DENIED`, per their distinct normative steps. Local kernel syscalls,
ordinary logging, and an already executing TPM command are not asynchronously
preempted.

`CTAPHID_INIT`, `PING`, `CBOR`, `CANCEL`, `ERROR`, and `KEEPALIVE` follow their
mandatory direction and length rules. Optional `WINK` is not advertised and
returns `ERR_INVALID_CMD`: there is no visible/audible device-identification
mechanism, so acknowledging it as implemented would be misleading.
`CAPABILITY_CBOR` and `CAPABILITY_NMSG` advertise CBOR support and the absence
of CTAPHID_MSG/U2F.

Audit status: **complete**.

## Follow-up Validation

The integrated follow-up passed `nix fmt`, `cargo check --workspace`, and
`cargo test --workspace` (170 passed, 8 ignored). `nix flake check --keep-going`
passed all checks for x86_64-linux, including the 15 NixOS VM scenarios.
This covers real TPM signing, PIN protocols, credential management, restart
ordering, transport/cancellation, reset, and integrity behavior. Nix skipped
incompatible aarch64-linux/aarch64-darwin checks; those platforms were not tested.
These results are regression evidence, not FIDO certification.

## Remaining Security and Conformance Work

1. **PIN storage assurance (§6.5.1).** The specification requires PIN storage
   to provide the same or better security assurances as private keys. A local
   PBKDF2 verifier plus a colocated MAC key does not meet this requirement for
   TPM-protected private keys. Sealing the verifier alone would not prevent
   retry-counter rollback; TPM-bound authorization and persistent retry/reset
   semantics need to be designed and tested together.
2. **Complete record integrity and rollback.** The credential MAC currently
   authenticates ID, RP, discoverability, user handle, and user names. It does
   not authenticate the entire keyslot/policy record, signature counter, or
   creation-order metadata, and no MAC prevents replay of an older valid store.
   This affects confidence in deletion/overwrite and counter behavior under
   store tampering. Extending the MAC requires a versioned storage transition;
   silently accepting old unauthenticated fields as trusted would not close
   the gap. Do not treat these security properties as implemented.
3. **A 2.2 advertised profile.** Implement `hmac-secret` and `credProtect` (or
   enforce implicit level 3), then rerun the §9 feature matrix and command
   audits before adding `FIDO_2_2` to GetInfo. The 2.2 reset text (§6.6) also
   requires regenerating a 128-bit device identifier; no such identifier or
   persistent-token/`encIdentifier` feature is currently implemented.
4. **Independent interoperability/certification.** VM flows exercise real TPM
   signatures and protocol-library clients, not an official FIDO conformance
   suite or a full browser interoperability matrix.
