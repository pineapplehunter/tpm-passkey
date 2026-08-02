# CTAP 2.2 Compliance Notes

This document is the maintained protocol checklist for `linux-tpm-fido2`. It is
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

## Common Rules

- A successful CTAP2 response starts with status `0x00`; the remaining bytes are
  the command's CBOR response map.
- Error responses contain only the one-byte CTAP status.
- `clientDataHash` is exactly 32 bytes.
- For PIN/UV Auth Protocol 2, `pinUvAuthToken` and `authenticate()` output are
  exactly 32 bytes.
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
| `0x06` | `getPinUvAuthTokenUsingUvWithPermissions` | protocol, subcommand, key agreement, permissions; RP ID where required | encrypted token |
| `0x07` | `getUVRetries` | `subCommand` | `uvRetries` |
| `0x09` | `getPinUvAuthTokenUsingPinWithPermissions` | protocol, subcommand, key agreement, encrypted PIN hash, permissions; RP ID where required | encrypted token |

Permission bits are `mc=0x01`, `ga=0x02`, `cm=0x04`, `be=0x08`, `lbw=0x10`,
`acfg=0x20`, and `pcmr=0x40`. `mc` and `ga` require an RP ID for permissioned
token subcommands. Undefined bits are ignored. A literal zero permissions value
is `CTAP1_ERR_INVALID_PARAMETER`. Permissions for unadvertised functionality
produce `CTAP2_ERR_UNAUTHORIZED_PERMISSION`.

`setPIN` authenticates `newPinEnc`. `changePIN` authenticates
`newPinEnc || pinHashEnc`. Decrypted `newPinEnc` is exactly 64 bytes before
trailing zero padding is removed. Decrypted `pinHashEnc` is exactly 16 bytes.

After a wrong PIN, retries are decremented and the key-agreement key is
regenerated. Three consecutive mismatches in one power cycle produce
`CTAP2_ERR_PIN_AUTH_BLOCKED`; zero retries produce `CTAP2_ERR_PIN_BLOCKED`.

A token issued by built-in UV records user presence for at most 30 seconds. The
cached presence is bound to the issuing login-session UID and session ID, and is
consumed by one user-presence operation. A PIN-issued token has no cached user
presence. All tokens remain cryptographically permission- and RP-scoped.

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
- `excludeList`, when present, is non-empty. Do not reveal a matching credential
  until user presence has been collected.
- CTAP options are `rk`, `up`, and `uv`, all booleans. `up=false` is
  `CTAP2_ERR_INVALID_OPTION`; unknown keys are ignored. WebAuthn fields such as
  `residentKey` are not CTAP options.
- A discoverable (`rk=true`) credential requires UV when this authenticator is
  protected by built-in UV or a PIN. Creating another discoverable credential
  for the same RP ID and user ID overwrites the old credential.
- Verify `authenticate(pinUvAuthToken, clientDataHash)`. The RP ID is not
  appended to the HMAC input. Separately require `mc` permission and enforce or
  associate the token's permissions RP ID.
- A zero-length `pinUvAuthParam` performs authenticator selection and then
  returns `PIN_NOT_SET` or `PIN_INVALID`.
- User presence consumes cached UP, UV, and all token permissions except `lbw`.

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
- With an allow list, select one matching credential, omit user/count when not
  needed, and do not initialize GetNextAssertion state.
- Without an allow list, consider discoverable credentials only, newest first.
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
- extension: `credProps`;
- the project AAGUID (16 bytes);
- options: `plat=false`, `rk=true`, `up=true`, `uv=true`, `clientPin` reflecting
  whether a PIN is configured, `pinUvAuthToken=true`, `credMgmt=true`, and
  `makeCredUvNotRqd=true`;
- maximum message size 1200 bytes;
- PIN/UV Auth Protocol 2;
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
Their state is bound to the initiating token and login-session UID/session ID,
expires after 30 seconds without a matching continuation, and is interrupted by
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
on success. Both collect fresh user presence and fail with
`CTAP2_ERR_OPERATION_DENIED` when it is denied. Because this USB authenticator
has no physical display, reset is accepted only during the first 10 seconds of
a new daemon/UHID authenticator generation; a later request returns
`CTAP2_ERR_NOT_ALLOWED` without prompting.

Reset deletes all credentials and client-PIN state and clears ephemeral token,
key-agreement, assertion, and credential-management state. Persistence failures
fail closed with `CTAP2_ERR_OPERATION_DENIED`. Selection does not cache presence
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
worker, echoes the nonce, and resynchronizes that CID. An incomplete packet
sequence times out after three seconds with `ERR_MSG_TIMEOUT`; a wrong expected
sequence returns `ERR_INVALID_SEQ` and aborts assembly.

CBOR execution runs on a persistent worker that exclusively owns the
Authenticator and TPM context. The UHID thread emits `CTAPHID_KEEPALIVE` at
100-ms intervals with `STATUS_PROCESSING` or `STATUS_UPNEEDED`. A zero-length
`CTAPHID_CANCEL` has no direct response. On the active CBOR CID it marks the
operation cancelled, queues state cleanup, and the original CBOR transaction
returns `CTAP2_ERR_KEEPALIVE_CANCEL`; on a non-active CID it is ignored.

`CTAPHID_INIT`, `PING`, `CBOR`, `CANCEL`, `ERROR`, and `KEEPALIVE` follow their
mandatory direction and length rules. `WINK` is implemented and advertised;
`CAPABILITY_CBOR` and `CAPABILITY_NMSG` advertise CBOR support and the absence
of CTAPHID_MSG/U2F.

Audit status: **complete**.

## Remaining Audit Order

1. Complete ClientPIN inputs, errors, permissions, and retry state.
2. Complete makeCredential and getAssertion request/response tables.
3. Audit getInfo capability claims against implemented behavior.
4. Complete credential management and stateful continuation commands.
5. Complete reset, selection, and unsupported command behavior.
6. Complete CTAPHID framing, channels, cancellation, keepalive, and errors.
