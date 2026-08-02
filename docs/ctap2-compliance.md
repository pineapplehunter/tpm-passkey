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

Audit status: **complete for ClientPIN request/response handling and token
issuance**. Permission consumption and user-presence state during subsequent
commands are tracked by the makeCredential/getAssertion audits.

## `authenticatorMakeCredential` (`0x01`)

Normative section: 6.1.

Request keys currently relevant to this implementation:

| Key | Name | Type |
| --- | --- | --- |
| `0x01` | `clientDataHash` | 32-byte string |
| `0x02` | `rp` | map |
| `0x03` | `user` | map |
| `0x04` | `pubKeyCredParams` | array |
| `0x05` | `excludeList` | array |
| `0x06` | `extensions` | map |
| `0x07` | `options` | map |
| `0x08` | `pinUvAuthParam` | byte string |
| `0x09` | `pinUvAuthProtocol` | unsigned integer |

For PIN/UV authentication, verify
`authenticate(pinUvAuthToken, clientDataHash)`. The RP ID is not appended to the
HMAC input. Separately require the `mc` permission and enforce or associate the
token's permissions RP ID.

Audit status: **PIN/UV input checked; full command pending**.

## `authenticatorGetAssertion` (`0x02`)

Normative section: 6.2. PIN/UV authentication likewise verifies
`authenticate(pinUvAuthToken, clientDataHash)`, then independently checks the
`ga` permission and RP-ID scope.

Audit status: **PIN/UV input checked; full command pending**.

## Remaining Audit Order

1. Complete ClientPIN inputs, errors, permissions, and retry state.
2. Complete makeCredential and getAssertion request/response tables.
3. Audit getInfo capability claims against implemented behavior.
4. Audit credential management and stateful continuation commands.
5. Audit reset, selection, and unsupported command behavior.
6. Audit CTAPHID framing, channels, cancellation, keepalive, and errors.
