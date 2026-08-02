# Refactor tasks

- [x] Move CTAP2 tests into a dedicated module.
- [x] Extract CTAP command and status definitions.
- [x] Extract CTAP CBOR codec helpers.
- [x] Extract authenticator-data and COSE encoding helpers.
- [x] Separate management protocol, service, and socket layers.
- [x] Inject user approval through a testable interface.
- [x] Extract shared credential domain conversions.
- [x] Refresh the architecture documentation.
- [x] Run the full Rust and NixOS validation suites.

## Client PIN/UV interoperability

- [x] Route ClientPIN subcommands 0x06 and 0x09 per CTAP 2.2.
- [x] Add UV retry and browser-shaped UV token tests.
- [x] Log CTAP status codes for failed commands.
- [x] Run Rust and NixOS validation.

## Debug logging

- [x] Separate lifecycle, command, packet, and trace-level messages.
- [x] Use consistent key-value context and name ClientPIN subcommands.
- [x] Remove sensitive or misleading payload/write diagnostics.
- [x] Document log levels and validate the changes.

## ClientPIN token response interoperability

- [x] Return only the defined `pinUvAuthToken` field for token responses.
- [x] Add strict response-shape regression coverage.
- [x] Run Rust and NixOS validation.

## makeCredential PIN/UV authentication

- [x] Verify `pinUvAuthParam` over `clientDataHash` only.
- [x] Exercise token-authenticated makeCredential through the CTAP handler and VM.
- [x] Run Rust and NixOS validation.

## Credential listing and configuration CLI

- [x] Store and report credential registration and last-use timestamps.
- [x] Show bound PCR indices in `list-credentials`.
- [x] Move default PCR policy setting to `config set default-pcr-policy`.
- [x] Add `config show` for current persistent configuration.
- [x] Update tests and documentation, then run Rust and NixOS validation.

## Credential deletion and approval reuse

- [x] Add an end-to-end test for deleting a credential.
- [x] Explain why browser registration currently invokes polkit twice.
- [x] Reuse UV-token user presence for one operation in the same login session without weakening transaction or RP scoping.
- [x] Document the security constraints and validate the changes.

## CTAP 2.2 systematic audit

- [x] Create and maintain `docs/ctap2-compliance.md` from the normative specification.
- [x] Complete the ClientPIN wire-format, cryptography, permission, and retry audit.
- [x] Audit makeCredential and getAssertion.
- [x] Audit getInfo capability claims.
- [ ] Audit credential management and stateful continuation commands.
- [ ] Audit reset, selection, and unsupported commands.
- [ ] Audit CTAPHID framing, channels, cancellation, keepalive, and errors.
- [ ] Run final Rust and NixOS validation.
