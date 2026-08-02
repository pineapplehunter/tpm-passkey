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
