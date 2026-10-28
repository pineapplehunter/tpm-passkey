# Client-only credProps is not an authenticator extension

Source: WebAuthn Level 3 §10.1.3 (credProps); the normative table explicitly says
client registration extension, with no authenticator input, processing or output.
https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension
Refetched source evidence: mvrt9t2sv9f08f. CTAP 2.2 extension list has no credProps.

Removed credProps from GetInfo and signed authenticator data. No authenticator
extensions are currently implemented, so GetInfo omits key 2 rather than emitting
an empty list. Unknown input extensions are ignored, without validating their
private payload shapes or setting ED/output. The overall extensions value must
still be a map. Existing credentials, policies, and databases are unchanged.

Updated tests: unknown-input acceptance, omitted capability, and real TPM
registration carrying a client-only input but no signed output/ED flag.
Passed: nix fmt, cargo check, cargo test (92). The updated VM assertions will
be run with the next full flake check after the PIN-state loading fix.
Follow-up: that full check passed on 2026-10-28 (new-queue task 0), including
registration with client-only inputs and no authenticator extension output.
