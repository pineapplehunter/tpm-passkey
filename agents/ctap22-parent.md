# CTAP normative audit

Source: CTAP 2.2 Proposed Standard, 2025-07-14, linked from AGENTS.md.
Baseline recovery/schema changes were committed as 47d0b0a before this audit.
The previous compliance checklist's "complete" labels are not evidence of
conformance; this pass rechecks normative text and adds independent regressions.

## Encoding (§8, §8.1–8.2)

- Use ciborium-ll for CBOR headers, then validate CTAP canonical restrictions:
  shortest integers/lengths, definite containers, sorted unique map keys, no
  tags, one complete object, and no more than four container nesting levels.
- Do not validate by round-trip encoding: CTAP permits all original float widths.
- Preserve the exact canonical encoded CM subcommand parameters when checking
  HMACs; a general encoder can shorten otherwise-valid floats in unknown fields.
- Honor the advertised 1200-byte command size with REQUEST_TOO_LARGE and share
  the size constant with GetInfo. Unknown canonical fields remain ignorable.
- Distinguish an unexpected top-level type from malformed CBOR.

Other command-family audits run independently; integrate in logical commits
with tests, then review cross-family contracts and the full VM test.

Important version boundary (§9): advertising FIDO_2_2 requires hmac-secret and,
when UV is supported, credProtect (unless every key is implicitly level 3).
Do not advertise 2.2 just because the current profile was audited against its
specification. Missing mandatory features must be implemented or explicitly
reported as remaining work; certification is not claimed.
