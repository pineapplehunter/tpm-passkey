# CTAP 2.2 normative audit and implementation

Baseline: commit 47d0b0a. Preserve TPM-backed signing, encrypted recovery,
single-user assumptions, and the current schema. User requests complete CTAP2
compliance and logical commits per family of fixes (parent integrates/commits).

Normative source (read the relevant sections, do not rely on existing checklist):
https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html
The web fetch tool can retrieve this URL even if direct urllib returns 403.
Enable web tools if needed, fetch readable content and page the stored result.

Audit the currently advertised USB/ES256/PIN/UV/discoverable-credential profile.
Implement normative MUST/SHALL behavior and errors, supported optional-feature
requirements, capability consistency, and security-sensitive SHOULDs. Do not
add every optional extension just to claim completeness. Do not claim FIDO
certification. Report explicitly any mandatory gap that cannot be resolved.

Each job has an isolated copy. Execute ONLY your assigned job. Do not commit.
Keep changes narrow, add regression tests in your own new module, and record
normative references and remaining limitations in agents/ctap22-JOB.md. Avoid
editing the shared docs/ctap2-compliance.md, protocol.rs, cbor_codec.rs, ctaphid.rs,
get_info_response, and global handle_cbor dispatch unless your job explicitly
owns them. Shared helper/API changes should be documented in the report.
Run nix fmt, cargo check and cargo test in the flake dev shell when feasible.
Read project instructions. Write /run/pi-subagent/response.md with findings,
changed paths, verification, and recommended logical commit groups.

## Credentials job
Own authenticatorMakeCredential, authenticatorGetAssertion, GetNextAssertion,
authenticatorData and their entity/option/descriptor validation helpers in
src/ctap2.rs, and src/ctap2/authenticator_data.rs. Read sections 6.1-6.3,
relevant 9/12 extension rules and common state rules. Add tests in
src/ctap2/credential_compliance_tests.rs (wire the module in ctap2.rs).
Do not edit PIN/token internals; report needed contract fixes to parent.
In particular verify all success/error flags, UP/UV semantics, allow/exclude
lists, privacy, limits, discovery ordering, persistent counters and rollback
on persistence failure, unsupported options/extensions, and interruptions.

## PIN job
Own ClientPIN, PIN/UV Auth Protocols, token issuance, validation, expiration,
permission consumption, and retry state in src/ctap2.rs. Read ALL section 6.5
including protocol and token state-machine sections and cross-references.
Add tests in src/ctap2/pin_compliance_tests.rs (wire module in ctap2.rs).
Do not edit make/get handler orchestration or global dispatch; report any
needed integration changes to parent. Audit which protocol versions are
required for advertised FIDO_2_0/FIDO_2_1/possible FIDO_2_2 and fix advertising
contracts through a clear report if owned by another job.

## Profile job
Own get_info_response, reset, selection, credential management, unsupported
commands, and profile/extension advertisement in src/ctap2.rs. Read sections
6.4, 6.6 onward, mandatory/optional extension requirements and feature options,
and relevant common state rules. Read enough of remaining optional commands
to justify rejecting them without advertising their features. Add tests in
src/ctap2/profile_compliance_tests.rs (wire module in ctap2.rs).
Determine whether FIDO_2_2 may honestly be advertised and report requirements
rather than adding a version string without implementation. Specifically
check min/max fields, feature/pinUvAuthProtocol consistency, CM authentication,
continuation lifetime and token binding, discoverability, reset persistence,
no-display restrictions and whether credProps is an authenticator extension.

Parent owns canonical CBOR/message encoding, common transport/status behavior,
CTAPHID, cross-job integration, independent specification coverage and final
checklist/VM verification. If a serious bug is outside your scope, report it
with exact normative reference and proposed fix, but do not edit that area.
