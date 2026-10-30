# Independent security audit

Audit the current tpm-passkey working tree, including the recent CTAP compliance corrections. This is a READ-ONLY review: do not change project files or commit. You may create scratch reproductions under /tmp and run targeted tools/tests in the Nix development environment. Write the final report to /run/pi-subagent/response.md.

Read AGENTS.md, docs/security.md, docs/architecture.md, docs/credentials.md, docs/dbus.md, docs/ctap2-compliance.md and applicable source/tests before drawing conclusions. Focus on concrete exploitable bugs and broken fail-closed behavior, not speculative hardening or certification claims.

Priorities:
1. CTAP PIN/token state: retry persistence and write failures, key-agreement lifecycle, token permissions/RP binding/expiry, cancellation, reset, continuation invalidation, and recent changes in src/ctap2.rs and src/ctaphid.rs.
2. Persistence/crypto: credential and configuration integrity boundaries, malformed/partial rows, missing keys, migration envelope binding, unsafe trust upgrades and rollback implications.
3. System-bus/approval/management boundaries: unique-sender authorization, sealed memfd validation, deadlines, cancellation/disconnection, secret/error/log exposure, mutation serialization and TPM-worker ownership.

Distinguish attacker capabilities (unprivileged same-user, other user, database-only writer, privileged host) and separate newly discovered issues from already documented limitations: colocated MAC key, incomplete record MAC, PIN storage not TPM-equivalent, store rollback, and lack of secure attention are already known. Do not simply repackage those as new vulnerabilities. Trace suspicious behavior through callers and persistence paths before reporting it.

For each finding provide severity, project-relative file and line references, prerequisite/attacker capability, triggering sequence or runnable reproduction, observed versus intended behavior, impact, and a minimal proposed correction. Mark hypotheses unverified. Report checks performed, tests run, areas not examined, and important assumptions. If no new concrete findings, say so without claiming the project is secure. Verify source files are unchanged at the end. Do not apply fixes: parent/user will review findings first.
