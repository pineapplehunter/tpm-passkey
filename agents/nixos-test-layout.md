# Focused NixOS test layout

User request: test subdirectories under nix/tests, each with a NixOS test,
its reason in the Nix source, and case-related assets. Shared configuration
and genuinely common assets remain directly under nix/tests.

Replaced the two broad top-level VM modules with twelve independent checks:
management, ctap-transport, ctap-credentials, credential-management,
pin-management, factory-reset, state-integrity, approval-cancel, optional-pcr,
signing-sessions, recovery-rotation, recovery-reboot.

Each directory has default.nix with a required reason. common.nix supplies
machine.nix and driver.py, and prints the reason. Shared register/assert fixture
scripts stay at the root. Each VM starts fresh; no test is a prerequisite for
another. Recovery rotation uses two keys, and session exhaustion has its own
PCR-bound signing test. Credential management now exercises successful RP and
credential continuations with three credentials across two RPs. Reset and PIN
CLI management have separate cases.

The shared expect helper checks child exit status and has a bounded timeout;
login/startup waits are bounded too. The flake module only registers cases.
See nix/tests/README.md for the index and focused nix build commands.

The immediately preceding credential-load fix (db5d19a, 109 local tests) will
also receive VM coverage in the standalone state-integrity case.
The first full check (task 3) exposed the state fault fixture exceeding systemd's
five-start rate limit; seven cases completed successfully before fail-fast stopped
the remaining builds. The fixture now resets that counter before intentional
restarts and waits for worker readiness. Production service limits are unchanged.
The registry was also moved into nix/tests/default.nix. The full retry passed
(task 4, nix flake check -L --keep-going): all twelve x86_64-linux VM checks and
treefmt passed. Seven earlier successful derivations were reused; the remaining
five completed in 19–37 seconds each. Python assets also passed AST parsing.
Evidence: /tmp/nixos-split-first.log and /tmp/nixos-split-final.log.
