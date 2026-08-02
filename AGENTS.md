# Agent Guidance

## References

- Product/status: `README.md`
- Architecture and TPM command-channel constraint: `docs/architecture.md`
- Threat model: `docs/security.md`
- Storage model: `docs/credentials.md`, `migrations/`
- CTAP 2.2: https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html
- Build/dev environment: `flake.nix`; CI: `.github/workflows/ci.yml`
- Current behavior and support: source and tests

## Workflow

- Run flake-provided tools with `nix develop --quiet -c`.
- After Rust changes, run `nix fmt`, `cargo check`, and `cargo test` in the dev shell.
- Validate flake changes with `nix flake check`.
- Dry run: `cargo run -- daemon --dry-run`.
- Prefer `sqlx::query!` over `query`.
- Never edit an existing migration; add one.
- Keep small temporary task notes in `agents/`.

Firefox/Linux is the first browser target. No GUI is planned.
