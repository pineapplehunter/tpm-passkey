# CLI Refactor Plan — Unix Socket Management Channel

## Architecture

The daemon (`daemon` subcommand) opens a **Unix stream socket** at
`$store_dir/management.sock`.  Management subcommands connect to this socket,
send a CBOR/JSON request, and receive a response.  This keeps the daemon
as the single owner of TPM state and credential store — no file-level
locking concerns and no competing with the browser for hidraw access.

```
┌──────────────────────────┐     Unix socket      ┌──────────────────────────┐
│  management subcommand   │ ◄──────────────────► │   daemon (background)     │
│  (list-credentials, etc) │   CBOR/JSON msgs     │  • UHID event loop       │
│                          │                       │  • Unix socket server    │
│                          │                       │  • owns TPM + store      │
└──────────────────────────┘                       └──────────────────────────┘
```

## Protocol

Length-prefixed JSON messages over `SOCK_STREAM`:
```
[4 bytes: u32 BE payload length][payload bytes: JSON]
```

Request format (JSON object):
```json
{ "cmd": "list-credentials", "params": { ... } }
```

Response format:
```json
{ "ok": true, "result": { ... } }
{ "ok": false, "error": "message" }
```

## Subcommands

```
tpm-passkey <SUBCOMMAND> [options]

Subcommands (connect to daemon via Unix socket):
  list-credentials       Print credential ID, RP ID, and user name for each
                         credential owned by the current session user.
  update-passphrase      Prompt for old recovery passphrase, then new
                         passphrase twice, sends to daemon which rewraps
                         every credential unlocked by the old passphrase.
  update-pcr-reference   Prompt for recovery passphrase, sends to daemon
                         which re-signs PCR policy for every credential
                         using the credential's stored PCR selection.
  update-pcr-policy      Accept --pcr <N> (repeatable) and either
                         credential IDs (positional) or --all.  Prompts for
                         passphrase, sends to daemon which re-signs each
                         matching credential with the new PCR selection.
  set-default-pcr-policy  Accepts a list of PCR indices; writes to
                          $store_dir/default-pcr-policy.json so newly created
                          credentials use those PCRs.

Daemon subcommand (background, owns TPM/store):
  daemon                 Start the UHID FIDO2 daemon with management socket.
```

## Shared arguments (every management subcommand)
- `--store-dir <PATH>`   (default from store::DEV_STORE_DIR)

## `daemon`-only arguments
- `--uhid-path <PATH>`   (default: `/dev/uhid`)
- `--tpm-path <PATH>`    (default: `/dev/tpmrm0`)
- `--store-dir <PATH>`
- `--dry-run`

## Files to modify

| File | Change |
|------|--------|
| `src/management.rs` | New module: protocol types, server (`serve`), client (`send_request`) |
| `src/lib.rs` | Add `pub mod management` |
| `src/main.rs` | Replace `Config` struct with clap subcommand enum; daemon starts management server in bg thread; management subs connect and print response |
| `src/store.rs` | Add `default_pcr_policy_path`, `load_default_pcr_policy`, `save_default_pcr_policy` |
| `Cargo.toml` | Add `rpassword` for interactive passphrase prompts; add `serde_json` (or reuse serde via ciborium) |
