# NixOS tests

Each test directory contains `default.nix`, its `reason`, and any case-specific
assets. Each is a separate `nixosTest` with a fresh VM/state directory; no case
requires another case to have run first. The root `default.nix` registers them.

| Directory / check suffix | Purpose |
| --- | --- |
| `management` | CLI defaults, columns, registration/signing smoke |
| `management-access` | Unprivileged callers, group/polkit policy, sealed FD validation |
| `ctap-transport` | HID fragmentation, GetInfo, unsupported commands |
| `ctap-credentials` | MakeCredential/GetAssertion, PIN 1/2, flags/signatures |
| `credential-management` | PIN-authenticated enumeration/update/continuation |
| `pin-management` | libfido2 PIN setup/change/storage/deletion |
| `factory-reset` | Credential invalidation and fresh PIN setup after reset |
| `state-integrity` | Corrupt state, fail-closed loading, backup repair |
| `approval-cancel` | Stalled logind/dialog cancellation and worker recovery |
| `approval-lifecycle` | Fresh decisions, missing helper, lock and restart behavior |
| `gtk-approval` | Real unprivileged GTK dialog and Escape denial on headless X11 |
| `optional-pcr` | Opt-in binding, no retrofit, future-only disable |
| `signing-sessions` | Repeated policy signing without TPM handle exhaustion |
| `recovery-rotation` | Multi-key phrase rotation, PCR update, token accounting |
| `recovery-reboot` | Changed boot PCRs, persistent keys, explicit re-unlock |

Shared files stay here:

- `machine.nix`: software TPM, daemon package, user, polkit and tools.
- `common.nix`: test constructor; requires a reason and prints it in the log.
- `approval-options.nix`: pure module-evaluation check for default enablement,
  systemd startup, opt-out, XDG autostart and manual startup. Protocol VMs
  explicitly disable automatic startup and select their own test agent.
- `driver.py`: bounded login/startup, management/expect and recovery helpers.
- `register.py`, `assert.py`: credential fixture creation and signature checks.
- `agent.py`: **test-only** auto-answering agent; controls a TTY session and
  advertises a graphical type to exercise the real eligibility checks.
- `tpm_test_bus.py`: sealed-FD management transport and agent readiness helpers.

Protocol fixtures are not proof of real desktop UX. The GTK smoke test runs the
actual GUI on headless X11, not manual Firefox/Wayland flows. Session activation,
lock cooperation and unfocused-window usability need target-desktop verification.

Run one test (adjust the system as needed):

```sh
nix build --no-link -L .#checks.x86_64-linux.nixos-state-integrity
```

Run the complete suite:

```sh
nix flake check -L
```
