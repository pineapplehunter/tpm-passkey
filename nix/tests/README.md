# NixOS tests

Each test directory contains a `README.md` with its name and a short explanation
of what it checks, a `default.nix` declaring the complete NixOS test derivation,
and any case-specific assets. Every derivation imports `../machine.nix` directly
for the common NixOS configuration. Shared Python helpers are installed through
`extraPythonPackages`; each script imports `TestEnv` and explicitly starts its VM
fixture.
Each has a fresh VM/state directory; no case requires another case to have run
first. The root `default.nix` registers them.
Every enrollment scenario explicitly completes mandatory migration setup (the
upgrade scenario first verifies that enrollment without setup fails). Transport-
only discovery and approval tests that do not enroll need no migration key.

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
| `approval-cancel` | Dialog cancellation and worker restart |
| `approval-lifecycle` | Fresh decisions and missing helper behavior |
| `gtk-approval` | Real unprivileged GTK dialog and Escape denial on headless X11 |
| `migration-rebind` | swtpm PolicyAuthorize baseline, passphrase rotation, disable/enable/rebind through serialized management |
| `migration-reboot` | Persist a passkey and migration authority through reboot, then rebind changed PCR state |
| `migration-upgrade` | Destructive legacy-format upgrade, exact PIN retention, mandatory fresh setup |
| `signing-sessions` | Repeated policy signing without TPM handle exhaustion |


Shared files stay here:

- `machine.nix`: software TPM, daemon package, user, polkit and tools.
- `approval-options.nix`: pure module-evaluation check for default enablement,
  systemd startup, opt-out, XDG autostart and manual startup. Protocol VMs
  explicitly disable automatic startup and select their own test agent.
- `python-package.nix`, `python/`: importable test library. `tpm_passkey_test.TestEnv`
  provides bounded login/startup and management helpers; `tpm_test_bus` provides
  the guest-side sealed-FD transport and agent readiness helpers. The package is
  installed in both the test driver and the guest Python environment.
- `register.py`, `assert.py`: credential fixture creation and signature checks.
- `agent.py`: **test-only** auto-answering agent with a simulated desktop session.

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
