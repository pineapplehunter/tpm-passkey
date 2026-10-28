# Controlled approval integration

Reviewed and integrated subagent e0bf15f6-fd16-4088-99a4-8e2a0c057c41's selected
approval.rs, polkit.rs, systemd_logind.rs changes; dependencies added with cargo
add/feature updates. No TPM context moves or migration changes.

All external-service waits share one 30-second deadline/cancel scope: Tokio Unix
connect (avoids zbus's hidden spawn_blocking connector), bus authentication,
logind listing/properties, polkit call, terminal fallback. The terminal uses an
independent nonblocking FD for writes/reads; no blocked stdout pipe/read_line.
Cancel polling is 20 ms; same-connection/ID polkit cleanup is capped at 100 ms.
Legacy UserApproval fakes compile unchanged; custom blocking implementations must
override approve_controlled to interrupt pending work. Only Approved grants UP.

Parent wiring propagates explicit outcomes. Normative recheck uncovered an
important status distinction: CTAP 2.2 §§6.6/6.9 require USER_ACTION_TIMEOUT=0x2f
for reset/selection, while §§6.1.2/6.2.2 UP and zero-length-auth selection use
OPERATION_DENIED. CANCEL uses KEEPALIVE_CANCEL=0x2d, never a direct HID response.
Source refetched via web (mvrutgis4nlbk6). One ErrorStatus variant was added.

Tests cover pending shared work/drop, actual stalled bus handshake, partial/empty
PTY input, noninteractive denial, command-specific outcome mapping, and a CTAPHID
provider that cannot finish without real cancellation. That transport test also
proves the worker accepts a new GetInfo afterwards. Full local run: 106 tests.

The VM regression freezes real logind then polkit processes, cancels selection
over UHID, and checks the worker is free while each process remains frozen.
For polkit, busctl monitor readiness uses sd_notify and JSON records verify the
CheckAuthorization/CancelCheckAuthorization connection sender and ID match.
The test restores stopped services in finally blocks. No real desktop GUI agent
interaction or pathological kernel/logging-sink preemption is claimed.

Passed nix fmt, cargo check/test (106), daemon dry run, and full nix flake check
(task 2). Both software-TPM VM checks passed. The frozen-logind and frozen-polkit
cancellation scripts completed in 0.62/0.56 seconds respectively, including
initialization and post-cancel GetInfo; cancellation itself was under one second.
Evidence: /tmp/ctap22-approval-flake.log. Only host-system checks were built.
