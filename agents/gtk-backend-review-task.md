# Final backend boundary review (read-only)

Implementation decisions: agents/gtk-implementation.md and original task updated
with three binaries, automatic eligible-session identity, group/polkit management,
sealed-FD secrets. Backend has now been integrated in this snapshot.

Review current src/bus.rs, src/polkit.rs, src/systemd_logind.rs, approval/CTAP
wiring and management dispatch against identity/authentication, pending request
binding, logind observation races, cancellation/deadline/lifecycle invariants.
Do not edit or commit. Do not claim baseline code is final without reading it.

A separate previous review found issues now fixed in this snapshot: polkit action
XML now installed through daemon in systemPackages; authenticated Cancel IDs are
tombstoned even before begin; FD seals checked before size; request encoding uses
fixed zeroizing buffer and externally-tagged enum with zeroizing secret fields
plus guarded decoder scratch (avoid Serde adjacent-tag buffering); frontend
terminal/Unicode controls escaped. Registration periodically retries after session
revocation and skips pending GUI consent. Session policy rejects multiple local
graphical sessions even when one is inactive because user-service PID isn't bound
to a graphical scope. Check concrete remaining bugs, not speculative abstractions.

Parent whole-workspace check/tests and six private-bus backend tests passed.
Full Nix flake check including 15 VM scenarios is running separately. No need to
repeat heavyweight builds: disk space is tight; target directories are not copied.
You can run tiny targeted tests/reproducers if needed but prefer source traces.
Report file/line, real trigger, impact and minimal fix; checked assumptions and
limits. If none found, say so without claiming full security/conformance.
