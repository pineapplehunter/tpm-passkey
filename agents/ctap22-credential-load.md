# Fail-closed credential loading

Found three related failure modes after 42ad996: credential-load errors became
an empty in-memory store (a later full save could delete old keys); HMAC key
read failures returned unverified credentials; full saves wrote NULL MACs when
MAC computation/key access failed. Missing primary slots also vanished through
an inner join rather than failing as malformed records.

Now loads require the existing key and metadata MAC, and preserve load errors.
A sticky credential-load failure flag blocks credential/PIN commands. Production
registration, assertion, and non-continuation CM operations reload trusted state;
a failed reload keeps the prior snapshot but never authorizes use or a save.
Snapshots require a MAC key before deleting any rows in their transaction.
Primary-slot lookup is a left join, so missing keys cause an error. Explicit
atomic reset can still remove corrupt/unloaded records; repair + restart can
recover without changing credentials. No migrations/retrofits.

Tests cover bad/missing MAC/key, missing primary slots, cached save failure,
startup/load failure gating, live registration/assertion reload, and repair.
Extended VM fault injection covers both live corruption and startup failure,
verifying restored metadata/keyslots exactly match the original snapshot.

Validated nix fmt, cargo check and cargo test (109), including the final CM
reload wiring. After the user-requested NixOS test decomposition, full flake
check passed (task 4), including standalone state-integrity corruption/repair
and real signing after repair. All twelve host-system VM checks passed.
Evidence: /tmp/nixos-split-final.log.

Remaining observation: assertion candidates are reversed in-memory, but loading
currently orders by RP/credential ID rather than creation time. Newest-first
ordering across reloads still needs a focused follow-up. Metadata MAC protection
also remains incomplete and is not TPM-bound or rollback-resistant.
