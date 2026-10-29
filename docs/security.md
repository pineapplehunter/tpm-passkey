# Security Model

This document defines the threat model, security objectives, assumptions, and known limitations of `tpm-passkey`.

The project is experimental. Unless explicitly identified as an implemented property, the requirements described in this document represent design objectives rather than verified security guarantees.

## System Model

`tpm-passkey` implements a virtual CTAP2 authenticator using the Linux UHID subsystem. A privileged daemon processes CTAPHID and CTAP2 requests, stores credential records in a local database, and delegates credential private-key operations to a TPM 2.0 device.

The daemon assumes a single-user machine. One daemon instance and credential
store serve one user, with no per-user namespaces, caller-UID checks, or
login-session binding. Multi-user isolation, fast user switching, and multi-seat
operation are unsupported. The goal is convenient TPM-bound passkey storage.
CTAP user presence is a GTK Allow/Deny acknowledgement, not host
re-authentication. Polkit authorizes the actual management/registration D-Bus
caller separately.

## Security-Relevant Entities

* **Relying Party (RP):** The remote service that registers a credential and verifies authentication assertions.
* **Client:** The browser or other CTAP client that communicates with the virtual authenticator.
* **Daemon:** The privileged `tpm-passkey-daemon` process that implements the virtual authenticator; it does not link GTK.
* **Approval Agent:** The unprivileged `tpm-passkey-approval-gtk` desktop process, trusted to report transaction-specific consent. Same-user compromise can subvert it.
* **Management CLI:** The unprivileged `tpm-passkey` process, which collects recovery phrases and requests daemon-side changes.
* **TPM:** The TPM 2.0 device that generates, protects, and uses credential private keys.
* **Credential Store:** The persistent database containing TPM object blobs, public-key material, credential metadata, policy information, and signature counters.
* **Session Manager:** `systemd-logind`, used to guard graphical-session eligibility and cancel pending consent on observed session loss/lock/change; it does not identify HID senders or credential owners.
* **Authorization Service:** polkit and its authentication agent, used for management privileges and group-gated approval-agent registration, not CTAP UP.
* **Device-Access Mechanism:** udev and `uaccess`, which grant access to the virtual HID device to the active user of the associated seat.
* **Platform Trust Chain:** The firmware, bootloader, kernel, and measured-boot components that determine relevant PCR values.

A PCR is a TPM state register and is not considered an independent actor.

## Adversary Model

### Multi-User Isolation Is Out of Scope

The application does not provide isolation between local credential users. Device,
system-bus/polkit policy and store permissions remain useful restrictions, but the daemon does
not determine which local user sent a HID request. Do not deploy it as a
shared-machine authenticator.

### Same-User Adversary

A same-user adversary controls a process running under the credential owner’s UID.

UHID reports do not identify their sending UID or process. The daemon cannot
distinguish an authorized browser from another process with device access.

A same-user adversary may therefore initiate CTAP operations. Transaction-specific user interaction is required to limit unauthorized use, but this does not provide protection after the user approves a misleading or insufficiently identified request.

### Privileged Adversary

A privileged adversary has administrative control over the running operating system.

This adversary may:

* Read or modify the credential database.
* Replace or modify the daemon.
* Access the TPM resource-manager device.
* Bypass desktop-authorization logic.
* Initiate arbitrary TPM commands permitted by the TPM hierarchy and object policies.
* Observe or modify passphrases entered through software controlled by the operating system.

The project does not claim to preserve user isolation, user acknowledgement, or authorization semantics against a live privileged adversary.

TPM object properties may continue to prevent extraction of credential private keys. However, private-key non-extractability does not imply that a privileged adversary cannot cause the TPM to use a key.

### Offline Storage Adversary

An offline storage adversary can read or modify the persistent credential store but cannot execute commands using the original TPM.

The design aims to prevent this adversary from extracting credential private keys and to detect unauthorized modification of security-sensitive records.

### Out-of-Scope Adversaries

The following are outside the primary threat model:

* Physical attacks against the TPM.
* TPM firmware compromise.
* Firmware or hardware supply-chain compromise.
* Kernel compromise that occurs before the daemon establishes its security state.
* Side-channel attacks against the TPM or host processor.
* Denial of service by a privileged adversary.

## Terminology

### Extractable

A credential private key is **extractable** when an adversary can reconstruct or export the raw private-key value for use outside the original TPM.

### Operationally Usable

A credential private key is **operationally usable** when an adversary can cause the TPM to produce a valid signature using that key, regardless of whether the raw private key can be extracted.

These properties are distinct. A TPM key may be non-extractable while remaining operationally usable by an adversary with sufficient authorization.

## Operating Modes

The intended design defines a base protection mechanism with optional, composable authorization factors.

### TPM-Bound Base

All credentials are generated by and bound to the TPM. The private key remains non-extractable and all cryptographic operations involving the private key are performed within the TPM.

This is the default for new credentials when no PCR selection is explicitly
configured. Such keys have no PCR policy and remain usable on the original TPM
across boot-state changes. This provides protection against key extraction but
does not prevent an adversary with sufficient access to the TPM and object blobs
from using the key. PCR binding is a separate, explicit opt-in.

### Authorization Factors

Additional authorization factors may be applied independently or in combination to strengthen credential protection.

#### PCR-Bound Authorization

The credential private key may be protected by a TPM authorization policy
associated with one or more explicitly selected PCR values. Enabling the default
selection requires configured recovery; creating a new bound credential also
requires unlocked recovery enrollment. Every newly created PCR-bound credential
has a recovery authority. Setting a phrase alone does not enable PCR binding.
Disabling the default affects only future registrations and does not relax or
retrofit existing credential policies.

PCRs represent measured platform state, including firmware, bootloader, kernel, and Secure Boot configuration. They do not, by themselves, attest to the integrity of all software components, including the daemon or root filesystem.

For systems using Secure Boot, it is strongly recommended to bind credentials to both:

* **PCR[1] (firmware measurements):** This PCR reflects firmware code and configuration. Binding to PCR[1] ensures that credentials are only usable when the platform firmware matches the enrolled state.
* **PCR[7] (Secure Boot policy):** This PCR reflects Secure Boot state and verification authorities (e.g., PK, KEK, db, dbx). Binding to PCR[7] ensures that credentials are only usable when Secure Boot is enabled and configured as expected.

Combining PCR[1] and PCR[7] provides stronger guarantees than using PCR[7] alone. PCR[7] ensures that Secure Boot policy has not changed, while PCR[1] helps ensure that the firmware itself has not been modified. This combination is commonly used in disk encryption systems (e.g., LUKS2 with TPM binding) to protect secrets against firmware tampering and Secure Boot policy changes.

However, several limitations must be considered:

* PCR values reflect measurements, not trust. An enrolled PCR state is only “known good” if it has been independently validated.
* Firmware updates, Secure Boot key changes, or bootloader updates will change PCR values and may render credentials unusable.
* PCR binding does not guarantee integrity of user-space components such as the daemon or applications unless additional mechanisms (e.g., measured boot with IMA or unified kernel images) are used.

An enrolled PCR value is treated as an authorized state. It is considered “known good” only when it has been independently validated against an expected platform configuration.

A recovery mechanism may be defined to authorize migration to a new accepted PCR state.

#### Passphrase-Based Authorization

Each recovery-enabled credential has a separate TPM recovery authority with an
independent random authorization value. The user-supplied phrase does not directly
become a TPM auth value: Argon2id derives an encryption key, and AES-256-GCM
protects the random authorization value. Associated data binds the ciphertext to
the credential ID, authority public blob, and `policyRef`.

The database stores salt, bounded KDF parameters, nonces, ciphertext, and TPM
object blobs, but no plaintext authorization value or derived encryption key.
The daemon configuration contains only an encrypted known unlock-check value.
A database copy permits offline phrase guessing, not immediate recovery use.

The recovery authority signs a new PCR approval via `PolicyAuthorize`; the
original registered passkey and its fixed TPM policy remain unchanged. Recovery
requires the original TPM, relevant blobs, and the phrase. See
[`credentials.md`](credentials.md) for the format and enrollment lifecycle.

#### Combined Authorization Policies

PCR-based and passphrase-based authorization mechanisms may be combined within a single TPM policy. For example, a credential may require both a valid PCR state and a correct passphrase, or may allow either condition through a policy branch.

The exact composition of these policies determines the effective security properties and recovery behavior of the credential.

## Security Objectives

### Private-Key Confidentiality

All credential private keys shall be generated by the TPM and shall remain non-extractable from the TPM under the assumed threat model.

Operations that require possession of a credential private key, including WebAuthn assertion signatures, shall be performed by the TPM.

The persistent credential store may contain TPM private and public object blobs. Disclosure of these blobs shall not reveal the raw credential private key without access to the originating TPM and satisfaction of the applicable TPM authorization policy.

Credential metadata is not necessarily confidential. Depending on the database format, disclosure may reveal:

* Relying-party identifiers.
* User names and display names.
* User handles.
* Credential identifiers.
* Public keys.
* Signature counters.
* Policy configuration and recovery metadata.

### Single-User Access Model

All stored credentials share one namespace. The daemon does not determine HID
caller UIDs, filter credentials by owner, or bind PIN tokens/credentials to login
sessions. Credential metadata has no local owner UID. Pending approval is cancelled
on observed session ineligibility; this is not per-user credential revocation.

Keep `hidraw` and store access restricted. The existing udev `uaccess` rule does
not constitute multi-user isolation: changing an ACL does not revoke an already
open descriptor. D-Bus management and registration authenticate their own actual
senders. The configured access group gates ordinary users; root is trusted and
controls the store regardless. Group members operate on the same credential
namespace, not separate stores.

### User Authorization

An unprivileged desktop agent registers its object path on the system bus. The
daemon uses the actual unique sender and bus-derived UID, never a caller-supplied
UID/name. Polkit gates registration, while logind independently checks graphical
eligibility. A user-service PID need not reside in the graphical session scope.
The helper checks that incoming requests originate from the current root-owned
daemon bus name. Root never accesses the user's display or session bus.

GTK Allow/Deny supplies acknowledgement only. It no longer provides the former
polkit/PAM host re-authentication assurance. The agent is not secure attention:
same-user malware can impersonate/compromise it or automate consent. The displayed
RP/account data is untrusted plain text, not independently verified web-origin
identity. Wayland may leave a dialog unfocused; automatic activation is not
promised. Neither session eligibility nor helper identity identifies the browser.

Authorization shall be associated with one specific CTAP transaction. Authorization results shall not be reused for unrelated requests unless the reuse semantics are explicitly defined and justified.

Host approval is user presence (UP), not CTAP built-in user verification (UV).
The authenticator does not advertise `uv` and does not issue built-in-UV tokens.
PIN/UV Auth Protocols 1 and 2 provide PIN verification once a PIN is configured;
only successful token authentication can set the authenticator-data UV bit.
PIN tokens are scoped by protocol, permissions, and RP ID. They do not cache UP:
a request requiring presence still needs a separate transaction-specific approval.
Presence consumes token permissions except the CTAP-defined `lbw` exception.

PIN verifier and retry state currently reside in SQLite, protected by a local
metadata MAC and PBKDF2. This is not equivalent to TPM private-key protection,
and does not meet CTAP 2.2 §6.5.1's PIN-storage assurance requirement. Offline
PIN guessing and rollback of this state remain security/compliance gaps.
Malformed or unverifiable PIN records now block credential/PIN operations with
`INTEGRITY_FAILURE`, rather than silently disabling PIN protection. Restoring
valid state and restarting repairs this without deleting credentials. Explicit
factory reset clears all credentials and PIN state atomically; ordinary operation
never automatically drops or regenerates an unreadable PIN record.

Cancellation, token expiry, and denied approval prevent authorization. Approval
has one 30-second absolute deadline, including system-bus setup and logind lookup.
Cancellation is checked every 20 ms; explicit remote dialog cancellation has a
further bounded cleanup allowance of at most 100 ms. Denial, timeout, cancellation,
missing helper/display, malformed replies or disconnection fail closed with no
fallback. A fresh request ID and connection binding prevent consent transfer or
replay. Session eligibility is rechecked before accepting Allow and during a
pending request. Observed loss cannot be undone by unlocking/re-registration for
that transaction. `LockedHint` depends on desktop cooperation; rapid unobserved
transitions are not a secure-attention guarantee. Local kernel calls and blocked
logging sinks are not preemptible; this is not a hard real-time guarantee.
Registration checks cancellation after TPM creation and before persistence;
reset checks before deletion. Cancellation racing an already-started SQLite
commit or TPM command cannot guarantee rollback/preemption.

### Management and Secret Transport

Management uses a separate system-bus API, with polkit checks against the actual
caller's unique bus name before processing mutations. Read, recovery and settings
operations have distinct actions. Group eligibility does not itself authorize
mutations: the deployment chooses own-password or administrator authentication,
without retained authorization. Existing recovery-phrase cryptographic checks
remain required; polkit cannot replace decryption knowledge.

Requests use bounded, write/grow/shrink-sealed anonymous memfds passed as Unix
FDs. The public operation must match the decoded request. Descriptors of the
wrong type, missing seals, excessive sizes and malformed/trailing input are
rejected. Seals are checked before taking the size snapshot. Secret bytes are
not serialized into D-Bus message bodies or included in errors/logs. Encoding uses
a fixed bounded zeroizing buffer; direct secret-field decoding uses guarded
scratch and field storage, including partial failures. This is best-effort
application-level erasure, not a guarantee that every library/allocator copy or
crash dump has been erased. FDs are closed promptly, but
sealed memfd pages cannot be overwritten and memory backing may be swapped or
retained by another holder. The bus broker handles these descriptors. This does
not hide secrets from a privileged monitor/broker, root, kernel compromise or
same-user process compromise; no end-to-end encryption claim is made.

The authenticator cannot independently verify the browser’s web origin. It receives an RP ID and client-data hash from the client platform and relies on the WebAuthn client and relying party to perform the corresponding origin validation.

### Persistent-State Integrity

Unauthorized modification of security-sensitive credential records should be detectable.

The authenticated record should include, at minimum:

* Credential ID.
* RP ID.
* User handle.
* TPM private and public blobs.
* Credential public key.
* TPM object attributes.
* PCR selection and policy digest.
* Authorization factors applied.
* Recovery-policy metadata.
* Password-KDF algorithm and parameters.
* Signature-counter state.

Integrity protection may be implemented using an HMAC or authenticated-encryption key whose use is restricted by the TPM.

Such protection does not provide integrity against a privileged adversary that is authorized to use the integrity key.

### Rollback Resistance

The current design does not provide rollback protection.

An adversary capable of restoring an older valid database may be able to:

* Restore a deleted credential.
* Revert a signature counter.
* Restore obsolete policy or recovery information.
* Undo credential revocation or rotation.

Rollback detection would require additional monotonic state, such as a TPM NV counter or another trusted version mechanism.

#### Current Mitigation Status

Rollback is not currently mitigated. The following mitigations are
available but not yet implemented:

- **TPM NV counter**: A monotonic NV counter could be incremented
  on each credential change. Before using a credential, the daemon
  would verify that the recorded counter value matches the TPM NV
  counter. An older database snapshot would have a stale counter
  value, making rollback detectable.
  - *Trade-off*: NV counters are one-time-writable (per boot for
    the TPM's limited NV index space) and add write latency.
    Counter exhaustion must be managed.
- **Database version table**: A monotonically increasing version
  number in a separate SQLite table, updated atomically with each
  credential change. This detects rollback within the database
  lifetime but not against a cloned database.
- **TPM-backed HMAC over credential metadata**: An HMAC over the
  credential record, keyed by a TPM-resident HMAC key (e.g., a
  `TPM2_PrimarySeal` key or an NV-indexed HMAC key). Each write
  includes a new HMAC that incorporates the prior HMAC value,
  forming a hash chain. An adversary reverting a record would
  need to recompute the chain.

These mitigations are deferred until the credential storage model
stabilizes and a concrete rollback threat profile is established.

### Availability

The system does not provide unconditional availability.

Credential use depends on the continued availability and consistency of:

* The original TPM and its hierarchy state.
* The TPM object blobs.
* The credential database.
* The required authorization factors (e.g., PCR state or passphrase).
* The session manager.
* The registered graphical approval agent and its display connection.
* Polkit for new registrations and management; its authentication agent when management policy requires authentication.
* The UHID and hidraw subsystems.

When PCR-bound authorization is used, changes to measured platform state may prevent normal credential use. Recovery is possible only if a recovery mechanism for the original credential key has been implemented and remains available.

When passphrase-based authorization is used, possession of the correct passphrase does not guarantee recovery if the TPM has been cleared, the credential record is corrupted, or the original TPM is unavailable.

In the TPM-bound base configuration without additional authorization factors, the credential is expected to remain usable while the original TPM, object blobs, and required TPM hierarchy remain available.

## Denial-of-Service Considerations

An unprivileged process with access to the virtual HID device may attempt to:

* Submit malformed or incomplete CTAPHID messages.
* Exhaust CTAPHID channels.
* Generate repeated authorization prompts.
* Hold the device open across session transitions.
* Cause excessive TPM operations.

The daemon should implement bounded request sizes, per-channel state limits, request timeouts, cancellation, prompt rate limiting, and limits on concurrent interactive operations.

## Current Implementation Status

The current source tree is experimental and does not yet satisfy all properties defined by this document.

Recovery now uses random, encrypted TPM authorization values and an Argon2id
wrapping key. The old plaintext-equivalent format is discarded by a new SQL
migration, not upgraded. This does not securely erase old stores or backups.
The enrollment wrapping key is retained in zeroizing worker memory after setup
or explicit unlock, and forgotten at restart. Policy changes always require
the phrase supplied in their own request. Passphrase rotation rewraps all slots
and configuration atomically but does not prevent reuse of older snapshots.

Before production security claims are made, at least the following issues must be resolved:
* Security-sensitive credential metadata must receive integrity protection.
* Approval reuse and stale authorization state must be eliminated or formally justified.
* Rollback behavior must be documented and, where required, mitigated. (Documented in § Rollback Resistance; mitigation deferred.)

No FIDO certification, production hardening, or resistance to a live privileged adversary is currently claimed.
