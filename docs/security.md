# Security Model

This document defines the threat model, security objectives, assumptions, and known limitations of `linux-tpm-fido2`.

The project is experimental. Unless explicitly identified as an implemented property, the requirements described in this document represent design objectives rather than verified security guarantees.

## System Model

`linux-tpm-fido2` implements a virtual CTAP2 authenticator using the Linux UHID subsystem. A privileged daemon processes CTAPHID and CTAP2 requests, stores credential records in a local database, and delegates credential private-key operations to a TPM 2.0 device.

The daemon assumes a single-user machine. One daemon instance and credential
store serve one user, with no per-user namespaces, caller-UID checks, or
login-session binding. Multi-user isolation, fast user switching, and multi-seat
operation are unsupported. The goal is convenient TPM-bound passkey storage.
Desktop authentication is requested through polkit.

## Security-Relevant Entities

* **Relying Party (RP):** The remote service that registers a credential and verifies authentication assertions.
* **Client:** The browser or other CTAP client that communicates with the virtual authenticator.
* **Daemon:** The privileged `linux-tpm-fido2` process that implements the virtual authenticator.
* **TPM:** The TPM 2.0 device that generates, protects, and uses credential private keys.
* **Credential Store:** The persistent database containing TPM object blobs, public-key material, credential metadata, policy information, and signature counters.
* **Session Manager:** `systemd-logind`, used only to find a desktop subject for routing polkit prompts, not to attribute requests or authorize credential access.
* **Authorization Service:** polkit and the graphical polkit authentication agent.
* **Device-Access Mechanism:** udev and `uaccess`, which grant access to the virtual HID device to the active user of the associated seat.
* **Platform Trust Chain:** The firmware, bootloader, kernel, and measured-boot components that determine relevant PCR values.

A PCR is a TPM state register and is not considered an independent actor.

## Adversary Model

### Multi-User Isolation Is Out of Scope

The application does not provide isolation between local users. Device, socket,
and store permissions remain useful access restrictions, but the daemon does
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

In this base configuration, no additional authorization factors are required beyond those inherent to the TPM object. This provides protection against key extraction but does not prevent an adversary with sufficient access to the TPM from using the key.

### Authorization Factors

Additional authorization factors may be applied independently or in combination to strengthen credential protection.

#### PCR-Bound Authorization

The credential private key may be protected by a TPM authorization policy associated with one or more enrolled PCR values.

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

All stored credentials share one namespace. The daemon does not check caller
UIDs, filter credentials by owner, bind CTAP state to login sessions, or revoke
access on session switches. Credential metadata has no local owner UID or
owner-dependent compatibility format.

Keep the `hidraw` device, management socket, and store access restricted.
The existing udev `uaccess` rule and root-only management socket remain, but do
not constitute a supported multi-user isolation model. In particular, changing
an ACL does not revoke an already-open file descriptor.

### User Authorization

Interactive authorization is routed to the active desktop's polkit agent. This
routing does not identify the sender of the HID request or establish credential
ownership.

A successful polkit operation establishes that the session user satisfied the configured polkit policy. Polkit authentication is not equivalent to an arbitrary graphical Allow/Deny acknowledgement.

Authorization shall be associated with one specific CTAP transaction. Authorization results shall not be reused for unrelated requests unless the reuse semantics are explicitly defined and justified.

The CTAP-defined user-presence state of a UV-issued `pinUvAuthToken` is the only current reuse. The UV approval names the requested RP ID, and cached presence may authorize one immediately following token-authenticated operation only when all of these remain true:

* The token HMAC is valid and has the required permission.
* The token's permissions RP ID matches the operation.
* No more than 30 seconds have elapsed since UV approval.
* Cached presence has not already been consumed.

The operation clears cached presence and all token permissions except the CTAP-defined `lbw` exception. PIN-issued tokens do not carry cached user presence and therefore still require a separate presence approval. This avoids a second polkit prompt for the built-in-UV browser flow without turning approval into a general same-user or time-based authorization grant.

Cancellation, token expiry, and denied approval prevent authorization. Session
termination and switching are not tracked. If polkit is unavailable, the existing
terminal approval fallback remains; it requires an explicit affirmative answer.

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
* The polkit service and graphical authentication agent.
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
