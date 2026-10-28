## Assessment

The proposed construction should **not** be implemented as written:

* A PCR digest is public and predictable, so `hash(PCR)` is not a suitable encryption key.
* `hash(P_recovery)` permits inexpensive passphrase guessing; use Argon2id with a unique salt and calibrated parameters. ([RFC Editor][1])
* The TPM does not normally decrypt `K_sign` and return it to the daemon. It loads a protected private object and performs `TPM2_Sign` internally. ([TPM2 Tools][2])
* Recovering a reusable `P_sign` into daemon memory weakens PCR enforcement: once captured, it could authorize future signatures without satisfying the PCR policy.
* A direct `PolicyOR(PCR, passphrase)` policy can provide two authorization branches, but changing the expected PCR digest would normally change the object policy. The registered WebAuthn key cannot then simply be recreated. `PolicyAuthorize` is specifically intended to permit mutable policies while retaining the original TPM object. ([TPM2 Tools][3])

I assume recovery means **authorizing a new PCR state on the same TPM**, not exporting the credential or migrating it to another TPM.

## Recommended construction

Remove `P_sign`. Introduce a dedicated recovery policy-authority key:

```text
K_sign      TPM-resident WebAuthn signing key
K_policy    TPM-resident policy-authority signing key
P_recovery  Passphrase authorizing K_policy
PCR_i       Currently approved platform state
D_i         TPM policy digest for PCR_i
R           Credential-specific policyRef
S_i         Signature by K_policy over D_i and R
```

The fixed authorization policy of `K_sign` is conceptually:

```text
PolicyAuthorize(Name(K_policy), R)
    AND
PolicyCommandCode(TPM2_CC_Sign)
```

`PolicyAuthorize` allows the PCR portion of the policy to change without changing `K_sign` or its public key. ([TPM2 Tools][4])

### Normal signing

```text
PolicyPCR(PCR_current)
    ↓
produce policy digest D_current
    ↓
verify S_i using public K_policy
    ↓
PolicyAuthorize(D_current, R, verification_ticket)
    ↓
PolicyCommandCode(TPM2_CC_Sign)
    ↓
TPM2_Sign(K_sign, M)
    ↓
Result
```

The TPM, rather than the daemon, determines whether the current PCR values satisfy the policy. `PolicyPCR` is explicitly intended for PCR-bound authorization and can be combined with `PolicyAuthorize`. ([TPM2 Tools][5])

### Recovery and PCR update

```text
P_recovery
    ↓
Argon2id(P_recovery, salt, parameters)
    ↓
authorize TPM-resident K_policy
    ↓
construct D_new for PCR_new
    ↓
S_new = TPM2_Sign(K_policy, D_new || R)
    ↓
test the new policy
    ↓
atomically replace {D_old, S_old} with {D_new, S_new}
```

The recovery passphrase does not directly authorize `K_sign`. It authorizes the creation of a new approved PCR policy. Normal signing then proceeds through the PCR path.

### Important binding

Use a credential-specific `policyRef`, for example:

```text
R = Hash(
    "tpm-passkey/pcr-policy/v1"
    || credential_uuid
    || owner_uid
)
```

Without a unique `policyRef`, a signed policy created for one credential could potentially be reused with another credential that trusts the same policy-authority key.

A single `K_policy` per Linux user is reasonable. The consequence is that compromise of that user’s recovery passphrase permits PCR-policy updates for all credentials belonging to that user.

## Implementation To-Do List

### 1. TPM policy design

* [x] Remove the encrypted or sealed `P_sign` design — using `PolicyAuthorize` with `K_policy` instead.
* [x] Define the exact policy digest construction — `PolicyPCR` → `PolicyAuthorize` → `PolicyCommandCode(Sign)`.
* [x] Add `PolicyPCR` for the configured PCR bank and indexes — PCR[7] SHA-256.
* [x] Add `PolicyAuthorize` using the recovery policy-authority key.
* [x] Add `PolicyCommandCode(TPM2_CC_Sign)`.
* [x] Ensure `K_sign` cannot also be authorized through an empty `authValue` — `userWithAuth=false` when policy is set.
* [x] Set `userWithAuth` consistently with the intended policy-only authorization.
* [x] Verify all policy calculations against real TPM sessions — NixOS test passes register+assert+loop+reboot+assert.

### 2. Recovery policy-authority key

* [x] Create a credential-scoped TPM signing key, `K_policy`, protected by the recovery-derived auth value. (finished 26-07-16)
* [x] Generate it before creating credentials that reference its TPM Name.
* [x] Store its public blob, private blob, TPM Name, and parent information.
* [x] Configure it only for policy-authorization signatures — ECDSA, no encryption/decryption attrs.
* [x] Protect it using an authorization value derived from `P_recovery`. (finished 26-07-16)
* [x] Do not set `noDA` unless bypassing TPM dictionary-attack protection is intentional — `noDA` is not set.
* [x] Restrict access to `K_policy` to the credential owner's active session — TPM auth value matching PBKDF2 output.

### 3. Recovery-passphrase processing

* [ ] Derive the TPM authorization value using Argon2id. PBKDF2 remains in use pending an Argon2 dependency and parameter calibration.
* [x] Generate a cryptographically random salt per policy-authority key (32 bytes via `getrandom`).
* [x] Store the salt and KDF parameters in the database — salt, hash stored in `credential_tokens` table.
* [ ] Calibrate memory and time costs on supported hardware.
* [x] Use a fixed-length derived authorization value accepted by the TPM (32-byte PBKDF2-SHA-256 output).
* [x] Zero temporary passphrase and derived-key buffers where practical.
* [ ] Use a salted/encrypted TPM authorization session when supplying sensitive authorization data.
* [x] Keep the CTAP PIN, login password, and recovery passphrase logically separate — distinct env var, salt, and hash.

### 4. Credential creation

* [x] Generate a unique credential UUID before constructing the TPM policy. (finished 26-07-16)
* [x] Derive the credential-specific `policyRef` — SHA-256("tpm-passkey/pcr-policy/v1" || UUID || UID).
* [x] Read and record the configured PCR selection ("sha256:7").
* [x] Construct the initial `PolicyPCR` digest via trial session.
* [x] Authorize the initial digest using `K_policy` — signs `SHA-256(pcrPolicyDigest || policyRef)` per TPM spec.
* [x] Create `K_sign` with the fixed `PolicyAuthorize`-based policy. (finished 26-07-16)
* [x] Store the approved-policy package with the credential. (finished 26-07-16)
* [x] Test signing through the complete policy before committing the credential — trial PolicyAuthorize + PolicyCommandCode + PolicyGetDigest.
* [x] Abort credential creation if any policy step fails — `?` operator propagates errors to `make_credential`.

### 5. Normal signing path

* [x] Start a fresh TPM policy session for each assertion. (finished 26-07-16)
* [x] Execute `PolicyPCR` using current TPM PCR values. (finished 26-07-16)
* [x] Load the stored approved-policy digest and signature. (finished 26-07-16)
* [x] Verify the policy signature through the TPM and obtain a verification ticket — passes `SHA-256(approvedPolicy || policyRef)` to `verify_signature`.
* [x] Execute `PolicyAuthorize` — uses the actual ticket from `verify_signature`, not a self-computed one.
* [x] Execute `PolicyCommandCode(TPM2_CC_Sign)`. (finished 26-07-16)
* [x] Sign using the original `K_sign` — via `execute_with_session(PolicySession, context.sign(...))`.
* [x] Flush all transient sessions and objects after completion — `PolicySessionGuard` and `ObjectHandleGuard` clean failed policy paths as well as successful signing.
* [x] Return an authorization error when PCR values do not match — TPM returns `TPM_RC_VALUE` on PCR mismatch.
* [x] Never fall back automatically to recovery-passphrase authorization during browser authentication.

### 6. PCR update operation

* [x] Expose PCR updating through the CLI (`--update-pcr-policy` / `main.rs`).
* [x] Require explicit user selection of the credentials to update — management commands require a hex credential ID; `--list-credentials` enumerates available IDs.
* [x] Display the old and proposed PCR selections and digests — `--update-pcr-policy` prints both policy packages before persistence.
* [x] Require the recovery passphrase (`TPM_PASSKEY_RECOVERY_PASSPHRASE` env var).
* [ ] Revalidate the active user session before and after passphrase entry.
* [x] Read the proposed PCR values directly from the TPM (`tpm.rs:update_authorized_policy`).
* [x] Construct the new policy digest (`tpm.rs:update_authorized_policy`).
* [x] Sign the new policy using `K_policy` (`tpm.rs:update_authorized_policy`).
* [x] Test the new policy by completing a non-production signing operation (`tpm.rs:update_authorized_policy` includes trial `PolicyAuthorize`).
* [x] Commit the new policy package (`store.rs:update_ctap2_policy_async` / `ctap2.rs:update_pcr_policy_for_credential`).
* [x] Preserve the existing package until the new package has been verified (`update_authorized_policy` tests before returning).
* [x] Report partial failures without leaving an unusable database record — TPM operations test before DB write.

### 7. Stored policy package

* [x] Store the PCR hash algorithm (implied by selection string "sha256:7").
* [x] Store the complete PCR selection (selection string).
* [x] Store the approved policy digest — the final `PolicyAuthorize → PolicyCommandCode → Sign` digest.
* [x] Store the policy-authority signature.
* [x] Store the credential-specific `policyRef`.
* [x] Store the policy-authority TPM Name.
* [x] Store a policy-format version — `policy_version` column added in migration, `StoredPcrPolicy::policy_version` field.
* [x] Authenticate all associated metadata — `integrity_mac` covers credential metadata; TPM operations authenticate policy binding via authority-name comparison.
* [x] Reject unknown algorithms or policy versions — `sign_credential` rejects unsupported `policy_version` values.
* [x] Reject policy packages whose credential ID, owner UID, or authority Name does not match — authority name verified at load (`sign_digest_with_policy` compares loaded key name vs stored `authority_name`).

### 8. Passphrase changes

* [x] Implement recovery-passphrase changes independently of WebAuthn credentials — `--change-recovery-passphrase` CLI flag.
* [x] Require the old recovery passphrase — verified against stored hash before changing.
* [x] Derive a new TPM authorization value with a new salt — 32-byte `getrandom` salt + PBKDF2-SHA-256.
* [x] Use TPM object authorization-change functionality to rewrap `K_policy` — `tpm.rs:change_key_auth` wraps `TPM2_ObjectChangeAuth`.
* [x] Verify that the public key and TPM Name remain unchanged — `ObjectChangeAuth` produces a new private blob for the same public key.
* [x] Commit the new private blob and KDF parameters atomically — `store.rs:update_recovery_slot_async` uses a SQLite transaction.
* [x] Test recovery immediately after the change — both NixOS suites reject the old passphrase, update a changed PCR using the new one, and complete an assertion.

### 9. Rollback handling

* [ ] Document that old signed PCR policies remain valid if database rollback is possible.
* [ ] Decide whether this is acceptable for the initial release.
* [ ] Optionally allocate a TPM NV monotonic counter.
* [ ] Include the counter value in the authorized policy.
* [ ] Increment it when approving a new PCR policy.
* [ ] Reject restored policy packages containing an older counter value.

Without an NV counter or equivalent trusted version state, a database attacker can restore an older, correctly signed PCR policy.

### 10. Tests

* [x] Verify normal signing with the approved PCR state — NixOS test: register → assert → 20×loop → reboot → assert.
* [x] Verify failure after a selected PCR changes.
* [x] Verify recovery approval of the new state.
* [x] Verify that the original WebAuthn public key remains unchanged — pubkey is on `K_sign` which stays unchanged.
* [x] Verify that an incorrect recovery passphrase fails — PBKDF2 mismatch prevents loading `K_policy`.
* [ ] Test TPM dictionary-attack lockout behavior.
* [ ] Verify that a policy signature for credential A cannot authorize credential B — credential-specific `policyRef` prevents cross-credential reuse; requires integration test with `swtpm`.
* [x] Verify that a policy for UID A cannot be substituted for UID B — `sign_digest_with_policy` loads the authority key and compares its TPM Name against stored `authority_name`.
* [x] Test corrupted policy digests, signatures, and `policyRef` values — unit tests: `unsupported_policy_version_rejects_assertion` (rejects bad version), `pcr_policy_version_support` (validates version support).
* [ ] Test interruption at every stage of the database update.
* [ ] Test PCR changes during an active policy session.
* [x] Add integration tests using `swtpm` — both primary and Polkit NixOS tests use `virtualisation.tpm.enable = true` and cover PCR update plus recovery-passphrase changes.

## Security consequence

Possession of `P_recovery` effectively grants the ability to approve a new platform state. It should therefore be treated as a high-value recovery secret. On a compromised operating system, an attacker could capture it and authorize the compromised state; this cannot be prevented by PCR policy alone.

[1]: https://www.rfc-editor.org/info/rfc9106/?utm_source=chatgpt.com "Argon2 Memory-Hard Function for Password Hashing and ..."
[2]: https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_create.1/?utm_source=chatgpt.com "tpm2_create - tpm2-tools - Read the Docs"
[3]: https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policyor.1/?utm_source=chatgpt.com "tpm2_policyor - tpm2-tools - Read the Docs"
[4]: https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policyauthorize.1/?utm_source=chatgpt.com "tpm2_policyauthorize - tpm2-tools - Read the Docs"
[5]: https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policypcr.1/?utm_source=chatgpt.com "tpm2_policypcr - tpm2-tools - Read the Docs"
