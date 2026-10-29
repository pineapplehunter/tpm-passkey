"""Real swtpm regression for PolicyAuthorize signing and PCR-policy rebinding."""
import cbor2
import hashlib
import sqlite3
import subprocess
import time

from tpm_test_bus import management
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice

PHRASE = "policy rebind integration phrase"
STORE = "/var/lib/tpm-passkey/credentials.sqlite"


def open_ctap():
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        devices = list(CtapHidDevice.list_devices())
        if devices:
            return devices[0], Ctap2(devices[0])
        time.sleep(0.1)
    raise AssertionError("virtual authenticator did not appear")


def register():
    device, ctap = open_ctap()
    rp = "policy-rebind.example.test"
    try:
        response = ctap.make_credential(
            hashlib.sha256(b"policy rebind registration").digest(),
            {"id": rp, "name": rp},
            {"id": b"policy-rebind-user", "name": "Policy Rebind"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": False, "up": True, "uv": False},
        )
        data = response.auth_data.credential_data
        assert data is not None
        return rp, data.credential_id, data.public_key
    finally:
        device.close()


def assertion(credential, denied=False):
    rp, credential_id, public_key = credential
    device, ctap = open_ctap()
    challenge = hashlib.sha256(b"policy rebind assertion").digest()
    try:
        try:
            response = ctap.get_assertion(
                rp,
                challenge,
                allow_list=[{"type": "public-key", "id": credential_id}],
                options={"up": True, "uv": False},
            )
        except CtapError as error:
            assert denied and error.code == CtapError.ERR.OPERATION_DENIED, error
            return
        assert not denied, "PCR mismatch did not prevent signing"
        response.verify(challenge, public_key)
    finally:
        device.close()


def primary(credential):
    with sqlite3.connect(STORE) as database:
        row = database.execute(
            "SELECT policy_selection, policy_digest, policy_ref, authority_name, "
            "authority_signature, tpm_key, public_key FROM credential_keyslots "
            "WHERE credential_id = ? AND slot_kind = 'primary'",
            (credential[1],),
        ).fetchone()
    assert row is not None, "credential primary slot missing"
    return row


def rebind(credential, pcr_indices, default_change=None):
    parameters = {
        "passphrase": PHRASE,
        "pcr_indices": pcr_indices or [],
        "all": True,
        "credential_ids": [],
    }
    if default_change is not None:
        parameters["default_policy_change"] = default_change
    result = management("update-pcr-policy", parameters)
    rows = result["results"]
    assert len(rows) == 1 and rows[0]["status"] == "ok", rows


# SetupMigration with no PCR selection creates an authorized baseline, not an
# unbound key. Credential creation consumes its public migration configuration.
result = management(
    "setup-migration", {"passphrase": PHRASE, "pcr_indices": None}
)
assert result["status"] == "migration configured", result
credential = register()
baseline = primary(credential)
assert baseline[0] == "none", baseline[0]
assert all(value is not None for value in baseline[:5]), baseline[:5]
assertion(credential)  # Exercises PolicyAuthorize with no PolicyPCR command.

# Rotate the passphrase without changing the public migration key or envelopes.
with sqlite3.connect(STORE) as database:
    old_config = cbor2.loads(database.execute("SELECT value FROM daemon_config WHERE key = 'migration_encryption'").fetchone()[0])
    old_envelopes = database.execute("SELECT encrypted_auth FROM credential_tokens ORDER BY token_id").fetchall()
NEW_PHRASE = "rotated policy rebind phrase"
management(
    "update-migration-passphrase",
    {"old_passphrase": PHRASE, "new_passphrase": NEW_PHRASE},
)
management("verify-migration-passphrase", {"passphrase": PHRASE}, ok=False)
management("verify-migration-passphrase", {"passphrase": NEW_PHRASE})
PHRASE = NEW_PHRASE
with sqlite3.connect(STORE) as database:
    new_config = cbor2.loads(database.execute("SELECT value FROM daemon_config WHERE key = 'migration_encryption'").fetchone()[0])
    assert new_config['config']['public_key'] == old_config['config']['public_key']
    assert new_config['config']['encrypted_scalar'] != old_config['config']['encrypted_scalar']
    assert database.execute("SELECT encrypted_auth FROM credential_tokens ORDER BY token_id").fetchall() == old_envelopes
assert primary(credential) == baseline, 'passphrase rotation changed the passkey policy or key'
assertion(credential)

# Rebind the same key through the protocol management operation. It must now
# require PCR 7, and a changed PCR must make signing fail closed.
rebind(credential, [7], {"Set": {"pcr_indices": [7]}})
bound = primary(credential)
assert bound[0] == "sha256:7", bound[0]
with sqlite3.connect(STORE) as database:
    default_blob = database.execute("SELECT value FROM daemon_config WHERE key = 'default_pcr_policy'").fetchone()[0]
assert cbor2.loads(default_blob) == [7]
assert bound[5:] == baseline[5:], "rebinding replaced the passkey key/blob"
assertion(credential)
subprocess.run(
    ["tpm2_pcrextend", "7:sha256=" + "a" * 64], check=True
)
assertion(credential, denied=True)

# Disable PCR binding for this credential (not merely future enrollments),
# again via the management protocol. The same passkey must sign despite the
# changed PCR, proving its authorized baseline policy is used.
rebind(credential, None, "Disable")
disabled = primary(credential)
assert disabled[0] == "none", disabled[0]
with sqlite3.connect(STORE) as database:
    assert database.execute("SELECT 1 FROM daemon_config WHERE key = 'default_pcr_policy'").fetchone() is None
assert disabled[5:] == baseline[5:], "disabling replaced the passkey key/blob"
assertion(credential)
# A normal migration skips this disabled policy; enabling it again must still
# use the same authority and primary key, then migrate a stale enforced policy.
skipped = management('migrate-pcr-reference', {'passphrase': PHRASE})
assert skipped['results'][0]['status'] == 'skipped', skipped
rebind(credential, [7], {'Set': {'pcr_indices': [7]}})
subprocess.run(['tpm2_pcrextend', '7:sha256=' + 'b' * 64], check=True)
assertion(credential, denied=True)
migrated = management('migrate-pcr-reference', {'passphrase': PHRASE})
assert migrated['results'][0]['status'] == 'ok', migrated
assert primary(credential)[5:] == baseline[5:]
assertion(credential)
print('PolicyAuthorize baseline, passphrase rotation and disabled/enable/rebind/migration passed')
