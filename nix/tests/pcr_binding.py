"""Real TPM/UHID regression for opt-in PCR binding and unchanged old keys."""
import hashlib
import socket
import sqlite3
import struct
import subprocess
import time

import cbor2
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice

PHRASE = "optional PCR recovery test phrase"
STORE = "/var/lib/tpm-passkey/credentials.sqlite"
SOCKET = "/run/tpm-passkey/management.sock"


def management(command, params=None, ok=True):
    request = {"cmd": command}
    if params is not None:
        request["params"] = params
    encoded = cbor2.dumps(request)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(20)
        client.connect(SOCKET)
        client.sendall(struct.pack(">I", len(encoded)) + encoded)
        with client.makefile("rb") as stream:
            length = struct.unpack(">I", stream.read(4))[0]
            response = cbor2.loads(stream.read(length))
    assert response["ok"] == ok, response
    return response.get("result")


def open_ctap():
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        devices = list(CtapHidDevice.list_devices())
        if devices:
            return devices[0], Ctap2(devices[0])
        time.sleep(0.1)
    raise AssertionError("virtual authenticator did not appear")


def register(label, denied=False):
    device, ctap = open_ctap()
    rp = label + ".example.test"
    try:
        try:
            response = ctap.make_credential(
                hashlib.sha256(label.encode()).digest(),
                {"id": rp, "name": rp},
                {"id": label.encode(), "name": label},
                [{"type": "public-key", "alg": -7}],
                options={"rk": False, "up": True, "uv": False},
            )
        except CtapError as error:
            assert denied and error.code == CtapError.ERR.OPERATION_DENIED, error
            return None
        assert not denied, "PCR-bound enrollment unexpectedly succeeded while locked"
        data = response.auth_data.credential_data
        assert data is not None
        return rp, data.credential_id, data.public_key
    finally:
        device.close()


def assertion(credential, denied=False):
    rp, credential_id, public_key = credential
    device, ctap = open_ctap()
    challenge = hashlib.sha256(b"PCR binding assertion").digest()
    try:
        try:
            response = ctap.get_assertion(
                rp, challenge,
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


def snapshot(credential):
    with sqlite3.connect(STORE) as database:
        return database.execute(
            "SELECT policy_selection, policy_digest, policy_ref, authority_name, "
            "authority_signature, tpm_key, public_key FROM credential_keyslots "
            "WHERE credential_id = ? AND slot_kind = 'primary'",
            (credential[1],),
        ).fetchone()


def unbound(credential):
    row = snapshot(credential)
    assert row is not None and row[:5] == (None,) * 5, row[:5]
    with sqlite3.connect(STORE) as database:
        assert database.execute(
            "SELECT count(*) FROM credential_keyslots WHERE credential_id = ? "
            "AND slot_kind = 'recovery'", (credential[1],)
        ).fetchone()[0] == 0


def extend_pcr(digit):
    subprocess.run(["tpm2_pcrextend", "7:sha256=" + digit * 64], check=True)


def restart():
    subprocess.run(["systemctl", "restart", "tpm-passkey"], check=True)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            management("show-config")
            device, _ = open_ctap()
            device.close()
            return
        except (OSError, EOFError):
            time.sleep(0.1)
    raise AssertionError("daemon failed to restart")


def recover(credential, phrase, success):
    result = management("update-pcr-reference", {"passphrase": phrase})
    row = next(row for row in result["results"] if row["credential"] == credential[1].hex())
    assert row["status"] == ("ok" if success else "error"), row


config = management("show-config")
assert config["default_pcr_policy"] is None
assert not config["recovery_passphrase_configured"]
assert "default_pcr_policy\tnone" in subprocess.check_output(
    ["tpm-passkey", "config", "show"], text=True
)
a = register("default-unbound")
unbound(a)
a_original = snapshot(a)
extend_pcr("a")
assertion(a)
management("set-default-pcr-policy", {"pcr_indices": [7]}, ok=False)
assert management("show-config")["default_pcr_policy"] is None

management("update-passphrase", {"new_passphrase": PHRASE})
assert management("show-config")["default_pcr_policy"] is None
b = register("phrase-only-unbound")
unbound(b)
b_original = snapshot(b)
extend_pcr("b")
assertion(a)
assertion(b)

management("set-default-pcr-policy", {"pcr_indices": [7]})
assert snapshot(a) == a_original and snapshot(b) == b_original
restart()
assert management("show-config")["default_pcr_policy"] == [7]
register("locked-bound", denied=True)
management("unlock-recovery", {"passphrase": "wrong phrase"}, ok=False)
register("still-locked-bound", denied=True)
management("unlock-recovery", {"passphrase": PHRASE})
c = register("opted-in-bound")
assert snapshot(c)[0] == "sha256:7"
with sqlite3.connect(STORE) as database:
    assert database.execute(
        "SELECT count(*) FROM credential_tokens t JOIN credential_keyslots k "
        "ON k.keyslot_id = t.keyslot_id WHERE k.credential_id = ?", (c[1],)
    ).fetchone()[0] == 1
c_before_recovery = snapshot(c)
extend_pcr("c")
assertion(a)
assertion(b)
assertion(c, denied=True)
recover(c, "wrong phrase", success=False)
assert snapshot(c) == c_before_recovery
assertion(c, denied=True)
recover(c, PHRASE, success=True)
assertion(c)
c_approved = snapshot(c)
assert c_approved[4] != c_before_recovery[4]
assert c_approved[5:] == c_before_recovery[5:]  # Same registered key/blobs.

subprocess.run(
    ["tpm-passkey", "config", "set", "default-pcr-policy", "--disable"], check=True
)
assert management("show-config")["default_pcr_policy"] is None
assert snapshot(c) == c_approved  # Disabling cannot relax an existing policy.
restart()
assert management("show-config")["default_pcr_policy"] is None
d = register("disabled-unbound")  # Works with recovery enrollment locked.
unbound(d)
extend_pcr("d")
for credential in (a, b, d):
    assertion(credential)
assertion(c, denied=True)
recover(c, "wrong phrase", success=False)
assert snapshot(c) == c_approved
recover(c, PHRASE, success=True)
assertion(c)
assert snapshot(a) == a_original and snapshot(b) == b_original
management("set-default-pcr-policy", {"pcr_indices": [1, 7]})
c_unchanged = snapshot(c)
restart()
assert management("show-config")["default_pcr_policy"] == [1, 7]
assert snapshot(c) == c_unchanged
print("Optional PCR binding, non-retrofit, and recovery regressions passed")
