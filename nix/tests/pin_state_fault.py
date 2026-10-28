"""A corrupt PIN record must not make the authenticator appear unprotected."""
import hashlib
import sqlite3
import subprocess
import time

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.hid import CtapHidDevice

STORE = "/var/lib/tpm-passkey/credentials.sqlite"


def restart():
    subprocess.run(["systemctl", "restart", "tpm-passkey"], check=True, timeout=20)


def connect():
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        devices = list(CtapHidDevice.list_devices())
        if devices:
            try:
                return devices[0], Ctap2(devices[0])
            except OSError:
                devices[0].close()
        time.sleep(0.1)
    raise AssertionError("authenticator did not reappear")


def snapshot():
    with sqlite3.connect(STORE) as database:
        metadata = database.execute(
            "SELECT * FROM credential_metadata ORDER BY credential_id"
        ).fetchall()
        keys = database.execute(
            "SELECT * FROM credential_keyslots ORDER BY keyslot_id"
        ).fetchall()
    return metadata, keys


def set_mac(value):
    with sqlite3.connect(STORE) as database:
        database.execute(
            "UPDATE client_pin_state SET integrity_mac = ? WHERE state_id = 1", (value,)
        )


def expect_integrity_failure(operation):
    try:
        operation()
    except CtapError as error:
        assert error.code == CtapError.ERR.INTEGRITY_FAILURE, error
    else:
        raise AssertionError("corrupt PIN state was accepted")


with sqlite3.connect(STORE) as database:
    original_mac = database.execute(
        "SELECT integrity_mac FROM client_pin_state WHERE state_id = 1"
    ).fetchone()[0]
assert original_mac is not None
original = snapshot()
assert original[0], "fault test needs existing credentials"
try:
    for corrupt in (bytes(32), None):
        set_mac(corrupt)
        restart()
        device, ctap = connect()
        try:
            assert ctap.info.options.get("clientPin") is True
            assert ctap.info.options.get("pinUvAuthToken") is True
            expect_integrity_failure(lambda: ctap.client_pin(2, 1))
            expect_integrity_failure(lambda: ctap.make_credential(
                hashlib.sha256(b"blocked registration").digest(),
                {"id": "blocked.example.test"}, {"id": b"blocked"},
                [{"type": "public-key", "alg": -7}], options={"rk": False},
            ))
            expect_integrity_failure(lambda: ctap.get_assertion(
                "login.example.test", hashlib.sha256(b"blocked assertion").digest(),
                options={"up": False},
            ))
            assert snapshot() == original
        finally:
            device.close()
finally:
    set_mac(original_mac)
    restart()

# Repair and restart recover the original PIN without deleting any passkeys.
device, ctap = connect()
try:
    token = ClientPin(ctap).get_pin_token(
        "1234", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
    )
    assert len(token) == 32
    assert snapshot() == original
finally:
    device.close()
print("PIN-state corruption fails closed and repair preserves credentials")
