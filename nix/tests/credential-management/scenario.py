import hashlib

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.pin import PinProtocolV1
from fido2.hid import CtapHidDevice

device = next(CtapHidDevice.list_devices())
try:
    ctap = Ctap2(device)
    pin = ClientPin(ctap, PinProtocolV1())
    token = pin.get_pin_token("1234", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
    management = CredentialManagement(ctap, pin.protocol, token)
    result = CredentialManagement.RESULT
    assert management.get_metadata()[result.EXISTING_CRED_COUNT] == 3
    relying_parties = management.enumerate_rps()
    assert {rp[result.RP]["id"] for rp in relying_parties} == {
        "manage.example.test", "other.example.test",
    }
    rp_hash = hashlib.sha256(b"manage.example.test").digest()
    credentials = management.enumerate_creds(rp_hash)
    assert len(credentials) == 2
    assert {credential[result.USER]["id"] for credential in credentials} == {b"first", b"second"}
    descriptor = credentials[0][result.CREDENTIAL_ID]
    user_id = credentials[0][result.USER]["id"]
    management.update_user_info(descriptor, {
        "id": user_id, "name": "updated-user", "displayName": "Updated User",
    })
    updated = next(c for c in management.enumerate_creds(rp_hash)
                   if c[result.CREDENTIAL_ID]["id"] == descriptor["id"])
    assert updated[result.USER] == {
        "id": user_id, "name": "updated-user", "displayName": "Updated User",
    }

    # With two RPs this continuation would still succeed without interruption.
    management.enumerate_rps_begin()
    management.get_metadata()
    try:
        management.enumerate_rps_next()
    except CtapError as error:
        assert error.code == CtapError.ERR.NOT_ALLOWED
    else:
        raise AssertionError("interrupted enumeration was accepted")
finally:
    device.close()
