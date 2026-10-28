import hashlib
import os
import sys
import traceback

from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.pin import PinProtocolV1
from fido2.hid import CTAPHID, CtapHidDevice
from fido2.webauthn import AuthenticatorData


def expect_ctap_error(expected, operation):
    try:
        operation()
    except CtapError as error:
        if error.code != expected:
            raise AssertionError(f"expected {expected}, got {error.code}") from error
    else:
        raise AssertionError(f"expected CTAP error {expected}")


def challenge(label):
    return hashlib.sha256(label.encode()).digest()


def register(ctap, rp_id, user_id, client_pin=None, uv_token=None):
    client_data_hash = challenge(f"register-{user_id}")
    pin_uv_param = None
    pin_uv_protocol = None
    if client_pin is not None and uv_token is not None:
        pin_uv_param = client_pin.protocol.authenticate(uv_token, client_data_hash)
        pin_uv_protocol = client_pin.protocol.VERSION

    return ctap.make_credential(
        client_data_hash,
        {"id": rp_id, "name": "CTAP compliance test"},
        {
            "id": user_id.encode(),
            "name": user_id,
            "displayName": f"Test user {user_id}",
        },
        [{"type": "public-key", "alg": -7}],
        extensions={"credProps": True},
        options={"rk": True, "up": True, "uv": False},
        pin_uv_param=pin_uv_param,
        pin_uv_protocol=pin_uv_protocol,
    )


def main():
    rp_id = sys.argv[1] if len(sys.argv) > 1 else "compliance.example.test"
    device = next(CtapHidDevice.list_devices())

    # CTAPHID framing must preserve payloads across initial and continuation
    # packets, through the authenticator's advertised maximum message size.
    for size in (0, 1, 57, 58, 116, 117, 200, 1024, 1200):
        payload = os.urandom(size)
        assert device.call(CTAPHID.PING, payload) == payload

    ctap = Ctap2(device)
    info = ctap.info
    assert "FIDO_2_0" in info.versions
    assert "FIDO_2_1" in info.versions
    assert len(info.aaguid) == 16
    assert info.max_msg_size >= 1024
    assert info.pin_uv_protocols == [2, 1]
    assert "usb" in info.transports
    assert "credProps" in info.extensions
    assert info.options.get("rk") is True
    assert info.options.get("up") is True
    assert "uv" not in info.options
    assert info.options.get("clientPin") is False
    assert info.options.get("pinUvAuthToken") is False
    assert info.options.get("credMgmt") is True
    assert any(
        algorithm.get("type") == "public-key" and algorithm.get("alg") == -7
        for algorithm in info.algorithms
    )

    # Host approval is UP only. Unsupported built-in UV cannot mint tokens.
    for subcommand in (6, 7):
        expect_ctap_error(
            CtapError.ERR.INVALID_COMMAND,
            lambda subcommand=subcommand: ctap.client_pin(2, subcommand),
        )
    expect_ctap_error(
        CtapError.ERR.INVALID_OPTION,
        lambda: ctap.get_assertion(rp_id, challenge("unsupported-uv"), options={"uv": True}),
    )

    # With no protection configured, rk=true is permitted but never claims UV.
    first = register(ctap, rp_id, "resident-user-1")
    assert not first.auth_data.flags & AuthenticatorData.FLAG.UV
    ClientPin(ctap).set_pin("1234")
    ctap = Ctap2(device)  # Refresh capabilities after PIN setup.
    assert "uv" not in ctap.info.options
    assert ctap.info.options.get("clientPin") is True
    assert ctap.info.options.get("pinUvAuthToken") is True
    client_pin = ClientPin(ctap)
    assert client_pin.protocol.VERSION == 2
    expect_ctap_error(
        CtapError.ERR(0x36),  # PUAT_REQUIRED, historically PIN_REQUIRED
        lambda: register(ctap, rp_id, "requires-pin"),
    )

    # FIDO_2_0 implies Protocol 1 and legacy getPinToken (subcommand 5).
    legacy_pin = ClientPin(ctap, PinProtocolV1())
    legacy_token = legacy_pin.get_pin_token("1234")
    assert len(legacy_token) == 32
    second = register(ctap, rp_id, "resident-user-2", legacy_pin, legacy_token)
    assert second.auth_data.flags & AuthenticatorData.FLAG.UV
    credentials = [first.auth_data.credential_data, second.auth_data.credential_data]

    for attestation in (first, second):
        auth_data = attestation.auth_data
        credential = auth_data.credential_data
        assert attestation.fmt == "none"
        assert attestation.att_stmt == {}
        assert auth_data.rp_id_hash == hashlib.sha256(rp_id.encode()).digest()
        assert auth_data.flags & AuthenticatorData.FLAG.UP
        assert auth_data.flags & AuthenticatorData.FLAG.AT
        assert auth_data.counter == 0
        assert credential is not None
        assert len(credential.aaguid) == 16
        assert isinstance(credential.public_key, ES256)
        assert auth_data.extensions == {"credProps": {"rk": True}}

    # excludeList must reject a credential already registered for this RP.
    descriptor = {"type": "public-key", "id": credentials[0].credential_id}
    exclude_token = client_pin.get_pin_token(
        "1234", permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
        permissions_rpid=rp_id,
    )
    exclude_challenge = challenge("excluded-credential")
    expect_ctap_error(
        CtapError.ERR.CREDENTIAL_EXCLUDED,
        lambda: ctap.make_credential(
            exclude_challenge,
            {"id": rp_id, "name": rp_id},
            {"id": b"excluded", "name": "excluded", "displayName": "Excluded"},
            [{"type": "public-key", "alg": -7}],
            exclude_list=[descriptor],
            options={"rk": True, "up": True, "uv": False},
            pin_uv_param=client_pin.protocol.authenticate(
                exclude_token, exclude_challenge
            ),
            pin_uv_protocol=client_pin.protocol.VERSION,
        ),
    )

    # Discoverable credentials must be returned without an allowList and via
    # getNextAssertion. Verify both signatures and user handles.
    assertion_challenge = challenge("resident-assertion")
    assertions = ctap.get_assertions(
        rp_id,
        assertion_challenge,
        options={"up": True, "uv": False},
    )
    assert len(assertions) == 2
    keys = {
        credential.credential_id: credential.public_key for credential in credentials
    }
    assert {assertion.user["id"] for assertion in assertions} == {
        b"resident-user-1",
        b"resident-user-2",
    }
    for assertion in assertions:
        assert assertion.auth_data.rp_id_hash == hashlib.sha256(rp_id.encode()).digest()
        assert assertion.auth_data.flags & AuthenticatorData.FLAG.UP
        assert not assertion.auth_data.flags & AuthenticatorData.FLAG.UV
        assert set(assertion.user) == {"id"}
        assertion.verify(assertion_challenge, keys[assertion.credential["id"]])

    # Protocol 2 permissioned PIN tokens authenticate real TPM assertions.
    verified_challenge = challenge("pin-verified-assertion")
    assertion_token = client_pin.get_pin_token(
        "1234", permissions=ClientPin.PERMISSION.GET_ASSERTION, permissions_rpid=rp_id
    )
    verified = ctap.get_assertion(
        rp_id, verified_challenge, allow_list=[descriptor],
        pin_uv_param=client_pin.protocol.authenticate(assertion_token, verified_challenge),
        pin_uv_protocol=2,
    )
    assert verified.auth_data.flags & AuthenticatorData.FLAG.UV
    assert verified.auth_data.flags & AuthenticatorData.FLAG.UP
    verified.verify(verified_challenge, credentials[0].public_key)

    # A credential is scoped to its RP, even when its ID is supplied explicitly.
    expect_ctap_error(
        CtapError.ERR.NO_CREDENTIALS,
        lambda: ctap.get_assertion(
            "other.example.test",
            challenge("wrong-rp"),
            allow_list=[descriptor],
            options={"up": False, "uv": False},
        ),
    )

    # up=false requests must not claim user presence in authenticatorData.
    silent_challenge = challenge("silent-assertion")
    silent = ctap.get_assertion(
        rp_id,
        silent_challenge,
        allow_list=[descriptor],
        options={"up": False, "uv": False},
    )
    assert not silent.auth_data.flags & AuthenticatorData.FLAG.UP
    silent.verify(silent_challenge, credentials[0].public_key)

    # CTAP requires a 32-byte clientDataHash.
    expect_ctap_error(
        CtapError.ERR.INVALID_CBOR,
        lambda: ctap.get_assertion(
            rp_id,
            b"short",
            allow_list=[descriptor],
            options={"up": False, "uv": False},
        ),
    )

    # Credential-management response keys and unauthenticated continuation
    # commands must interoperate with a strict CTAP client.
    management_token = client_pin.get_pin_token(
        "1234", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
    )
    credential_management = CredentialManagement(
        ctap, client_pin.protocol, management_token
    )
    metadata = credential_management.get_metadata()
    assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 2
    relying_parties = credential_management.enumerate_rps()
    assert len(relying_parties) == 1
    assert relying_parties[0][CredentialManagement.RESULT.RP]["id"] == rp_id
    managed_credentials = credential_management.enumerate_creds(
        hashlib.sha256(rp_id.encode()).digest()
    )
    assert len(managed_credentials) == 2
    assert {
        credential[CredentialManagement.RESULT.CREDENTIAL_ID]["id"]
        for credential in managed_credentials
    } == set(keys)

    updated_descriptor = managed_credentials[0][
        CredentialManagement.RESULT.CREDENTIAL_ID
    ]
    original_user_id = managed_credentials[0][CredentialManagement.RESULT.USER]["id"]
    credential_management.update_user_info(
        updated_descriptor,
        {
            "id": original_user_id,
            "name": "updated-user",
            "displayName": "Updated User",
        },
    )
    updated_credentials = credential_management.enumerate_creds(
        hashlib.sha256(rp_id.encode()).digest()
    )
    updated = next(
        credential
        for credential in updated_credentials
        if credential[CredentialManagement.RESULT.CREDENTIAL_ID]["id"]
        == updated_descriptor["id"]
    )
    assert updated[CredentialManagement.RESULT.USER] == {
        "id": original_user_id,
        "name": "updated-user",
        "displayName": "Updated User",
    }

    # A non-continuation operation interrupts enumeration state.
    credential_management.enumerate_rps_begin()
    credential_management.get_metadata()
    expect_ctap_error(
        CtapError.ERR.NOT_ALLOWED,
        credential_management.enumerate_rps_next,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        raise
