import cbor2
import hashlib
import sys
import traceback
from pathlib import Path

from fido2.ctap2 import ClientPin, Ctap2
from fido2.hid import CtapHidDevice

try:
    workdir, rp_id, user_name, user_id, challenge, rk_str = sys.argv[1:7]
    rk = rk_str.lower() == "true"
    device = next(CtapHidDevice.list_devices())
    ctap = Ctap2(device)
    client_data_hash = hashlib.sha256(challenge.encode()).digest()
    pin_uv_param = None
    pin_uv_protocol = None
    if rk and ctap.info.options.get("clientPin"):
        # Optional integration-test PIN, needed only for protected rk enrollment.
        pin = sys.argv[7]
        client_pin = ClientPin(ctap)
        token = client_pin.get_pin_token(
            pin, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
            permissions_rpid=rp_id,
        )
        pin_uv_param = client_pin.protocol.authenticate(token, client_data_hash)
        pin_uv_protocol = client_pin.protocol.VERSION
    print("python smoke: calling make_credential rk=" + str(rk), file=sys.stderr, flush=True)
    attestation = ctap.make_credential(
        client_data_hash,
        {"id": rp_id, "name": rp_id},
        {"id": user_id.encode(), "name": user_name, "displayName": user_name},
        [{"type": "public-key", "alg": -7}],
        options={"rk": rk, "up": True, "uv": False},
        pin_uv_param=pin_uv_param,
        pin_uv_protocol=pin_uv_protocol,
    )
    print("python smoke: make_credential returned", file=sys.stderr, flush=True)
    credential_data = attestation.auth_data.credential_data
    Path(workdir, "credential.id").write_bytes(credential_data.credential_id)
    with Path(workdir, "pubkey.cbor").open("wb") as stream:
        cbor2.dump(dict(credential_data.public_key), stream)
except Exception:
    traceback.print_exc()
    raise
