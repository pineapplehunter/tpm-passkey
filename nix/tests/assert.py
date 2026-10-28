import cbor2
import hashlib
import sys
import traceback
from pathlib import Path

from fido2.cose import CoseKey
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice

try:
    workdir, rp_id, challenge = sys.argv[1:4]
    device = next(CtapHidDevice.list_devices())
    ctap = Ctap2(device)
    client_data_hash = hashlib.sha256(challenge.encode()).digest()
    credential_id = Path(workdir, "credential.id").read_bytes()
    public_key = CoseKey.parse(cbor2.load(Path(workdir, "pubkey.cbor").open("rb")))
    print("python smoke: calling get_assertion", file=sys.stderr, flush=True)
    assertion = ctap.get_assertion(
        rp_id,
        client_data_hash,
        allow_list=[{"type": "public-key", "id": credential_id}],
        options={"up": True, "uv": False},
    )
    print("python smoke: get_assertion returned", file=sys.stderr, flush=True)
    assertion.verify(client_data_hash, public_key)
except Exception:
    traceback.print_exc()
    raise
