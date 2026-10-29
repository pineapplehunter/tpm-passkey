"""UI independent lifecycle tests against the real daemon and bus."""
import json
from pathlib import Path
from fido2.hid import CTAPHID, CtapHidDevice

mode = Path("/run/user/1000/tpm-passkey-test-mode")
events = Path("/run/user/1000/tpm-passkey-test-events")

def selection():
    device = next(CtapHidDevice.list_devices())
    try:
        return device.call(CTAPHID.CBOR, b"\x0b")
    finally:
        device.close()

assert selection() == b"\x00"
mode.write_text("deny")
assert selection() == b"\x27", "prior Allow must not be cached"
mode.write_text("allow")
assert selection() == b"\x00"
rows = [json.loads(line) for line in events.read_text().splitlines()]
ids = [row["id"] for row in rows if row["kind"] == "request"]
assert len(ids) == 3 and len(set(ids)) == 3

mode.unlink(missing_ok=True)
print("Fresh decisions verified")
