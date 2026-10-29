import time
from fido2.hid import CTAPHID, CtapHidDevice

device = next(CtapHidDevice.list_devices())
try:
    start = time.monotonic()
    assert device.call(CTAPHID.CBOR, b"\x0b") == b"\x27"
    assert time.monotonic() - start < 3, "missing agents must not queue future consent"
finally:
    device.close()
