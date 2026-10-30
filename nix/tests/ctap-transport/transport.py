import os

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID, CtapHidDevice

device = next(CtapHidDevice.list_devices())
try:
    # No visible/audible WINK implementation: do not claim that capability.
    assert not device.capabilities & 0x01
    try:
        device.call(CTAPHID.CBOR, b"")
    except CtapError as error:
        assert error.code == CtapError.ERR.INVALID_LENGTH, error
    else:
        raise AssertionError("empty CBOR transport request was accepted")
    for size in (0, 1, 57, 58, 116, 117, 200, 1024, 1200):
        payload = os.urandom(size)
        assert device.call(CTAPHID.PING, payload) == payload
    info = Ctap2(device).info
    assert {"FIDO_2_0", "FIDO_2_1"}.issubset(info.versions)
    assert len(info.aaguid) == 16
    assert info.max_msg_size >= 1024
    assert info.pin_uv_protocols == [2, 1]
    assert "usb" in info.transports
    assert not info.extensions
    for option in ("rk", "up", "credMgmt"):
        assert info.options.get(option) is True
    assert "uv" not in info.options
    assert info.options.get("clientPin") is False
    assert info.options.get("pinUvAuthToken") is False
    assert any(p.get("type") == "public-key" and p.get("alg") == -7 for p in info.algorithms)
    for command in (0x09, 0x0C, 0x0D, 0x40, 0x41, 0xFF):
        assert device.call(CTAPHID.CBOR, bytes([command])) == b"\x01"
finally:
    device.close()
