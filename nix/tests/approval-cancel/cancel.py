"""Cancel while a registered agent is pending; verify wire cleanup."""
import json
from pathlib import Path
import sys
import threading
import time
from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID, CtapHidDevice

verify_agent = "--agent" in sys.argv
path = Path("/run/user/1000/tpm-passkey-test-events")
before = len(path.read_text().splitlines()) if path.exists() else 0

def events():
    rows = []
    for line in path.read_text().splitlines()[before:]:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows

with next(CtapHidDevice.list_devices()) as device:
    event = threading.Event()
    up_needed = threading.Event()
    cancelled_at = None
    def keepalive(status):
        if int(status) == 2:
            up_needed.set()
    def cancel_pending():
        global cancelled_at
        if not up_needed.wait(2):
            event.set()
            return
        if verify_agent:
            deadline = time.monotonic() + 2
            while not any(row.get("kind") == "request" for row in events()):
                if time.monotonic() >= deadline:
                    event.set()
                    return
                time.sleep(0.01)
        cancelled_at = time.monotonic()
        event.set()
    threading.Thread(target=cancel_pending, daemon=True).start()
    watchdog = threading.Timer(5, event.set)
    watchdog.start()
    try:
        reply = device.call(CTAPHID.CBOR, b"\x0b", event=event, on_keepalive=keepalive)
        assert cancelled_at is not None, "approval did not become pending"
        assert reply == b"\x2d", reply
        assert time.monotonic() - cancelled_at < 1
        assert "FIDO_2_1" in Ctap2(device).info.versions
        if verify_agent:
            deadline = time.monotonic() + 1
            while not any(row.get("member") == "Cancel" for row in events()):
                assert time.monotonic() < deadline, events()
                time.sleep(0.01)
            checks = [row for row in events() if row.get("member") == "Request"]
            cancels = [row for row in events() if row.get("member") == "Cancel"]
            assert len(checks) == len(cancels) == 1, events()
            assert checks[0]["id"] == cancels[0]["id"]
            assert checks[0]["sender"] == cancels[0]["sender"]
            assert checks[0]["sender"] == Path("/run/user/1000/tpm-passkey-test-ready").read_text()
    finally:
        watchdog.cancel()
print("Pending approval cancelled; CTAP worker responsive; directed dialog cancellation verified")
