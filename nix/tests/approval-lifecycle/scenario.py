"""UI independent lifecycle tests against the real daemon, bus and logind."""
import json
from pathlib import Path
import subprocess
import threading
import time
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

session = subprocess.check_output([
    "loginctl", "show-user", "alice", "-p", "Display", "--value"], text=True).strip()
# The fixture is a controlled TTY; choose its actual session if Display is empty.
if not session:
    sessions = subprocess.check_output(["loginctl", "list-sessions", "--no-legend"], text=True)
    session = next(line.split()[0] for line in sessions.splitlines() if "alice" in line)
path = subprocess.check_output([
    "busctl", "call", "org.freedesktop.login1", "/org/freedesktop/login1",
    "org.freedesktop.login1.Manager", "GetSession", "s", session], text=True).split('"')[1]

def locked(value):
    subprocess.run(["busctl", "call", "org.freedesktop.login1", path,
        "org.freedesktop.login1.Session", "SetLockedHint", "b", str(value).lower()], check=True)

mode.write_text("pending")
result = []
worker = threading.Thread(target=lambda: result.append(selection()))
worker.start()
try:
    deadline = time.monotonic() + 3
    while sum(json.loads(line).get("kind") == "request" for line in events.read_text().splitlines()) < 4:
        assert time.monotonic() < deadline, "agent never received request"
        time.sleep(0.01)
    locked(True)
    worker.join(timeout=3)
    assert not worker.is_alive(), "session lock failed to cancel pending approval"
    assert result == [b"\x27"], result
    assert selection() == b"\x27", "locked session must not display fresh consent"
finally:
    locked(False)
    mode.unlink(missing_ok=True)
print("Fresh decisions and session-lock cancellation verified")
