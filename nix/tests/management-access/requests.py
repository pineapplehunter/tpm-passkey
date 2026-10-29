"""User-side negative transport tests: never authorize one operation as another."""
import asyncio
import cbor2
from tpm_test_bus import manage_raw, management

assert management("show-config") is not None

async def refused(operation, payload, sealed=True):
    try:
        response = await manage_raw(operation, payload, sealed)
    except RuntimeError:
        return
    assert not response["ok"], response

async def main():
    show = cbor2.dumps("show-config")
    await refused("show-config", show, sealed=False)
    await refused("show-config", b"malformed-test-secret")
    await refused("show-config", show + b"trailing-test-secret")
    await refused("show-config", b"x" * (16 * 1024 + 1))
    await refused("show-config", cbor2.dumps("disable-default-pcr-policy"))
    await refused("unknown-operation", show)

asyncio.run(main())
print("Group-member requests cannot bypass sealed-FD or operation authorization checks")
