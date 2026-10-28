{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "management";
  reason = "Check fresh CLI defaults and listing columns, then verify an unbound passkey can register and sign through real UHID/TPM.";
  testScript = ''
    output = machine.succeed("fido2-manage -list")
    assert "1209" in output or "tpm-passkey" in output.lower(), output
    assert "FIDO_2_1" in machine.succeed("fido2-manage -info -device 1")
    assert mgmt("list-credentials").strip() == ""
    output = mgmt("config show")
    assert "default_pcr_policy\tnone" in output, output
    assert "recovery_passphrase_configured\tfalse" in output, output
    machine.fail("tpm-passkey config set default-pcr-policy 7")
    mgmt("config set default-pcr-policy --disable")

    machine.succeed("mkdir -p /tmp/credential")
    machine.succeed("python3 ${../register.py} /tmp/credential manage.example.test alice user-1 registration false")
    machine.succeed("python3 ${../assert.py} /tmp/credential manage.example.test assertion")
    rows = [line.split("\t") for line in mgmt("list-credentials").strip().splitlines()]
    assert len(rows) == 1 and len(rows[0]) == 6, rows
    assert rows[0][1:3] == ["manage.example.test", "alice"], rows
    assert rows[0][3] != "unknown" and rows[0][4] != "never", rows
    assert rows[0][5] == "none", rows
  '';
}
