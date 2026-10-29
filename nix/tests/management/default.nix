{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "management";
  reason = "Initialize migration-key setup and verify standalone CLI tables, JSON, detail, and a real swtpm-backed registration/assertion.";
  testScript = ''
    output = machine.succeed("fido2-manage -list")
    assert "1209" in output or "tpm-passkey" in output.lower(), output
    assert "FIDO_2_1" in machine.succeed("fido2-manage -info -device 1")
    mgmt_expect(
        "setup",
        'expect "Choose PCR binding"; send "\\r"; '
        'expect "Create migration passphrase: "; send "management phrase\\r"; '
        'expect "Confirm passphrase: "; send "management phrase\\r"; expect eof',
    )
    output = mgmt("list")
    assert "ID" in output and "SITE" in output, output
    output = mgmt("config show")
    assert "migration_configured" in output and "true" in output, output
    assert "default_pcr_policy" in mgmt("config policy")
    assert "No PCR-bound credentials" in mgmt("migrate")

    machine.succeed("mkdir -p /tmp/credential")
    machine.succeed("python3 ${../register.py} /tmp/credential manage.example.test alice user-1 registration false")
    machine.succeed("python3 ${../assert.py} /tmp/credential manage.example.test assertion")
    output = mgmt("list")
    assert "manage.example.test" in output and "alice" in output, output
    import json
    listed = json.loads(mgmt("list --json"))
    assert len(listed) == 1 and set(listed[0]) == {"local_id", "rp_id", "account", "created_at"}, listed
    assert listed[0]["rp_id"] == "manage.example.test" and listed[0]["account"] == "alice"
    assert '"rp_id": "manage.example.test"' in mgmt("info 1 --json")
    # PCR-disabled credentials require no passphrase for a no-op migration.
    assert "No PCR-bound credentials" in mgmt("migrate")
    output = mgmt_expect(
        "config policy --disable",
        'expect "Proceed?"; send "y\\r"; '
        'expect "Migration passphrase: "; send "management phrase\\r"; expect eof',
    )
    assert "Default policy and all existing credential policies updated" in output, output
    machine.succeed("python3 ${../assert.py} /tmp/credential manage.example.test after-policy")
  '';
}
