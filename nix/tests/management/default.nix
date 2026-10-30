{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-management";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    output = machine.succeed("fido2-manage -list")
    assert "1209" in output or "tpm-passkey" in output.lower(), output
    assert "FIDO_2_1" in machine.succeed("fido2-manage -info -device 1")
    env.mgmt_expect(
        "setup",
        'expect "Choose PCR binding"; send "\\r"; '
        'expect "Create migration passphrase: "; send "management phrase\\r"; '
        'expect "Confirm passphrase: "; send "management phrase\\r"; expect eof',
    )
    output = env.mgmt("list")
    assert "ID" in output and "SITE" in output, output
    output = env.mgmt("config show")
    assert "migration_configured" in output and "true" in output, output
    assert "default_pcr_policy" in env.mgmt("config policy")
    assert "No PCR-bound credentials" in env.mgmt("migrate")

    machine.succeed("mkdir -p /tmp/credential")
    machine.succeed("python3 ${../register.py} /tmp/credential manage.example.test alice user-1 registration false")
    machine.succeed("python3 ${../assert.py} /tmp/credential manage.example.test assertion")
    output = env.mgmt("list")
    assert "manage.example.test" in output and "alice" in output, output
    import json
    listed = json.loads(env.mgmt("list --json"))
    assert len(listed) == 1 and set(listed[0]) == {"local_id", "rp_id", "account", "created_at"}, listed
    assert listed[0]["rp_id"] == "manage.example.test" and listed[0]["account"] == "alice"
    assert '"rp_id": "manage.example.test"' in env.mgmt("info 1 --json")
    # PCR-disabled credentials require no passphrase for a no-op migration.
    assert "No PCR-bound credentials" in env.mgmt("migrate")
    output = env.mgmt_expect(
        "config policy --disable",
        'expect "Proceed?"; send "y\\r"; '
        'expect "Migration passphrase: "; send "management phrase\\r"; expect eof',
    )
    assert "Default policy and all existing credential policies updated" in output, output
    machine.succeed("python3 ${../assert.py} /tmp/credential manage.example.test after-policy")
  '';
}
