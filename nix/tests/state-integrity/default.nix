{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-state-integrity";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.setup_migration()
    env.expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "1234\\r"; '
        'expect "Enter the same PIN again"; send "1234\\r"; expect eof')
    machine.succeed("mkdir -p /tmp/credential")
    machine.succeed("python3 ${../register.py} /tmp/credential login.example.test alice user-1 registration false")
    env.scenario("${./scenario.py}", timeout=90)
    machine.succeed("python3 ${../assert.py} /tmp/credential login.example.test repaired")
    assert env.mgmt("list --json").count('"local_id"') == 1
  '';
}
