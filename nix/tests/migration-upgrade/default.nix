{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-migration-upgrade";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "1234\\r"; '
        'expect "Enter the same PIN again"; send "1234\\r"; expect eof')
    machine.succeed("systemctl stop tpm-passkey")
    machine.succeed("python3 ${./legacy.py} prepare ${../../../migrations}")
    env.start_daemon()
    machine.succeed("python3 ${./legacy.py} check")
    assert env.mgmt("list --json").strip() == "[]"
    assert "false" in env.mgmt("config show")
    machine.succeed("mkdir -p /tmp/upgrade-credential")
    register = "python3 ${../register.py} /tmp/upgrade-credential upgrade.example.test alice user-1 registration true 1234"
    machine.fail(register)
    env.setup_migration("fresh upgrade migration phrase")
    machine.succeed(register)
    machine.succeed("python3 ${../assert.py} /tmp/upgrade-credential upgrade.example.test retained-pin")
  '';
}
