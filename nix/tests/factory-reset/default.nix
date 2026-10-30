{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-factory-reset";
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
    machine.succeed("python3 ${../register.py} /tmp/credential reset.example.test alice user-1 registration true 1234")
    machine.succeed("python3 ${../assert.py} /tmp/credential reset.example.test before-reset")
    machine.succeed("systemctl restart tpm-passkey")
    env.wait_for_agent()
    env.expect_command("fido2-manage -reset -device 1",
        'expect "Are you sure you want to proceed?"; send "Y\\r"; expect eof')
    assert env.mgmt("list --json").strip() == "[]"
    machine.fail("python3 ${../assert.py} /tmp/credential reset.example.test after-reset")
    env.expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "5678\\r"; '
        'expect "Enter the same PIN again"; send "5678\\r"; expect eof')
  '';
}
