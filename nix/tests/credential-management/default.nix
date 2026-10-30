{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-credential-management";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.setup_migration()
    env.expect_command("fido2-manage -setPIN -device 1",
        'expect "Enter new PIN"; send "1234\\r"; '
        'expect "Enter the same PIN again"; send "1234\\r"; expect eof')
    for user, rp in [("first", "manage.example.test"), ("second", "manage.example.test"), ("third", "other.example.test")]:
        machine.succeed(f"mkdir -p /tmp/{user}")
        machine.succeed(f"python3 ${../register.py} /tmp/{user} {rp} {user} {user} registration true 1234")
    machine.succeed("python3 ${./scenario.py}", timeout=45)
  '';
}
