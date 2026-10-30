{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-ctap-credentials";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.setup_migration()
    machine.succeed("python3 ${./scenario.py} credentials.example.test", timeout=90)
    assert env.mgmt("list --json").count("credentials.example.test") == 2
    machine.succeed("systemctl stop tpm-passkey")
    env.start_daemon()
    machine.succeed("python3 ${./scenario.py} credentials.example.test --reload-order", timeout=30)
  '';
}
