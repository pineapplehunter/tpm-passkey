{ pkgs, package }:
pkgs.testers.runNixOSTest {
  extraPythonPackages = ps: [ (ps.callPackage ../python-package.nix { }) ];
  name = "tpm-passkey-management-access";
  nodes.machine.imports = [ (import ../machine.nix { inherit pkgs package; }) ];
  testScript = ''
    from tpm_passkey_test import TestEnv
    env = TestEnv(machine)
    env.start()

    env.setup_migration()
    machine.succeed("test ! -e /run/tpm-passkey/management.sock")
    actions = machine.succeed("pkaction")
    for suffix in ["register-agent", "read", "manage-migration", "manage-settings"]:
        assert "io.github.pineapplehunter.tpm-passkey." + suffix in actions
    machine.succeed("runuser -u alice -- tpm-passkey config show")
    machine.fail("runuser -u bob -- tpm-passkey config show")
    machine.succeed("runuser -u bob -- python3 ${./requests.py} --denied", timeout=30)
    machine.succeed("runuser -u alice -- python3 ${./requests.py}", timeout=60)
  '';
}
