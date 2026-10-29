{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "management-access";
  reason = "Run management as group-member Alice and nonmember Bob; verify real polkit gates, noninteractive registration, sealed-FD validation and operation/authentication binding.";
  testScript = ''
    setup_migration()
    machine.succeed("test ! -e /run/tpm-passkey/management.sock")
    actions = machine.succeed("pkaction")
    for suffix in ["register-agent", "read", "manage-migration", "manage-settings"]:
        assert "io.github.pineapplehunter.tpm-passkey." + suffix in actions
    machine.succeed("runuser -u alice -- tpm-passkey config show")
    machine.fail("runuser -u bob -- tpm-passkey config show")
    machine.succeed("runuser -u bob -- env PYTHONPATH=" + shlex.quote(python_helpers) + " python3 ${./requests.py} --denied", timeout=30)
    machine.succeed("runuser -u alice -- env PYTHONPATH=" + shlex.quote(python_helpers) + " python3 ${./requests.py}", timeout=60)
  '';
}
