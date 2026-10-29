{ pkgs, package }:
{
  name,
  reason,
  testScript,
  extraMachineConfig ? { },
  allowReboot ? false,
}:
pkgs.testers.runNixOSTest {
  name = "tpm-passkey-${name}";
  nodes.machine.imports = [
    (import ./machine.nix { inherit pkgs package; })
    extraMachineConfig
  ];
  testScript =
    "print(${builtins.toJSON reason})\n"
    + "python_helpers = '${pkgs.writeTextDir "tpm_test_bus.py" (builtins.readFile ./tpm_test_bus.py)}'\n"
    + (if allowReboot then "machine.start(allow_reboot=True)\n" else "")
    + builtins.readFile ./driver.py
    + "\n"
    + testScript;
}
