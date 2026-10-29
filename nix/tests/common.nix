{ pkgs, package }:
{
  name,
  reason,
  testScript,
  extraMachineConfig ? { },
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
    + builtins.readFile ./driver.py
    + "\n"
    + testScript;
}
