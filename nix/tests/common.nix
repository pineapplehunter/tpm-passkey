{ pkgs, package }:
{
  name,
  reason,
  testScript,
}:
pkgs.testers.runNixOSTest {
  name = "tpm-passkey-${name}";
  nodes.machine = import ./machine.nix { inherit pkgs package; };
  testScript =
    "print(${builtins.toJSON reason})\n" + builtins.readFile ./driver.py + "\n" + testScript;
}
