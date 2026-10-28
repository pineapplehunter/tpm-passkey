{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "optional-pcr";
  reason = "Prove PCR binding is opt-in, never retrofits existing keys, survives explicit disabling, and requires configured/unlocked recovery for new bound keys.";
  testScript = ''
    machine.succeed("python3 ${./scenario.py}", timeout=180)
  '';
}
