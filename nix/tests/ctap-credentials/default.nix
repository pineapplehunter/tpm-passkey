{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "ctap-credentials";
  reason = "Verify MakeCredential/GetAssertion wire shapes, real signatures, PIN protocols 1/2, RP scoping, exclusion and accurate UP/UV/extension flags.";
  testScript = ''
    setup_migration()
    machine.succeed("python3 ${./scenario.py} credentials.example.test", timeout=90)
    assert mgmt("list --json").count("credentials.example.test") == 2
  '';
}
