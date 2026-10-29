{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "migration-rebind";
  reason = "Exercise PolicyAuthorize signing and rebinding one credential from a PCR-disabled baseline to PCR-bound and back using the management protocol.";
  testScript = ''
    scenario("${./scenario.py}", timeout=180)
  '';
}
