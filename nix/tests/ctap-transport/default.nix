{ pkgs, package }:
(import ../common.nix { inherit pkgs package; }) {
  name = "ctap-transport";
  reason = "Check HID fragmentation/echo and truthful GetInfo capabilities independently of credential setup, and reject unimplemented CTAP commands.";
  testScript = ''
    machine.succeed("python3 ${./transport.py}", timeout=30)
  '';
}
