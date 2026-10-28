{
  perSystem =
    {
      lib,
      pkgs,
      config,
      ...
    }:
    {
      checks.nixos-pcr = pkgs.testers.runNixOSTest {
        name = "linux-tpm-fido2-optional-pcr";
        nodes.machine = {
          imports = [ ./nixos-module.nix ];
          virtualisation.tpm.enable = true;
          users.users.alice = {
            isNormalUser = true;
            password = "alice";
          };
          services.linux-tpm-fido2 = {
            enable = true;
            package = config.packages.default;
            tpmPath = "/dev/tpm0";
          };
          systemd.services.linux-tpm-fido2.wantedBy = lib.mkForce [ ];
          security.polkit.extraConfig = ''
            polkit.addRule(function(action, subject) {
              if (action.id == "io.github.pineapplehunter.linux-tpm-fido2.approve"
                  && subject.user == "alice") {
                return polkit.Result.YES;
              }
            });
          '';
          environment.systemPackages = with pkgs; [
            tpm2-tools
            (python3.withPackages (ps: [
              ps.cbor2
              ps.fido2
            ]))
          ];
        };
        testScript = ''
          machine.wait_for_unit("getty@tty1.service")
          machine.send_key("ctrl-alt-f1")
          machine.wait_until_tty_matches("1", "login:")
          machine.send_chars("alice\n")
          machine.wait_until_tty_matches("1", "Password:")
          machine.send_chars("alice\n")
          machine.wait_until_tty_matches("1", "alice@")
          machine.succeed("systemctl start linux-tpm-fido2")
          machine.wait_for_unit("linux-tpm-fido2")
          try:
              machine.succeed("python3 ${./tests/pcr_binding.py}", timeout=180)
          except Exception:
              print(machine.succeed("journalctl -u linux-tpm-fido2 --no-pager -n 100"))
              raise
        '';
      };
    };
}
