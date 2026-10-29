{
  perSystem =
    {
      lib,
      pkgs,
      config,
      ...
    }:
    {
      checks = lib.listToAttrs (
        map
          (name: {
            name = "nixos-${name}";
            value = pkgs.callPackage (./. + "/${name}/default.nix") {
              inherit pkgs;
              package = {
                daemon = config.packages.daemon;
                cli = config.packages.cli;
                gtk = config.packages.approval-gtk;
              };
            };
          })
          [
            "management"
            "management-access"
            "ctap-transport"
            "ctap-credentials"
            "credential-management"
            "pin-management"
            "factory-reset"
            "state-integrity"
            "approval-cancel"
            "approval-lifecycle"
            "gtk-approval"
            "optional-pcr"
            "signing-sessions"
            "recovery-rotation"
            "recovery-reboot"
          ]
      );
    };
}
