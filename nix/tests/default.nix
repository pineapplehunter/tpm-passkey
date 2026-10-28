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
              package = config.packages.default;
            };
          })
          [
            "management"
            "ctap-transport"
            "ctap-credentials"
            "credential-management"
            "pin-management"
            "factory-reset"
            "state-integrity"
            "approval-cancel"
            "optional-pcr"
            "signing-sessions"
            "recovery-rotation"
            "recovery-reboot"
          ]
      );
    };
}
