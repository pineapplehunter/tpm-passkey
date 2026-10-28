{
  description = "A basic shell";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  inputs.flake-parts.url = "github:hercules-ci/flake-parts";
  inputs.treefmt-nix = {
    url = "github:numtide/treefmt-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay?ref=stable";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.flake-parts.flakeModules.easyOverlay
        inputs.treefmt-nix.flakeModule
        ./nix/tests/default.nix
        ./nix/module.nix
      ];

      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      perSystem =
        {
          pkgs,
          system,
          config,
          ...
        }:
        {
          packages.default = pkgs.callPackage ./nix/package.nix { };

          overlayAttrs = {
            tpm-passkey = config.packages.default;
          };

          treefmt = {
            projectRootFile = "flake.nix";

            programs = {
              nixfmt.enable = true;
              rustfmt.enable = true;
              taplo.enable = true;
            };
          };

          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.rust-overlay.overlays.default
              # Add overlays as needed
            ];
          };

          devShells.default =
            let
              sqlx-prepare-shell = pkgs.writeShellScriptBin "sqlx-prepare-script" ''
                set -x
                TMP=$(mktemp)
                trap "rm -rf $TMP" EXIT
                export SQLX_OFFLINE=false
                export DATABASE_URL=sqlite://$TMP
                cargo sqlx migrate run
                cargo sqlx prepare
              '';
            in
            pkgs.mkShell {
              env.SQLX_OFFLINE = "true";

              packages = with pkgs; [
                pkg-config
                rustPlatform.bindgenHook
                sqlx-cli
                tpm2-tss
                tpm2-tools
                sqlite
                sqlx-prepare-shell
                (rust-bin.stable.latest.default.override {
                  extensions = [
                    "rust-src"
                    "rust-analyzer"
                  ];
                  targets = [ ];
                })
              ];
            };

          # Uncomment to build any package with `nix build .#package`
          #legacyPackages = pkgs;
        };
    };
}
