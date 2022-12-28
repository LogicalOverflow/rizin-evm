{
  description = "EVM support for rizin";

  inputs =  {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-22.05";
    unstable.url = "github:nixos/nixpkgs/nixos-unstable";

    nix-filter.url = "github:numtide/nix-filter";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, unstable, nix-filter, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        name = "rizin-evm";

        lib = nixpkgs.lib;
        pkgs = unstable.legacyPackages.${system};
      in rec {

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.ccls pkgs.bear
            pkgs.meson pkgs.ninja
            pkgs.gnumake pkgs.pkg-config
            pkgs.rizin pkgs.openssl
          ];
          # ] ++ packages.default.nativeBuildInputs ++ packages.default.buildInputs;
        };
      });
}
