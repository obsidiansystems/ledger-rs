{ pkgsFun ? import (import ./nix/nixpkgs/thunk.nix)

, rustOverlay ? import "${import ./nix/nixpkgs-mozilla/thunk.nix}/rust-overlay.nix"

# Rust manifest hash must be updated when rust-toolchain file changes.
, rustPackages ? pkgs.rustChannelOf {
    date = "2020-05-04";
    rustToolchain = ./rust-toolchain;
    sha256 = "0yvh2ck2vqas164yh01ggj4ckznx04blz3jgbkickfgjm18y269j";
  }

, pkgs ? pkgsFun {
    overlays = [
      rustOverlay
    ];
  }

, gitignoreNix ? import ./nix/gitignore.nix/thunk.nix

}:

let
  rustPlatform = pkgs.makeRustPlatform {
    inherit (rustPackages) cargo;
    rustc = rustPackages.rust;
  };
  inherit (import gitignoreNix { inherit (pkgs) lib; }) gitignoreSource;
in rustPlatform.buildRustPackage {
  name = "ckb";
  src = gitignoreSource ./.;
  # Requires that the ledger is plugged in, so turn tests off
  doCheck = false;
  nativeBuildInputs = with pkgs.buildPackages; [ pkg-config protobuf ];
  buildInputs = with pkgs; [ openssl libudev ];
  verifyCargoDeps = true;

  # Cargo hash must be updated when Cargo.lock file changes.
  cargoSha256 = "1qsc8mx6xc7qaqkn92ybb3f9fhz01y2snzfi80dcqzm8f276c43p";
}
