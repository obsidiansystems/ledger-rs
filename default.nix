{ pkgs ? import <nixpkgs> {} }:
pkgs.rustPlatform.buildRustPackage {
  name = "ledger-rs";
  src = ./.;
  # Requires that the ledger is plugged in, so turn tests off
  doCheck = false;
  nativeBuildInputs = [ pkgs.pkgconfig ];
  buildInputs = [ pkgs.openssl pkgs.libudev ];
  verifyCargoDeps = false;

  # Cargo hash must be updated when Cargo.lock file changes.
  cargoSha256 = "08vz4nx25rrqnc7plzzv12bxvvl6d5lvzcnkvq2haw1r5rw41irm";
}

