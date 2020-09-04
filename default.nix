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
  # cargoSha256 = pkgs.lib.fakeSha256;
  cargoSha256 = "0kccfnqvd4bbk6zl6y3p4s40qjn01yqrbfg6d13c95l92crcxwxf";
}

