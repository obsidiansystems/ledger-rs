{ pkgs ? import <nixpkgs> {} }:
pkgs.rustPlatform.buildRustPackage {
  name = "ledger-rs";
  src = pkgs.lib.cleanSource ./.;
  # Requires that the ledger is plugged in, so turn tests off
  doCheck = false;
  nativeBuildInputs = [ pkgs.pkgconfig ];
  buildInputs = [ pkgs.openssl pkgs.libudev ];
  verifyCargoDeps = false;

  # Cargo hash must be updated when Cargo.lock file changes.
  # cargoSha256 = pkgs.lib.fakeSha256;
  cargoSha256 = "sha256:12sqyhz90ga77hz4lw9aqmp320b9n8l4w67gn2fqk9p8lzcz5ydc";
}

