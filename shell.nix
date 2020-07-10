{ pkgs ? import <nixpkgs> {}}:
(import ./. {}).overrideAttrs(p: {
  nativeBuildInputs = [ pkgs.rustfmt pkgs.cargo-watch ] ++ p.nativeBuildInputs;
})
