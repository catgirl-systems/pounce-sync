{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  packages = with pkgs; [
    go
    gopls
    sqlite
  ];

  # the sqlite driver is cgo
  CGO_ENABLED = "1";
}
