{ pkgs }:
pkgs.mkShellNoCC {
  packages = import ./tooling.nix { inherit pkgs; };

  UV_PYTHON_DOWNLOADS = "never";
  UV_NO_MANAGED_PYTHON = "1";
  UV_PYTHON = "${pkgs.python3}/bin/python";
}
