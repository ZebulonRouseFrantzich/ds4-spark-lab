{ pkgs }:
let
  gitSsh = pkgs.writeShellScript "ds4-git-ssh" ''
    if [[ -r "''${HOME}/.ssh/config" ]]; then
      exec ${pkgs.openssh}/bin/ssh -F "''${HOME}/.ssh/config" "$@"
    fi

    exec ${pkgs.openssh}/bin/ssh -F /dev/null "$@"
  '';
in
pkgs.mkShellNoCC {
  packages = import ./tooling.nix { inherit pkgs; };

  GIT_SSH = "${gitSsh}";
  UV_PYTHON_DOWNLOADS = "never";
  UV_NO_MANAGED_PYTHON = "1";
  UV_PYTHON = "${pkgs.python3}/bin/python";
}
