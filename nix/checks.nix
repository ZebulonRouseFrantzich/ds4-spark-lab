{ pkgs }:
{
  formatting =
    pkgs.runCommand "nixfmt-check"
      {
        nativeBuildInputs = [ pkgs.nixfmt-tree ];
      }
      ''
        mkdir -p source/nix
        cp ${../flake.nix} source/flake.nix
        cp ${./tooling.nix} source/nix/tooling.nix
        cp ${./dev-shell.nix} source/nix/dev-shell.nix
        cp ${./checks.nix} source/nix/checks.nix
        cd source
        treefmt --ci --tree-root "$PWD" --walk filesystem
        touch "$out"
      '';
}
