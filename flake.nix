{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    devenv.url = "github:cachix/devenv";
  };

  outputs = { self, nixpkgs, devenv, systems, ... } @ inputs:
    let
      forEachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      packages = forEachSystem (system: {
        devenv-up = self.devShells.${system}.default.config.procfileScript;
      });

      devShells = forEachSystem
        (system:
          let
            pkgs = nixpkgs.legacyPackages.${system};
          in
          {
            default = devenv.lib.mkShell {
              inherit inputs pkgs;
              modules = [
                ({ pkgs, lib, config, ... }: {
                  dotenv.disableHint = true;

                  languages.c= {
                    enable = true;
                  };

                  git-hooks.excludes = [ ".devenv" ];
                  git-hooks.hooks = {
                    # clang-tidy.enable = true;
                  };

                  packages = with pkgs; [
                    llvm
                  ];
                })
              ];
            };
          });
    };
}
