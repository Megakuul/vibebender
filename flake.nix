{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/25.11";
  };

  outputs = {self, ...} @ inputs: let
    systems = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  in {
    devShells = inputs.nixpkgs.lib.genAttrs systems (
      system: let
        pkgs = import inputs.nixpkgs {inherit system;};
      in {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gotools
            go-tools
            gofumpt
            ppp
          ];
        };
      }
    );
  };
}
