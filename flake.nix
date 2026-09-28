{
  description = "credlock: hand secrets to one command at a time, after you've seen what is asked for and why";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.buildGoModule {
            pname = "credlock";
            version = "0.1.0";
            src = self;
            vendorHash = "sha256-2Scqr95ip4s3UujpBA57hghlywkimUCLsVaaldSbM1E=";
            # The 1Password SDK's desktop-app sign-in needs cgo.
            env.CGO_ENABLED = 1;
            ldflags = [ "-s" "-w" "-X main.version=0.1.0" ];
            meta = {
              description = "Hand secrets to one command at a time, after you've seen what is asked for and why";
              homepage = "https://github.com/cdmckay/credlock";
              license = pkgs.lib.licenses.gpl3Plus;
              mainProgram = "credlock";
              platforms = pkgs.lib.platforms.darwin;
            };
          };
        });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gopls
              pkgs.golangci-lint
            ];
          };
        });
    };
}
