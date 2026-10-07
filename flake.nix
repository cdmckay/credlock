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
          # The last release, from VERSION, plus the commit it was built from:
          # a build of main between releases is "0.1.0+6d36c09", not "0.1.0".
          release = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
          version = "${release}+${self.shortRev or self.dirtyShortRev or "unknown"}";
        in
        {
          default = pkgs.buildGoModule {
            pname = "credlock";
            inherit version;
            src = self;
            vendorHash = "sha256-mV/B7JaCEIwmW1slxvaGFuys96AgZ21/yxUlccvXz24=";
            # The 1Password SDK's desktop-app sign-in needs cgo, on a Mac. On
            # Linux credlock only asks a Mac in hub mode, so it builds without.
            env.CGO_ENABLED = if pkgs.stdenv.hostPlatform.isDarwin then 1 else 0;
            ldflags = [ "-s" "-w" "-X main.version=${version}" ];
            meta = {
              description = "Hand secrets to one command at a time, after you've seen what is asked for and why";
              homepage = "https://github.com/cdmckay/credlock";
              license = pkgs.lib.licenses.gpl3Plus;
              mainProgram = "credlock";
              platforms = pkgs.lib.platforms.darwin ++ pkgs.lib.platforms.linux;
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
