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
          linux = pkgs.stdenv.hostPlatform.isLinux;
          credlock = { window }: pkgs.buildGoModule {
            pname = "credlock";
            inherit version;
            src = self;
            vendorHash = "sha256-Ssq9zE5Zs620sVXvZ/t3aXBtBVCso8qfxbGxsEIPXMU=";
            # The 1Password SDK's desktop-app sign-in needs cgo: it loads the
            # app's library at run time, on Linux as on a Mac.
            env.CGO_ENABLED = 1;
            # On Linux the approval window is GTK 4 and libadwaita, behind the
            # gtk build tag. Without it credlock only asks a hub.
            tags = pkgs.lib.optional (linux && window) "gtk";
            nativeBuildInputs = pkgs.lib.optional (linux && window) pkgs.pkg-config;
            buildInputs = pkgs.lib.optionals (linux && window) [ pkgs.gtk4 pkgs.libadwaita ];
            ldflags = [ "-s" "-w" "-X main.version=${version}" ];
            meta = {
              description = "Hand secrets to one command at a time, after you've seen what is asked for and why";
              homepage = "https://github.com/cdmckay/credlock";
              license = pkgs.lib.licenses.gpl3Plus;
              mainProgram = "credlock";
              platforms = pkgs.lib.platforms.darwin ++ pkgs.lib.platforms.linux;
            };
          };
        in
        {
          default = credlock { window = true; };
          # For machines that only ask a hub, such as servers: no window, so
          # no GTK. On a Mac it is the same as default.
          headless = credlock { window = false; };
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
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              # The approval window's build: go build -tags gtk.
              pkgs.pkg-config
              pkgs.gtk4
              pkgs.libadwaita
            ];
          };
        });
    };
}
