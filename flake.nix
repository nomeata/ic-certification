{
  inputs.nixpkgs.url = github:NixOS/nixpkgs/release-23.05;
  inputs.dfinity-sdk = {
    #url = "github:paulyoung/nixpkgs-dfinity-sdk";
    url = "github:nomeata/nixpkgs-dfinity-sdk/joachim/0.13.1";
    flake = false;
  };

  description = "Development environment";

  outputs = { self, nixpkgs, dfinity-sdk }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import dfinity-sdk) ];
      };

      vessel-src = pkgs.fetchFromGitHub {
        owner = "dfinity";
        repo = "vessel";
        rev = "v0.7.0";
        hash = "sha256-pQcC5RDnZOQGXdrcZolTprMEryBwbi58GqGYb61rGZQ=";
      };
      vessel = (import vessel-src { inherit system; }).vessel;

      # Generated with:
      # cd mops.nix/; nix run nixpkgs#node2nix -- -i <( echo '["ic-mops"]' ) -18
      mops = (import ./mops.nix { inherit system pkgs; }).ic-mops;

      dfx = (pkgs.dfinity-sdk {
        acceptLicenseAgreement = true;
        sdkSystem = system;
      }).latest;

    in
    {
      packages.x86_64-linux.dfx = dfx;
      packages.x86_64-linux.mops = mops;
      packages.x86_64-linux.vessel = vessel;
      devShell.x86_64-linux = pkgs.mkShell {
        buildInputs = [
          pkgs.wasmtime
          vessel
          (pkgs.ghc.withPackages(p: with p;
            [ cryptonite text tasty tasty-hedgehog containers
              memory typed-process quickcheck-instances
            ]))
          pkgs.ghcid
          dfx
          pkgs.dhall
          pkgs.nodejs
          mops
        ];
      };
    };
}
