{
  inputs.nixpkgs.url = github:NixOS/nixpkgs/master;
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
        rev = "99661e40c4c47110129176ee9ecc61a50f1f60db";
        hash = "sha256-nrSxy6L+wg+g9PFQJ964ZW2bZyiE/ZJ5S5N281/I6ys=";
      };
      vessel = (import vessel-src { inherit system; }).vessel;

      # Generated with node2nix -i <( echo '["ic-mops"]' )
      mops = (import ./mops.nix { inherit system pkgs; }).ic-mops;

      dfx = (pkgs.dfinity-sdk {
        acceptLicenseAgreement = true;
        sdkSystem = system;
      }).latest;

    in
    {
      packages.x86_64-linux.dfx = dfx;
      packages.x86_64-linux.mops = mops;
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
