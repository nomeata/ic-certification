{
  inputs.nixpkgs.url        = github:NixOS/nixpkgs/master;
  description = "Development environment for motoko-merkle-tree";

  outputs = { self, nixpkgs }:
    let
       pkgs = nixpkgs.legacyPackages.x86_64-linux;

       # Switch to dfinity/vessel once
       # https://github.com/dfinity/vessel/pull/70 is merged
       vessel-src = pkgs.fetchFromGitHub {
         owner = "dfinity";
         repo = "vessel";
         rev = "99661e40c4c47110129176ee9ecc61a50f1f60db";
         hash = "sha256-nrSxy6L+wg+g9PFQJ964ZW2bZyiE/ZJ5S5N281/I6ys=";
       };
       vessel = (import vessel-src { system = "x86_64-linux"; }).vessel;
    in
    {
      devShell.x86_64-linux = pkgs.mkShell {
        buildInputs = [
          pkgs.wasmtime
          vessel
          (pkgs.ghc.withPackages(p: with p;
            [ cryptonite text tasty tasty-hedgehog containers
              memory typed-process quickcheck-instances
            ]))
          pkgs.ghcid
        ];
      };
    };
}
