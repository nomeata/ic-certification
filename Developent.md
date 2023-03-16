## Developemnt and testing

A `nix` based development environment installing `dfx`, `vessel`, `mops` and
Haskell is provided; just run `nix develop` to enter it.

Run `make docs` to generate the documentation locally. Via github actions, this is also available
at <https://nomeata.github.io/ic-certification/>.

Direcory `test` contains a small test suite, mostly for the `Dyadic` helper module, using the
Motoko matcher's library. 

In `gen-tests` you will find a Haskell program that generates random trees and witnesses and checks
that they behave as expected.  Just run `cabal run gen-tests` in that directory.
The Haskell code implements the same logic for how to structure the binary
trees, and thus can also serve as a specification. It exercises the `MerkleTree` module mostly.
The other (less hairy) modules are exercised thoroughly.
