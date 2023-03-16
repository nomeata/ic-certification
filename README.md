# ic-certification

This Motoko library provides functionality around “Certification”, in particular

 * A labeled tree data sturcture with merkelization (`MerkleTree`) and the ability to
   generate witnesses according to Internet Computer Interface Specification.
 * Support for the “Canister Signature scheme” that builds on top of that.
 * Utilities related to the “Implementation-independent hash” that is used,
   among other things, for signing HTTP requests to the Internet Computer

See <https://nomeata.github.io/ic-certification/> for the docuemntation of the
current development version.

The `demo/` directory contains a commented  canister demonstrating these features; it is also live
at <https://wpsi7-7aaaa-aaaai-acpzq-cai.ic0.app/>.

## Installation

TODO

## Developemnt and testing

A `nix` based development environment installing `dfx` and `vessel` and Haskell is provided; just
run `nix develop` to enter it.

Run `make docs` to generate the documentation locally. Via github actions, this is also available
at <https://nomeata.github.io/ic-certification/>.

Direcory `test` contains a small test suite, mostly for the `Dyadic` helper module, using the
Motoko matcher's library. 

In `gen-tests` you will find a Haskell program that generates random trees and witnesses and checks
that they behave as expected.  Just run `cabal run gen-tests` in that directory.
The Haskell code implements the same logic for how to structure the binary
trees, and thus can also serve as a specification. It exercises the `MerkleTree` module mostly.
The other (less hairy) modules are exercised thoroughly.

## License

This library is distributed under the terms of the Apache License (Version 2.0). See LICENSE for details.
