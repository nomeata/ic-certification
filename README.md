# ic-certification

This Motoko library provides functionality around “Certification”, in particular

 * An labeled tree data sturcture with merkelization (`MerkleTree`) and the abilityt o
   generate witnesses according to Internet Computer Interface Specification.
 * Support for the “Canister Signature scheme” that builds on top of that.
 * Utilities related to the “Implementation-independent hash” that is used,
   among other things, for signing HTTP requests to the Internet Computer

See <https://nomeata.github.io/ic-certification/> for the docuemntation of the
current development version.

The `demo/` directory contains a commented  canister demonstrating these features; it is also live
at <https://wpsi7-7aaaa-aaaai-acpzq-cai.ic0.app/>.

## Developemnt and testing

TODO

## License

This library is distributed under the terms of the Apache License (Version 2.0). See LICENSE for details.
