let upstream =
      https://github.com/dfinity/vessel-package-set/releases/download/mo-0.10.0-20230911/package-set.dhall sha256:7bce6afe8b96a8808f66b5b6f7015257d44fc1f3e95add7ced3ccb7ce36e5603

{-
let additions = [
   { name = "cbor"
   , repo = "https://github.com/gekctek/motoko_cbor"
   , version = "v1.0.1"
   , dependencies = [ "xtended-numbers" ] : List Text
   },
   { name = "xtended-numbers"
   , version = "v1.0.2"
   , repo = "https://github.com/edjcase/motoko_numbers"
   , dependencies = [] : List Text
   }
]
in upstream # additions
-}

in upstream

