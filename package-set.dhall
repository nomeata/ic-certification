let upstream =
      https://github.com/dfinity/vessel-package-set/releases/download/mo-0.8.4-20230311/package-set.dhall sha256:bf5cec8ba99cfa6abcdb793a4aeaea9f4c913a4bd97af0a556bd6e81aaf75cd4


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

