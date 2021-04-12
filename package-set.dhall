let upstream =
      https://github.com/dfinity/vessel-package-set/releases/download/mo-0.5.14-20210409/package-set.dhall sha256:8ebfd1c83165bbbc3e961b0deb7f4dad6e55935c93a6e580b7b884d5661c8cbe

let additions = [
   { name = "sha256"
   , repo = "https://github.com/nomeata/motoko-sha.git"
   , version = "90cbfc3b6c131767027fdd910393a5766208142c"
   , dependencies = ["base"]
   }
]
in upstream # additions

