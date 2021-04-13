{-
 - This program generates some test cases for motoko-merkle-tree.
 -}

{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE OverloadedStrings #-}

import qualified Data.Map.Lazy as M
import qualified Data.Set as S
import qualified Data.ByteString.Lazy as BS
import Crypto.Hash (hashlazy, SHA256)
import Data.ByteArray (convert)
import System.Process.Typed
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.ByteString
import Text.Printf
import Data.List
import Numeric

type Blob = BS.ByteString
type Path = [Label]
type Label = Blob
type Value = Blob
type Hash = Blob


moSrc pairs reveal exp_w = unlines $
  [ "import Debug \"mo:base/Debug\";"
  , "import MerkleTree \"src/MerkleTree\";"
  , "var t = MerkleTree.empty();"
  ] ++
  [ printf "t := MerkleTree.put(t, %s, %s);" (moBlob k) (moBlob v)
  | (k,v) <- pairs
  ] ++
  [ printf "let w = MerkleTree.reveals(t, [%s].vals());" $
    intercalate ", " [ printf "%s : Blob" (moBlob k) | k <- reveal ]
  ] ++
  [ "Debug.print(debug_show w);"
  , printf "assert (w == %s);" (moT exp_w) ]

moT :: HashTree -> String
moT EmptyTree = "#empty"
moT (Fork t1 t2) = printf "#fork(%s,%s)" (moT t1) (moT t2)
moT (Labeled l t) = printf "#labeled(%s,%s)" (moBlob l) (moT t)
moT (Leaf v) = printf "#leaf(%s)" (moBlob v)
moT (Pruned h) = printf "#pruned(%s)" (moBlob h)

moBlob :: BS.ByteString -> String
moBlob = dblQuote . concatMap (printf "\\%02x") . BS.unpack

dblQuote :: String -> String
dblQuote = printf "\"%s\""

propSHA256 = do
  blob <- arbitrary
  let src = test_src blob (h blob)
  return $
    counterexample ("Failing src:\n" <> src) $
    ioProperty $ do
      writeFile "../tmp.mo" src
      runProcess_ (shell "cd .. && $(vessel bin)/moc $(vessel sources) -wasi-system-api tmp.mo")
      runProcess_ (shell "cd .. && wasmtime tmp.wasm")

  where
    test_src b e = unlines
      [ "import Debug \"mo:base/Debug\";"
      , "import SHA256 \"mo:sha256/SHA256\";"
      , "import Blob \"mo:base/Blob\";"
      , printf "let h = Blob.fromArray(SHA256.sha256(Blob.toArray(%s)));" (moBlob b)
      , "Debug.print(debug_show h);"
      , printf "assert (h == (%s : Blob));" (moBlob e)
      ]

propPruned = do
  pairs <- arbitrary
  included <- sublistOf (map fst pairs)
  extra <- arbitrary
  reveal <- shuffle (included ++ extra)

  let tree = construct (SubTrees (M.fromList [ (h k, Value (h v)) | (k,v) <- pairs ]))
  let witness = prune tree [[h k]| k <- reveal]

  let src = moSrc pairs reveal witness

  return $
    counterexample ("Failing src:\n" <> src) $
    ioProperty $ do
      writeFile "../tmp.mo" src
      runProcess_ (shell "cd .. && $(vessel bin)/moc $(vessel sources) -wasi-system-api tmp.mo")
      runProcess_ (shell "cd .. && wasmtime tmp.wasm")

main = defaultMain $
    testGroup "tests"
        [ testProperty "SHA256 test" propSHA256
        , testProperty "witness tests" propPruned
        ]


-- HashTree implementation below

data LabeledTree
    = Value Value
    | SubTrees (M.Map Blob LabeledTree)
  deriving Show

data HashTree
    = EmptyTree
    | Fork HashTree HashTree
    | Labeled Blob HashTree
    | Leaf Value
    | Pruned Hash
  deriving Show

construct :: LabeledTree -> HashTree
construct (Value v) = Leaf v
construct (SubTrees m) =
    foldBinary EmptyTree Fork
        [ Labeled k (construct v) | (k,v) <- M.toAscList m ]

foldBinary :: a -> (a -> a -> a) -> [a] -> a
foldBinary e (⋔) = go
  where
    go [] = e
    go [x] = x
    go xs = go xs1 ⋔ go xs2
      where (xs1, xs2) = splitAt (length xs `div` 2) xs

reconstruct :: HashTree -> Hash
reconstruct = go
  where
    go EmptyTree     = h $ domSep "ic-hashtree-empty"
    go (Fork t1 t2)  = h $ domSep "ic-hashtree-fork" <> go t1 <> go t2
    go (Labeled l t) = h $ domSep "ic-hashtree-labeled" <> l <> go t
    go (Leaf v)      = h $ domSep "ic-hashtree-leaf" <> v
    go (Pruned h)    = h


h :: BS.ByteString -> BS.ByteString
h = BS.fromStrict . convert . hashlazy @SHA256

domSep :: Blob -> Blob
domSep s = BS.singleton (fromIntegral (BS.length s)) <> s


flatten :: HashTree -> [HashTree]
flatten t = go t [] -- using difference lists
  where
    go EmptyTree = id
    go (Fork t1 t2) = go t1 . go t2
    go t = (t:)

prune :: HashTree -> [Path] -> HashTree
prune tree [] = Pruned (reconstruct tree)
prune tree paths | [] `elem` paths = tree
prune tree paths = go tree
  where
    -- These labels are availbale
    present :: S.Set Label
    present = S.fromList [ l | Labeled l _ <- flatten tree]

    -- We need all requested labels, and if not present, the immediate neighbors
    -- This maps labels to paths at that label that we need
    wanted :: M.Map Label (S.Set Path)
    wanted = M.fromListWith S.union $ concat
        [ if l `S.member` present
          then [ (l, S.singleton p) ]
          else
            [ (l', S.empty) | Just l' <- pure $ l `S.lookupLT` present ] ++
            [ (l', S.empty) | Just l' <- pure $ l `S.lookupGT` present ]
        | l:p <- paths ]

    -- Smart constructor to avoid unnecessary forks
    fork t1 t2
        | prunedOrEmpty t1, prunedOrEmpty t2 = Pruned (reconstruct (Fork t1 t2))
        | otherwise = Fork t1 t2
      where
        prunedOrEmpty (Pruned _) = True
        prunedOrEmpty EmptyTree = True
        prunedOrEmpty _ = False

    go EmptyTree = EmptyTree
    go (Labeled l subtree)
        | Just path_tails <- M.lookup l wanted = Labeled l (prune subtree (S.toList path_tails))
    go (Fork t1 t2) = fork (go t1) (go t2)
    go tree = Pruned (reconstruct tree)

