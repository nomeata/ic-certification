{-
 - This program generates some test cases for motoko-merkle-tree.
 -}

{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Map.Lazy as M
import qualified Data.Set as S
import qualified Data.ByteString.Lazy as BS
import Control.Monad
import Control.Monad.IO.Class
import Control.Applicative
import Crypto.Hash (hashlazy, SHA256)
import Data.Bits
import Data.Maybe
import Data.ByteArray (convert)
import Data.List hiding (insert)
import GHC.Stack
import Hedgehog
import Hedgehog.Gen hiding (constant)
import Hedgehog.Range
import Numeric
import System.Exit
import System.Process.Typed
import Test.Tasty
import Test.Tasty.Hedgehog
import Text.Printf

type Blob = BS.ByteString
type Path = [Label]
type Label = Blob
type Value = Blob
type Hash = Blob
type Pairs = [(Path, Value)]

moSrc :: Pairs -> [Path] -> HashTree -> String
moSrc pairs reveal exp_w = unlines $
  [ "import Debug \"mo:base/Debug\";"
  , "import MerkleTree \"src/MerkleTree\";"
  , "var t = MerkleTree.empty();"
  ] ++
  [ printf "t := MerkleTree.put(t, %s, %s);" (moBlobs k) (moBlob v) | (k,v) <- pairs ] ++
  [ printf "let w = MerkleTree.reveals(t, [%s].vals());" $
    intercalate ", " [ moBlobs k | k <- reveal ]
  ] ++
  [ "Debug.print(debug_show t);"
  , "Debug.print(debug_show w);"
  , printf "assert (w == %s);" (moT exp_w)
  , printf "assert (MerkleTree.reconstruct w == MerkleTree.treeHash t);"
  ]

moSrcDel :: Pairs -> [Path] -> Pairs -> String
moSrcDel pairs1 dps pairs2 = unlines $
  [ "import Debug \"mo:base/Debug\";"
  , "import MerkleTree \"src/MerkleTree\";"
  , "var t1 = MerkleTree.empty();" ] ++
  [ printf "t1 := MerkleTree.put(t1, %s, %s);" (moBlobs k) (moBlob v) | (k,v) <- pairs1 ] ++
  [ "var t2 = t1;" ] ++
  [ printf "t2 := MerkleTree.delete(t2, %s);" (moBlobs k) | k <- dps ] ++
  [ "var t3 = MerkleTree.empty();" ] ++
  [ printf "t3 := MerkleTree.put(t3, %s, %s);" (moBlobs k) (moBlob v) | (k,v) <- pairs2 ] ++
  [ "Debug.print(debug_show (MerkleTree.structure t1));"
  , "Debug.print(debug_show (MerkleTree.structure t2));"
  , "Debug.print(debug_show (MerkleTree.structure t3));"
  , printf "assert (t2 == t3);"
  ]

moT :: HashTree -> String
moT EmptyTree = "#empty"
moT (Fork t1 t2) = printf "#fork(%s,%s)" (moT t1) (moT t2)
moT (Labeled l t) = printf "#labeled(%s,%s)" (moBlob l) (moT t)
moT (Leaf v) = printf "#leaf(%s)" (moBlob v)
moT (Pruned h) = printf "#pruned(%s)" (moBlob h)

moBlob :: BS.ByteString -> String
moBlob = dblQuote . concatMap (printf "\\%02x") . BS.unpack
moBlobs :: [BS.ByteString] -> String
moBlobs = printf "([%s] : [Blob])" . intercalate ", " . fmap moBlob

dblQuote :: String -> String
dblQuote = printf "\"%s\""

lbytes :: (Alternative m, MonadGen m) => m BS.ByteString
lbytes = fmap BS.fromStrict $
    element ["", "a", "b", "c"] <|>
    bytes (constant 0 3) <|>
    bytes (linear 0 70)

propSHA256 = property $ do
    blob <- forAll lbytes
    let src = test_src blob (h blob)
    annotate src -- Generated sourced
    evalIO $ writeFile "../tmp.mo" src
    runCommand "cd .. && $(vessel bin)/moc $(mops sources) -no-check-ir -wasi-system-api tmp.mo"
    runCommand "cd .. && wasmtime tmp.wasm"
  where
    test_src b e = unlines
      [ "import Debug \"mo:base/Debug\";"
      , "import SHA256 \"mo:sha2/Sha256\";"
      , "import Blob \"mo:base/Blob\";"
      , printf "let h = SHA256.fromBlob(#sha256, %s);" (moBlob b)
      , "Debug.print(debug_show h);"
      , printf "assert (h == (%s : Blob));" (moBlob e)
      ]

runCommand :: (HasCallStack, MonadTest m, MonadIO m) => String -> m ()
runCommand cmd = do
  (ex,stderr, stdout) <- evalIO $ readProcess (shell cmd)
  unless (BS.null stdout) $ annotate $
    printf "%s (stdout)\n:%s\n" cmd (T.unpack (T.decodeUtf8 (BS.toStrict stdout)))
  unless (BS.null stderr) $ annotate $
    printf "%s (stderr)\n:%s\n" cmd (T.unpack (T.decodeUtf8 (BS.toStrict stderr)))
  ex === ExitSuccess

propPruned = property $ do
  ls :: [Label] <- forAll $ nub <$> list (linear 1 10) lbytes
  ps :: [Path] <- forAll $ list (linear 0 10) (nub <$> list (constant 0 3) (element ls))
  vs :: [Blob] <- forAll $ mapM (const lbytes) ps
  let pairs = zip ps vs
  included :: [Path] <- forAll $ subsequence ps
  extra :: [Path] <- forAll $ nub <$> list (linear 0 3) (nub <$> list (constant 0 3) (element ls))
  reveal :: [Path] <- forAll $ prune $ shuffle (included ++ extra)

  let tree = construct (fromList [ (p, v) | (p,v) <- pairs ])
  let witness = pruneTree tree reveal
  annotate (moT tree)
  annotate (moT witness)

  let src = moSrc pairs reveal witness
  -- annotate src -- Generated sourced
  evalIO $ writeFile "../tmp.mo" src
  runCommand "cd .. && $(vessel bin)/moc $(mops sources) -no-check-ir -wasi-system-api tmp.mo"
  runCommand "cd .. && wasmtime tmp.wasm"

propDelete = property $ do
  ls :: [Label] <- forAll $ nub <$> list (linear 1 10) lbytes
  ps :: [Path] <- forAll $ list (linear 0 10) (nub <$> list (constant 0 3) (element ls))
  vs :: [Blob] <- forAll $ mapM (const lbytes) ps
  let pairs = zip ps vs
  included :: [Path] <- forAll $ subsequence ps
  extra :: [Path] <- forAll $ nub <$> list (linear 0 3) (nub <$> list (constant 0 3) (element ls))
  dps :: [Path] <- forAll $ shuffle (included ++ extra)

  let pairs2 = [ (p, v)
               | (p, v) <- afterInsertion pairs
               , not (any (\d -> d `conflicts` p) dps)
               ]
  annotate $ show pairs
  annotate $ show pairs2

  let src = moSrcDel pairs dps pairs2
  -- annotate src -- Generated sourced
  evalIO $ writeFile "../tmp.mo" src
  runCommand "cd .. && $(vessel bin)/moc $(mops sources) -no-check-ir -wasi-system-api tmp.mo"
  runCommand "cd .. && wasmtime tmp.wasm"


conflicts :: Path -> Path -> Bool
conflicts p1 p2 = p1 `isPrefixOf` p2 || p2 `isPrefixOf` p1

-- Removes those elements that will be overriden later
afterInsertion :: Pairs -> Pairs
afterInsertion [] = []
afterInsertion ((k,v): ps)
    | throw_out = afterInsertion ps
    | otherwise = (k,v) : afterInsertion ps
  where throw_out = any (\(k',_) -> k `conflicts` k') ps

main = defaultMain $
    testGroup "tests"
        [ testProperty "SHA256" propSHA256
        , testProperty "witness" propPruned
        , testProperty "delete" propDelete
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

insert :: Path -> Value -> LabeledTree -> LabeledTree
insert [] v _ = Value v
insert (k:ps) v (Value _) = insert (k:ps) v (SubTrees M.empty)
insert (k:ps) v (SubTrees m) = SubTrees (M.alter go k m)
  where
    go old = Just $ insert ps v (fromMaybe (SubTrees M.empty) old)

fromList :: Pairs -> LabeledTree
fromList = foldl' (\t (p,v) -> insert p v t) (SubTrees M.empty)

construct :: LabeledTree -> HashTree
construct (Value v) = Leaf v
construct (SubTrees m) = go 0 (M.toAscList m)
  where
    go _ [] = EmptyTree
    go _ [(k,t)] = singleton (k,t)
    go i xs =
        go (error "this should not happen") xs1
        `fork` (go (i+1) xs2 `fork` go (i+1) xs3)
      where
        (xs1', xs3) = span (isBitUnset i . fst) xs
        (xs1, xs2) = span (\(k,_) -> BS.length k == fromIntegral (i `div` 8)) xs1'

    singleton (k,t) = Labeled k (construct t)

    isBitUnset :: Int -> Blob -> Bool
    isBitUnset i b
      | i `div` 8 >= fromIntegral (BS.length b) = True
      | otherwise = not $ BS.index b (fromIntegral (i `div` 8)) `testBit` (7 - (i `mod` 8))

    fork EmptyTree t = t
    fork t EmptyTree = t
    fork t1 t2 = Fork t1 t2



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

pruneTree :: HashTree -> [Path] -> HashTree
pruneTree tree [] = Pruned (reconstruct tree)
pruneTree (Leaf v) paths | [] `elem` paths = Leaf v
pruneTree tree paths = go tree
  where
    -- These labels are available
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
        | Just path_tails <- M.lookup l wanted = Labeled l (pruneTree subtree (S.toList path_tails))
    go (Fork t1 t2) = fork (go t1) (go t2)
    go tree = Pruned (reconstruct tree)

