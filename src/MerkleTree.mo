/// **A merkle tree**
///
/// This library provides a simple merkle tree data structure for Motoko.
/// It provides a key-value store, where both keys and values are of type Blob.
///
/// ```motoko
/// var t = MerkleTree.empty();
/// t := MerkleTree.put(t, "Alice", "\00\01");
/// t := MerkleTree.put(t, "Bob", "\00\02");
///
/// let w = MerkleTree.reveals(t, ["Alice" : Blob, "Malfoy": Blob].vals());
/// ```
/// will produce
/// ```
/// #fork (#labeled ("\3B…\43", #leaf("\00\01")), #pruned ("\EB…\87"))
/// #fork(#labeled("\41\6C\69\63\65", #leaf("\00\01")), #labeled("\42\6F\62", #pruned("\E6…\E2")))
/// ```
///
/// The witness format is compatible with
/// the [HashTree] used by the Internet Computer,
/// so client-side, the same logic can be used, but note
///
///  * the trees produces here are flat; no nested subtrees
//     (but see `witnessUnderLabel` to place the whole tree under a label).
///  * no CBOR encoding is provided here. The assumption is that the witnesses are transferred
///    via Candid, and decoded to a data type understood by the client-side library.
///
/// Revealing multiple keys at once is supported, and so is proving absence of a key.
///
/// The tree branches on the bits of the keys (i.e. a patricia tree). This means that the merkle
/// tree and thus the root hash is unique for a given tree. This in particular means that insertions
/// are efficient, and that the tree can be reconstructed from the data, independently of the
/// insertion order.
///
/// A functional API is provided (instead of an object-oriented one), so that
/// the actual tree can easily be stored in stable memory.
///
/// The tree-related functions are still limited, only insertion so far, no
/// lookup, deletion, modification, or more fancy operations. These can be added
/// when needed.
///
/// [HashTree]: <https://internetcomputer.org/docs/current/references/ic-interface-spec#certificate>

import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Debug "mo:base/Debug";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import SHA256 "mo:sha256/SHA256";
import Dyadic "Dyadic";

module {

  public type Key = Blob;
  public type Path = [Blob];
  public type Value = Blob;

  /// This is the main type of this module: a possibly empty tree that maps
  /// `Key`s to `Value`s.
  public type Tree = LabeledTree;

  type Leaf = { value : Value; leaf_hash : Hash; };
  type LabeledTree = { #leaf : Leaf; #subtree : OT; };

  type OT = ?T;
  type T = {
    // All values in this fork are contained in the `interval`.
    // Moreover, the `left` subtree is contained in the left half of the interval
    // And the `right` subtree is contained in the right half of the interval
    #fork : {
      interval : Dyadic.Interval;
      hash : Hash; // simple memoization of the HashTree hash
      left : T;
      right : T;
    };
    // The value or subtree at a certain label, plus the
    // elements whose keys this is a strict prefix of
    #prefix : {
      key : Key;
      prefix : Prefix; // a copy of the key as array
      here : LabeledTree;
      labeled_hash : Hash; // simple memoization of the labeled leaf HashTree hash
      rest : OT; // Labels that are a suffix of key
      tree_hash : Hash; // simple memoization of the overall HashTree hash
    };
  };

  /// The type of witnesses. This correponds to the `HashTree` in the Interface
  /// Specification of the Internet Computer
  public type Witness = {
    #empty;
    #pruned : Hash;
    #fork : (Witness, Witness);
    #labeled : (Key, Witness);
    #leaf : Value;
  };

  public type Hash = Blob;

  /// Nat8 is easier to work with so far
  type Prefix = [Nat8];

  // Hash-related functions
  func h(b : Blob) : Hash {
    Blob.fromArray(SHA256.sha256(Blob.toArray(b)));
  };
  func h2(b1 : Blob, b2 : Blob) : Hash {
    let d = SHA256.Digest();
    d.write(Blob.toArray(b1));
    d.write(Blob.toArray(b2));
    Blob.fromArray(d.sum());
  };
  func h3(b1 : Blob, b2 : Blob, b3 : Blob) : Hash {
    let d = SHA256.Digest();
    d.write(Blob.toArray(b1));
    d.write(Blob.toArray(b2));
    d.write(Blob.toArray(b3));
    Blob.fromArray(d.sum());
  };

  // Functions on Tree (the possibly empty tree)

  /// The root hash of the merkle tree. This is the value that you would sign
  /// or pass to `CertifiedData.set`
  public func treeHash(t : Tree) : Hash {
    labeledTreeHash(t);
  };

  /// Tree construction: The empty tree
  public func empty() : Tree {
    return #subtree null
  };

  /// Tree construction: Inserting a key into the tree.
  /// An existing value under that key is overridden.
  /// This also deletes all keys at all paths that are a
  /// prefix of the given path!
  public func put(t : Tree, ks : Path, v : Value) : Tree {
    putIter(t, ks.vals(), v);
  };

  public func putIter(t : LabeledTree, ki : Iter.Iter<Key>, v : Value) : LabeledTree {
    switch (ki.next()) {
      case (null) { #leaf(mkLeaf(v)) };
      case (?k) { 
        modifyLabeledTree(t, k, func (s) { putIter(s, ki, v) })
      };
    }
  };
  
  // Labeled tree (the multi-level trees)

  func labeledTreeHash(s : LabeledTree) : Hash {
    switch s {
      case (#leaf(l)) l.leaf_hash;
      case (#subtree(t)) hashOT(t);
    }
  };

  func hashOT(t : OT) : Hash {
    switch (t) {
      case (null) h("\11ic-hashtree-empty");
      case (?t) hashT(t);
    }
  };

  // Now on the real T (the non-empty one-level tree)


  func hashT(t : T) : Hash {
    switch t {
      case (#fork(f)) f.hash;
      case (#prefix(l)) l.tree_hash;
    }
  };

  func intervalT(t : T) : Dyadic.Interval {
    switch t {
      case (#fork(f)) { f.interval };
      case (#prefix(l)) { Dyadic.singleton(l.prefix) };
    }
  };

  // Smart contructors (memoize the hashes and other data)

  func hashLeafNode(v : Value) : Hash {
    h2("\10ic-hashtree-leaf", v)
  };

  func mkLeaf (v : Value) : Leaf {
    let leaf_hash = hashLeafNode(v);
    { value = v; leaf_hash = leaf_hash}
  };

  func mkLabel(k : Key, p : Prefix, s : LabeledTree) : T {
    mkPrefix(k, p, s, null);
  };

  func mkPrefix(k : Key, p : Prefix, s : LabeledTree, rest : ?T) : T {
    let labeled_hash = h3("\13ic-hashtree-labeled", k, labeledTreeHash(s));

    let tree_hash = switch (rest) {
      case null { labeled_hash };
      case (?rest) { h3("\10ic-hashtree-fork", labeled_hash, hashT(rest)); };
    };

    #prefix {
      key = k;
      prefix = p;
      labeled_hash = labeled_hash;
      here = s;
      rest = rest;
      tree_hash = tree_hash;
    }
  };


  func mkFork(i : Dyadic.Interval, t1 : T, t2 : T) : T {
    #fork {
      interval = i;
      hash = h3("\10ic-hashtree-fork", hashT(t1), hashT(t2));
      left = t1;
      right = t2;
    }
  };

  // Modification (in particular insertion)

  func modifyLabeledTree(t : LabeledTree, k : Key, f : LabeledTree -> LabeledTree) : LabeledTree {
    switch (t) {
      // If we are supposed to modify at a label, but encounter a leaf, we throw it away
      case (#leaf _) { #subtree (? modifyOT(null, k, Blob.toArray(k), f)) };
      case (#subtree s) { #subtree (? modifyOT(s, k, Blob.toArray(k), f)) };
    }
  };

  func modifyOT(t : ?T, k : Key, p : Prefix, f : LabeledTree -> LabeledTree) : T {
    switch t {
      case null { mkLabel(k, p, f (#subtree null)) };
      case (?t) { modifyT(t, k, p, f) };
    }
  };


  func modifyT(t : T, k : Key, p : Prefix, f : LabeledTree -> LabeledTree) : T {
    switch (Dyadic.find(p, intervalT(t))) {
      case (#before(i)) {
        mkFork({ prefix = p; len = i }, mkLabel(k, p, f (#subtree null)), t)
      };
      case (#after(i)) {
        mkFork({ prefix = p; len = i }, t, mkLabel(k, p, f (#subtree null)))
      };
      case (#needle_is_prefix) {
        mkPrefix(k,p,f (#subtree null), ?t)
      };
      case (#equal) {
        modifyHere(t, k, p, f)
      };
      case (#in_left_half) {
        modifyLeft(t, k, p, f);
      };
      case (#in_right_half) {
        modifyRight(t, k, p, f);
      };
    }
  };

  func modifyHere(t : T, k : Key, p : Prefix, f : LabeledTree -> LabeledTree) : T {
    switch (t) {
      case (#prefix(l)) {
        mkPrefix(k, p, f (l.here), l.rest) 
      };
      case (#fork(_)) {
        mkPrefix(k, p, f (#subtree null), ?t);
      };
    }
  };

  func modifyLeft(t : T, k : Key, p : Prefix, f : LabeledTree -> LabeledTree) : T {
    switch (t) {
      case (#fork(frk)) {
        mkFork(frk.interval, modifyT(frk.left, k, p, f), frk.right)
      };
      case (#prefix(l)) {
        mkPrefix(l.key, l.prefix, l.here, ? modifyOT(l.rest, k, p, f))
      }
    }
  };

  func modifyRight(t : T, k : Key, p : Prefix, f : LabeledTree -> LabeledTree) : T {
    switch (t) {
      case (#fork(frk)) {
        mkFork(frk.interval, frk.left, modifyT(frk.right, k, p, f))
      };
      case (#prefix(l)) {
        mkPrefix(l.key, l.prefix, l.here, ? modifyOT(l.rest, k, p, f))
      }
    }
  };

  // Witness construction

  /// Create a witness that reveals the value of the key `k` in the tree `tree`.
  ///
  /// If `k` is not in the tree, the witness will prove that fact.
  public func reveal(tree : Tree, path : Path) : Witness {
    revealIter(tree, path.vals())
  };

  func revealIter(tree : LabeledTree, ki : Iter.Iter<Key>) : Witness {
    switch (ki.next()) {
      case (null) { 
        switch (tree) {
          case (#leaf(l)) { #leaf(l.value) };
          // What to reveal when the location is not a value but a subtree?
          // If empty, reveal that
          case (#subtree(null)) { #empty };
          // else reveal its root hash
          case (#subtree(?t)) { #pruned(hashT(t)) };
        }
      };
      case (?k) { 
        switch (tree) {
          // What to reveal when a value is on the way the path?
          // Let's reveal it in purned form
          case (#leaf(l)) { #pruned(treeHash(tree)) };
          case (#subtree(s)) { 
            switch (s) {
              case null { #empty };
              case (?t) {
                let (_, w, _) = revealT(t, Blob.toArray(k), ki);
                w
              }
            }
          }
        }
      };
    }
  };

  // Returned bools indicate whether to also reveal left or right neighbor
  func revealT(t : T, p : Prefix, ki : Iter.Iter<Key>) : (Bool, Witness, Bool) {
    switch (Dyadic.find(p, intervalT(t))) {
      case (#before(i)) {
        (true, revealMinKey(t), false);
      };
      case (#after(i)) {
        (false, revealMaxKey(t), true);
      };
      case (#equal) {
        revealLeaf(t, ki);
      };
      case (#needle_is_prefix) {
        (true, revealMinKey(t), false);
      };
      case (#in_left_half) {
        revealLeft(t, p, ki);
      };
      case (#in_right_half) {
        revealRight(t, p, ki);
      };
    }
  };

  func revealMinKey(t : T) : Witness {
    switch (t) {
      case (#fork(f)) {
        #fork(revealMinKey(f.left), #pruned(hashT(f.right)))
      };
      case (#prefix(l)) {
        #labeled(l.key, #pruned(labeledTreeHash(l.here)));
      }
    }
  };

  func revealMaxKey(t : T) : Witness {
    switch (t) {
      case (#fork(f)) {
        #fork(#pruned(hashT(f.left)), revealMaxKey(f.right))
      };
      case (#prefix(l)) {
        switch (l.rest) {
          case null { #labeled(l.key, #pruned(labeledTreeHash(l.here))) };
          case (?t) { #fork(#pruned(l.labeled_hash), revealMaxKey(t)) };
        }
      }
    }
  };

  func revealLeaf(t : T, ki : Iter.Iter<Key>) : (Bool, Witness, Bool) {
    switch (t) {
      case (#fork(f)) { (true, revealMinKey(t), false); };
      case (#prefix(l)) {
        let lw = #labeled(l.key, revealIter(l.here, ki));
        switch (l.rest) {
          case (null) { (false, lw, false) };
          case (?t)   { (false, #fork(lw, #pruned(hashT(t))), false); }
        }
      }
    }
  };

  func revealLeft(t : T, p : Prefix, ki : Iter.Iter<Key>) : (Bool, Witness, Bool) {
    switch (t) {
      case (#fork(f)) {
        let (b1,w1,b2) = revealT(f.left, p, ki);
        let w2 = if b2 { revealMinKey(f.right) } else { #pruned(hashT(f.right)) };
        (b1, #fork(w1, w2), false);
      };
      case (#prefix(l)) {
        switch (l.rest) {
          case null { (false, #labeled(l.key, #pruned(labeledTreeHash(l.here))), true); };
          case (?t2) {
            let (b1,w1,b2) = revealT(t2, p, ki);
            let w0 = if b1 { #labeled(l.key, #pruned(labeledTreeHash(l.here))) }
                     else { #pruned(l.labeled_hash) };
            (false, #fork(w0, w1), b2);
          }
        }
      }
    }
  };

  func revealRight(t : T, p : Prefix, ki : Iter.Iter<Key>) : (Bool, Witness, Bool) {
    switch (t) {
      case (#fork(f)) {
        let (b1,w2,b2) = revealT(f.right, p, ki);
        let w1 = if b1 { revealMaxKey(f.left) } else { #pruned(hashT(f.left)) };
        (false, #fork(w1, w2), b2);
      };
      case (#prefix(l)) {
        switch (l.rest) {
          case null { (false, #labeled(l.key, #pruned(labeledTreeHash(l.here))), true); };
          case (?t2) {
            let (b1,w1,b2) = revealT(t2, p, ki);
            let w0 = if b1 { #labeled(l.key, #pruned(labeledTreeHash(l.here))) }
                     else { #pruned(l.labeled_hash) };
            (false, #fork(w0, w1), b2);
          }
        }
      }
    }
  };

  /// Merges two witnesses, to reveal multiple values.
  ///
  /// The two witnesses must come from the same tree, else this function is
  /// undefined (and may trap).
  public func merge(w1 : Witness, w2 : Witness) : Witness {
    switch (w1, w2) {
      case (#pruned(h1), #pruned(h2)) {
        if (h1 != h2) Debug.print("MerkleTree.merge: pruned hashes differ");
        #pruned(h1)
      };
      case (#pruned _, w2) w2;
      case (w1, #pruned _) w1;
      // If both witnesses are not pruned, they must be headed by the same
      // constructor:
      case (#empty, #empty) #empty;
      case (#labeled(l1, w1), #labeled(l2, w2)) {
        if (l1 != l2) Debug.print("MerkleTree.merge: labels differ");
        #labeled(l1, merge(w1, w2));
      };
      case (#fork(w11, w12), #fork(w21, w22)) {
        #fork(merge(w11, w21), merge(w12, w22))
      };
      case (#leaf(v1), #leaf(v2)) {
        if (v1 != v2) Debug.print("MerkleTree.merge: values differ");
        #leaf(v2)
      };
      case (_,_) {
        Debug.print("MerkleTree.merge: shapes differ");
        #empty;
      }
    }
  };

  /// Reveal nothing from the tree. Mostly useful as a netural element to `merge`.
  public func revealNothing(tree : Tree) : Witness {
    #pruned(treeHash(tree))
  };

  /// Reveals multiple paths
  public func reveals(tree : Tree, ks : Iter.Iter<Path>) : Witness {
    // Odd, no Iter.fold? Then let’s do a mutable loop
    var w = revealNothing(tree);
    for (k in ks) { w := merge(w, reveal(tree, k)); };
    return w;
  };

  /// Nests a witness under a label. This can be used when you want to use this
  /// library (which only produces flat labeled tree), but want to be forward
  /// compatible to a world where you actually produce nested labeled trees, or
  /// to be compatibe with an external specification that requires you to put
  /// this hash-of-blob-labeled tree in a subtree.
  ///
  /// To not pass the result of this function to `merge`! of this ru
  public func witnessUnderLabel(l : Blob, w : Witness) : Witness {
    #labeled(l, w)
  };

  /// This goes along `witnessUnderLabel`, and transforms the hash
  /// that is calculated by `treeHash` accordingly.
  ///
  /// If you wrap your witnesses using `witnessUnderLabel` before
  /// sending them out, make sure to wrap your tree hash with `hashUnderLabel`
  /// before passing them to `CertifiedData.set`.
  public func hashUnderLabel(l : Blob, h : Hash) : Hash {
    h3("\13ic-hashtree-labeled", l, h);
  };
}
