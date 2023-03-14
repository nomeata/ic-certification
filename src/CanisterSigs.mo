import Principal "mo:base/Principal";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Blob "mo:base/Blob";
import MerkleTree "MerkleTree";
import ReqData "ReqData";
import SHA224 "mo:sha224/SHA224";

module {
  type PublicKey = Blob;

  public func publicKey(canister_id : Principal, seed : Blob) : PublicKey {
    let b = Principal.toBlob(canister_id);
    let buf = Buffer.Buffer<Nat8>(0);
    buf.add(Nat8.fromNat(b.size()));
    bufferAppend(buf, b);
    bufferAppend(buf, seed);
    wrapDer(Blob.fromArray(Buffer.toArray(buf)));
  };

  public func selfAuthenticatingPrincipal(publicKey : PublicKey) : Principal {
    let buf = Buffer.Buffer<Nat8>(28+1);
    bufferAppend(buf, Blob.fromArray(SHA224.sha224(Blob.toArray(publicKey))));
    buf.add(0x02);
    Principal.fromBlob(Blob.fromArray(Buffer.toArray(buf)));
  };

  func wrapDer(raw_key : Blob) : Blob {
    let canister_sig_oid_seq : Blob = "\30\0c\06\0a\2b\06\01\04\01\83\b8\43\01\02";
    let buf = Buffer.Buffer<Nat8>(0);
    buf.add(0x30); // SEQUENCE
    buf.add(Nat8.fromNat(canister_sig_oid_seq.size() + 3 + raw_key.size())); // overall length  
    bufferAppend(buf, canister_sig_oid_seq);
    buf.add(0x03); // BIT String
    buf.add(Nat8.fromNat(1 + raw_key.size())); // key size
    buf.add(0x00); // BIT Padding
    bufferAppend(buf, raw_key);
    Blob.fromArray(Buffer.toArray(buf));
  };

  // Missing in standard library? Faster implementation?
  func bufferAppend(buf : Buffer.Buffer<Nat8>, b : Blob) {
    for (x in b.vals()) { buf.add(x) };
  };

  public func signature(cert : Blob, witness : MerkleTree.Witness) : Blob {
    ReqData.encodeCBOR([
      ("certificate", #blob(cert)),
      ("tree", repOfWitness(witness))
    ])
  } ;

  func repOfWitness(w : MerkleTree.Witness) : ReqData.V {
    switch(w) {
      case (#empty)        { #array([#nat(0)]) };
      case (#fork(l,r))    { #array([#nat(1), repOfWitness(l), repOfWitness(r)]) };
      case (#labeled(k,w)) { #array([#nat(2), #blob(k), repOfWitness(w)])};
      case (#leaf(v))      { #array([#nat(3), #blob(v)])};
      case (#pruned(h))    { #array([#nat(4), #blob(h)])};
    }
  };
}