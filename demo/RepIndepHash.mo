import SHA256 "mo:sha256/SHA256";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Text "mo:base/Text";

module {

  type Hash = Blob;

  // https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map
  public type R = [(Text, V)];
  public type V = {
    #blob : Blob;
    #string : Text;
    #nat : Nat;
    #array : [V];
    #map : R;
  };

  public func hash_of_map(r : R) : Blob { Blob.fromArray(hash_val(#map(r))) };

  // Also see https://github.com/dfinity/ic-hs/blob/master/src/IC/HTTP/RequestId.hs
  func hash_val(v : V) : [Nat8] {
    let d = SHA256.Digest();
    d.write(encode_val(v));
    d.sum();
  };

  func encode_val(v : V) : [Nat8] {
    switch (v) {
      case (#blob(b)) { Blob.toArray(b) };
      case (#string(t)) { Blob.toArray(Text.encodeUtf8(t)) };
      case (#nat(n)) { Debug.trap("encode_val: TODO") };
      case (#array(a)) { arrayConcat(Iter.map(a.vals(), hash_val)); };
      case (#map(m)) {
        let entries : Buffer.Buffer<Blob> = Buffer.fromIter(Iter.map(m.vals(), func ((k : Text, v : V)) : Blob {
            Blob.fromArray(arrayConcat([ hash_val(#string(k)), hash_val(v) ].vals()));
        }));
        entries.sort(Blob.compare); // No Array.compare, so go through blob
        arrayConcat(Iter.map(entries.vals(), Blob.toArray));
      }
    }
  };

  func h(b1 : Blob) : Blob {
    let d = SHA256.Digest();
    d.write(Blob.toArray(b1));
    Blob.fromArray(d.sum());
  };

  // Missing in standard library? Faster implementation?
  func bufferAppend<X>(buf : Buffer.Buffer<X>, a : [X]) {
    for (x in a.vals()) { buf.add(x) };
  };

  // Array concat
  func arrayConcat<X>(as : Iter.Iter<[X]>) : [X] {
    let buf = Buffer.Buffer<X>(0);
    for (a in as) { bufferAppend(buf, a) };
    Buffer.toArray(buf);
  };

}