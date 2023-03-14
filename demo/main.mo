/*
This small Motoko canister demonstrates, as a proof of concept, how to serve
HTTP requests with dynamic data, and how to do that in a certified way.

To learn more about the theory behind certified variables, I recommend
my talk at https://dfinity.org/howitworks/response-certification
*/


/*
We start with s bunch of imports.
*/

import T "mo:base/Text";
import O "mo:base/Option";
import A "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Blob "mo:base/Blob";
import Iter "mo:base/Iter";
import Error "mo:base/Error";
import Buffer "mo:base/Buffer";
import Principal "mo:base/Principal";
import CertifiedData "mo:base/CertifiedData";
import SHA256 "mo:sha256/SHA256";
import MerkleTree "mo:merkle-tree/MerkleTree";


/*
The actor functionality is pretty straight forward: We store
a string, provide an update call to set it, and we define a function
that includes that string in the main page of our service.
*/

actor Self {
  stable var last_message : Text = "Nobody said anything yet.";

  public shared func leave_message(msg : Text) : async () {
    last_message := msg;
    update_asset_hash(); // will be explained below
  };

  func my_id(): Principal = Principal.fromActor(Self);

  func main_page(): Blob {
    return T.encodeUtf8 (
      "This canister demonstrates certified HTTP assets from Motoko.\n" #
      "\n" #
      "You can see this text at https://" # debug_show my_id() # ".ic0.app/\n" #
      "(note, no raw!) and it will validate!\n" #
      "\n" #
      "And to demonstrate that this really is dynamic, you can leave a" #
      "message at https://ic.rocks/principal/" # debug_show my_id() # "\n" #
      "\n" #
      "The last message submitted was:\n" #
      last_message
    )
  };


/*
To serve HTTP assets, we have to define a query method called `http_request`,
and return the body and the headers. If you don’t care about certification and
just want to serve from <canisterid>.raw.ic0.app, you can do that without
worrying about the ic-certification header.
*/

  type HeaderField = (Text, Text);

  type HttpResponse = {
    status_code: Nat16;
    headers: [HeaderField];
    body: Blob;
  };

  type HttpRequest  = {
    method: Text;
    url: Text;
    headers: [HeaderField];
    body: Blob;
  };

  public query func http_request(req : HttpRequest) : async HttpResponse {
    // check if / is requested
    if (req.method == "GET" and (req.url == "/" or T.startsWith(req.url, #text "/?"))) {
      // If so, return the main page with with right headers
      return {
        status_code = 200;
        headers = [ ("content-type", "text/plain"), certification_header() ];
        body = main_page()
      }
    } else {
      // Else return an error code. Note that we cannot certify this response
      // so a user going to https://ce7vw-haaaa-aaaai-aanva-cai.ic0.app/foo
      // will not see the error message
      return {
        status_code = 404;
        headers = [ ("content-type", "text/plain") ];
        body = "404 Not found.\n This canister only serves /.\n"
      }
    }
  };



/*
If it weren’t for certification, this would be it. The remainder of the file deals with certification.

We need to maintain a merkle tree. We store it in stable memory (but be
careful, the tree data structure can be large with many cached hashes,
so double-check that you are not running out of cycles when upgrading.)
*/

  stable var mt = MerkleTree.empty();

/*
We need to store a hash of the main page in the hash tree.
See <https://internetcomputer.org/docs/current/references/ic-interface-spec#http-gateway> for
the specification.

This function needs to be called at the end of each update call that can affect the main page.
*/

  func update_asset_hash() {
    mt := MerkleTree.put(mt, ["http_assets", "/"], h(main_page()));
    // After every modification, we should update the hash.
    CertifiedData.set(MerkleTree.treeHash(mt));
  };

/*
We should also do this after upgrades:
*/
  system func postupgrade() {
    update_asset_hash();
  };

/*
In fact, we should do it during initialization as well, but Motoko’s definedness analysis is
too strict and will not allow the following, and there is no `system func init` in Motoko.
This means it will not validate until the first post call comes in.
*/
  // update_asset_hash();

/*
The other use of the tree is when calculating the ic-certificate header. This header
contains the certificate obtained from the system, which we just pass through,
and a witness calculated from hash tree that reveals the hash of the current
value of the main page.
*/

  func certification_header() : HeaderField {
    let witness = MerkleTree.reveal(mt, ["http_assets", "/"]);
    let encoded = MerkleTree.encodeWitness(witness);
    let cert = switch (CertifiedData.getCertificate()) {
      case (?c) c;
      case null {
        // unfortunately, we cannot do
        //   throw Error.reject("getCertificate failed. Call this as a query call!")
        // here, because this function isn’t async, but we can’t make it async
        // because it is called from a query (and it would do the wrong thing) :-(
        //
        // So just return erronous data instead
        "getCertificate failed. Call this as a query call!" : Blob
      }
    };
    return
      ("ic-certificate",
        "certificate=:" # base64(cert) # ":, " #
        "tree=:" # base64(encoded) # ":"
      )
  };

/*
Convenience function to implement SHA256 on Blobs rather than [Int8]
*/
  func h(b1 : Blob) : Blob {
    let d = SHA256.Digest();
    d.write(Blob.toArray(b1));
    Blob.fromArray(d.sum());
  };

/*
Base64 encoding.
*/

  func base64(b : Blob) : Text {
    let base64_chars : [Text] = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/"];
    let bytes = Blob.toArray(b);
    let pad_len = if (bytes.size() % 3 == 0) { 0 } else {3 - bytes.size() % 3 : Nat};
    let padded_bytes = A.append(bytes, A.tabulate<Nat8>(pad_len, func(_) { 0 }));
    var out = "";
    for (j in Iter.range(1,padded_bytes.size() / 3)) {
      let i = j - 1 : Nat; // annoying inclusive upper bound in Iter.range
      let b1 = padded_bytes[3*i];
      let b2 = padded_bytes[3*i+1];
      let b3 = padded_bytes[3*i+2];
      let c1 = (b1 >> 2          ) & 63;
      let c2 = (b1 << 4 | b2 >> 4) & 63;
      let c3 = (b2 << 2 | b3 >> 6) & 63;
      let c4 = (b3               ) & 63;
      out #= base64_chars[Nat8.toNat(c1)]
          # base64_chars[Nat8.toNat(c2)]
          # (if (3*i+1 >= bytes.size()) { "=" } else { base64_chars[Nat8.toNat(c3)] })
          # (if (3*i+2 >= bytes.size()) { "=" } else { base64_chars[Nat8.toNat(c4)] });
    };
    return out
  };

};
