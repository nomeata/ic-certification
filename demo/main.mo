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
import Debug "mo:base/Debug";


/*
This actor demostrates the MerkleTree library. Its functionality is

 * Storing a certfiable key-value store.
 * Certified HTTP read access to it.
 * Setting and deleting values via update calls.

*/

actor Self {

/*
We'll use the merkle tree structure also as a key value store. This may not always be the right
thing -- if you do not want to certify the raw data directly, but only some views
(e.g. a HTML rendering), it may make sense to keep the main data in a regular data structure.
But here we will use it, also to exercise lookup, deletion and iteration.
*/
  stable var mt = MerkleTree.empty();

/*
Two public methods to modify the merkle tree.
*/

  public shared func store(key : Text, value : Text) : async () {
    // Store key directly
    mt := MerkleTree.put(mt, ["store", T.encodeUtf8(key)], T.encodeUtf8(value));
    mt := MerkleTree.put(mt, ["http_assets", T.encodeUtf8("/get/" # key)], T.encodeUtf8(value));
    update_asset_hash(?key); // will be explained below
  };

  public shared func delete(key : Text) : async () {
    mt := MerkleTree.delete(mt, ["store", T.encodeUtf8(key)]);
    update_asset_hash(?key); // will be explained below
  };

/*
A HTML rendering of the main page, including links to all keys:
*/

  func my_id(): Principal = Principal.fromActor(Self);

  func page_template(body : Text): Blob {
    return T.encodeUtf8 (
      "<html>" #
      "<head>" #
      "<title>IC certified assets demo</title>" #
      "</head>" #
      "<body>" #
      body #
      "</body>" #
      "</html>"
    )
  };

  func main_page(): Blob {
    page_template(
      "<p>This canister demonstrates certified HTTP assets from Motoko.</p>" #
      "<p>You can see this text at <tt>https://" # debug_show my_id() # ".ic0.app/</tt> " #
      "(note, no <tt>raw</tt> in the URL!) and it will validate!</p>" #
      "<p>This canister is dynamic, and implements a simple key-value store. Here is the list of " #
      "keys:</p>" #
      "<ul>" #
      T.join("", Iter.map(MerkleTree.labelsAt(mt, ["store"]), func(key : Blob) : Text {
          "<li><a href='/get/" # ofUtf8(key) # "'>" # ofUtf8(key) # "</a></li>"
      })) #
      "</ul>" #
      "<p>And to demonstrate that this really is dynamic, you can store and delete keys using " #
      "<a href='https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.ic0.app/?id=" # debug_show my_id() # "'>" #
      "the Candid UI</a></p>."
    );
  };

  func value_page(key : Text): Blob {
    switch (MerkleTree.lookup(mt, ["store", T.encodeUtf8(key)])) {
      case (null) { page_template("<p>Key " # key # " not found.</p>"); };
      case (?v) { page_template(
        "<p>Key " # key # " has value:</p>" #
        "<pre>" # ofUtf8(v) # "</pre>"); 
      };
    }
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

/*
Simple request routing. 
*/
  public query func http_request(req : HttpRequest) : async HttpResponse {
    if (req.method == "GET") {
      // check if / is requested
      if (req.url == "/") {
        // If so, return the main page with with right headers
        return {
          status_code = 200;
          headers = [ ("content-type", "text/html"), certification_header(req.url) ];
          body = main_page()
        }
      };
      switch (T.stripStart(req.url, #text "/get/")) {
        case null {};
        case (?key) {
          return { status_code = 200;
            headers = [ ("content-type", "text/html"), certification_header(req.url) ];
            body = value_page(key);
          }
        }
      };
    };
    // Nothing matched?
    // Else return an error code. Note that we cannot certify this response
    // so a user going to https://ce7vw-haaaa-aaaai-aanva-cai.ic0.app/foo
    // will not see the error message
    return {
      status_code = 404;
      headers = [ ("content-type", "text/plain") ];
      body = "404 Not found.\n This canister only serves /.\n"
    }
  };


/*
We need to store a hash the rendered pages in hash tree.
See <https://internetcomputer.org/docs/current/references/ic-interface-spec#http-gateway> for
the specification.

So this function needs to be called whenever some output changes.

In this demo, when a key is deleted, we actually certify the “key not there” page.
This is not good for production, because the hash tree will ever grow.
*/

  func update_asset_hash(ok : ?Text) {
    // Always update main page
    mt := MerkleTree.put(mt, ["http_assets", "/"], h(main_page()));
    // Update the page at that key
    switch (ok) {
      case null {};
      case (?k) {
        mt := MerkleTree.put(mt, ["http_assets", T.encodeUtf8("/get/" # k)], h(value_page(k)));
      }
    };
    // After every modification, we should update the hash.
    CertifiedData.set(MerkleTree.treeHash(mt));
  };

/*
We should also do this after upgrades:
*/
  system func postupgrade() {
    update_asset_hash(null);
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

  func certification_header(url : Text) : HeaderField {
    let witness = MerkleTree.reveal(mt, ["http_assets", T.encodeUtf8(url)]);
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

  // We put the blobs in the tree, we know they are valid
  func ofUtf8(b: Blob) : Text {
    switch (T.decodeUtf8(b)){
      case (?t) t;
      case null { Debug.trap("Internal error: invalid utf8")};
    }
  };

};
