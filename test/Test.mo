import M "mo:matchers/Matchers";
import S "mo:matchers/Suite";
import T "mo:matchers/Testable";
import Debug "mo:base/Debug";
import Array "mo:base/Array";

import Dyadic "../src/Dyadic";
import MerkleTree "../src/MerkleTree";
import CanisterSigs "../src/CanisterSigs";
import ReqData "../src/ReqData";

let testFindRes : T.Testable<Dyadic.FindResult> = {
   display = func (fr : Dyadic.FindResult) : Text = debug_show fr;
   equals = func (fr1 : Dyadic.FindResult, fr2 : Dyadic.FindResult) : Bool = fr1 == fr2
};
func findRes(fr: Dyadic.FindResult) : T.TestableItem<Dyadic.FindResult> {
  return {
   display = func (fr : Dyadic.FindResult) : Text = (debug_show fr);
   equals = func (fr1 : Dyadic.FindResult, fr2 : Dyadic.FindResult) : Bool = fr1 == fr2;
   item = fr;
  }
};

let suite = S.suite("Dyadic.find", [
    S.test("issue8",
      Dyadic.find(
        [0],
        Dyadic.mk(Array.tabulate<Nat8>(33,func(_){1}), 257),
      ),
      M.equals(findRes(#before(7)))
    ),
    S.test("test_short",
      Dyadic.find(
        [0],
        { prefix = [0];
          len = 7;
        }
      ),
      M.equals(findRes(#in_left_half))
    ),
    S.test("test_short1",
      Dyadic.find(
        [0],
        { prefix = [0];
          len = 8;
        }
      ),
      M.equals(findRes(#equal))
    ),
    S.test("test_short2",
      Dyadic.find(
        [0,0],
        { prefix = [0];
          len = 8;
        }
      ),
      M.equals(findRes(#in_left_half))
    ),
    S.test("test_short3",
      Dyadic.find(
        [0,255],
        { prefix = [0];
          len = 8;
        }
      ),
      M.equals(findRes(#in_right_half))
    ),
    S.test("test_short4",
      Dyadic.find(
        [0],
        { prefix = [0,0];
          len = 16;
        }
      ),
      M.equals(findRes(#needle_is_prefix))
    ),
    S.test("test1",
      Dyadic.find(
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 0;
        }
      ),
      M.equals(findRes(#in_left_half))
    ),
    S.test("test1b",
      Dyadic.find(
        [0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 0;
        }
      ),
      M.equals(findRes(#in_right_half))
    ),
    S.test("test2",
      Dyadic.find(
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        Dyadic.singleton([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
      ),
      M.equals(findRes(#equal))
    ),
    S.test("test2a",
      Dyadic.find(
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        Dyadic.singleton([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
      ),
      M.equals(findRes(#before(255)))
    ),
    S.test("test2b",
      Dyadic.find(
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],
        Dyadic.singleton([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
      ),
      M.equals(findRes(#after(254)))
    ),
    S.test("test3",
      Dyadic.find(
        [0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 16;
        }
      ),
      M.equals(findRes(#in_left_half))
    ),
    S.test("test4",
      Dyadic.find(
        [0,1,0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 16;
        }
      ),
      M.equals(findRes(#in_right_half))
    ),
    S.test("test5",
      Dyadic.find(
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 16;
        }
      ),
      M.equals(findRes(#before(15)))
    ),
    S.test("test6",
      Dyadic.find(
        [0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 16;
        }
      ),
      M.equals(findRes(#after(14)))
    ),
    S.test("test7",
      Dyadic.find(
        [0,0,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,0,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 17;
        }
      ),
      M.equals(findRes(#in_left_half))
    ),
    S.test("test8",
      Dyadic.find(
        [0,0,0xC0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,0,0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 17;
        }
      ),
      M.equals(findRes(#in_right_half))
    ),
    S.test("test9",
      Dyadic.find(
        [0,0,0x00,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,0,0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 17;
        }
      ),
      M.equals(findRes(#before(16)))
    ),
    S.test("test10",
      Dyadic.find(
        [0,1,0x00,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        { prefix = [0,0,0xff,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
          len = 17;
        }
      ),
      M.equals(findRes(#after(15)))
    ),
]);

S.run(suite);

/// the example from the test. TODO: Integrate into the setup above.

var t = MerkleTree.empty();
t := MerkleTree.put(t, ["Alice"], "\00\01");
t := MerkleTree.put(t, ["Bob"], "\00\02");

let w = MerkleTree.reveals(t, ([["Alice"], ["Malfoy"]] : [[Blob]]).vals());
Debug.print(debug_show w);

/// Some example witnesses
Debug.print("Some CBOR-encoded witnesses:");
Debug.print(debug_show (MerkleTree.encodeWitness(#empty)));
Debug.print(debug_show (MerkleTree.encodeWitness(#labeled("",#leaf("0")))));
let b10 = "0123456789" : Blob;
let b20 = "01234567890123456789" : Blob;
let b23 = "01234567890123456789012" : Blob;
let b24 = "012345678901234567890123" : Blob;
Debug.print(debug_show (MerkleTree.encodeWitness(#labeled(b23,#leaf(b24)))));
