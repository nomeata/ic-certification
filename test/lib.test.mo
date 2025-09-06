import { test; suite } "mo:test";
import Debug "mo:base@0/Debug";
import Array "mo:base@0/Array";

import Dyadic "../src/Dyadic";
import MerkleTree "../src/MerkleTree";

// Helper function to assert FindResult equality
func assertFindResult(actual : Dyadic.FindResult, expected : Dyadic.FindResult) {
  assert actual == expected;
};

suite(
  "Dyadic.find",
  func() {
    test(
      "issue8",
      func() {
        let result = Dyadic.find(
          [0],
          Dyadic.mk(Array.tabulate<Nat8>(33, func(_) { 1 }), 257),
        );
        assertFindResult(result, #before(7));
      },
    );

    test(
      "test_short",
      func() {
        let result = Dyadic.find(
          [0],
          {
            prefix = [0];
            len = 7;
          },
        );
        assertFindResult(result, #in_left_half);
      },
    );

    test(
      "test_short1",
      func() {
        let result = Dyadic.find(
          [0],
          {
            prefix = [0];
            len = 8;
          },
        );
        assertFindResult(result, #equal);
      },
    );

    test(
      "test_short2",
      func() {
        let result = Dyadic.find(
          [0, 0],
          {
            prefix = [0];
            len = 8;
          },
        );
        assertFindResult(result, #in_left_half);
      },
    );

    test(
      "test_short3",
      func() {
        let result = Dyadic.find(
          [0, 255],
          {
            prefix = [0];
            len = 8;
          },
        );
        assertFindResult(result, #in_right_half);
      },
    );

    test(
      "test_short4",
      func() {
        let result = Dyadic.find(
          [0],
          {
            prefix = [0, 0];
            len = 16;
          },
        );
        assertFindResult(result, #needle_is_prefix);
      },
    );

    test(
      "test1",
      func() {
        let result = Dyadic.find(
          [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 0;
          },
        );
        assertFindResult(result, #in_left_half);
      },
    );

    test(
      "test1b",
      func() {
        let result = Dyadic.find(
          [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 0;
          },
        );
        assertFindResult(result, #in_right_half);
      },
    );

    test(
      "test2",
      func() {
        let result = Dyadic.find(
          [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          Dyadic.singleton([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        );
        assertFindResult(result, #equal);
      },
    );

    test(
      "test2a",
      func() {
        let result = Dyadic.find(
          [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          Dyadic.singleton([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        );
        assertFindResult(result, #before(255));
      },
    );

    test(
      "test2b",
      func() {
        let result = Dyadic.find(
          [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
          Dyadic.singleton([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        );
        assertFindResult(result, #after(254));
      },
    );

    test(
      "test3",
      func() {
        let result = Dyadic.find(
          [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 16;
          },
        );
        assertFindResult(result, #in_left_half);
      },
    );

    test(
      "test4",
      func() {
        let result = Dyadic.find(
          [0, 1, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 16;
          },
        );
        assertFindResult(result, #in_right_half);
      },
    );

    test(
      "test5",
      func() {
        let result = Dyadic.find(
          [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 16;
          },
        );
        assertFindResult(result, #before(15));
      },
    );

    test(
      "test6",
      func() {
        let result = Dyadic.find(
          [0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 16;
          },
        );
        assertFindResult(result, #after(14));
      },
    );

    test(
      "test7",
      func() {
        let result = Dyadic.find(
          [0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 17;
          },
        );
        assertFindResult(result, #in_left_half);
      },
    );

    test(
      "test8",
      func() {
        let result = Dyadic.find(
          [0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 17;
          },
        );
        assertFindResult(result, #in_right_half);
      },
    );

    test(
      "test9",
      func() {
        let result = Dyadic.find(
          [0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 17;
          },
        );
        assertFindResult(result, #before(16));
      },
    );

    test(
      "test10",
      func() {
        let result = Dyadic.find(
          [0, 1, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          {
            prefix = [0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            len = 17;
          },
        );
        assertFindResult(result, #after(15));
      },
    );
  },
);

suite(
  "MerkleTree examples",
  func() {
    test(
      "example from the test",
      func() {
        var t = MerkleTree.empty();
        t := MerkleTree.put(t, ["Alice"], "\00\01");
        t := MerkleTree.put(t, ["Bob"], "\00\02");

        let w = MerkleTree.reveals(t, ([["Alice"], ["Malfoy"]] : [[Blob]]).vals());
        Debug.print(debug_show w);

        // Basic assertion that the witness was generated (it's not empty)
        switch (w) {
          case (#empty) assert false;
          case (_) assert true;
        };
      },
    );

    test(
      "CBOR-encoded witnesses",
      func() {
        Debug.print("Some CBOR-encoded witnesses:");
        Debug.print(debug_show (MerkleTree.encodeWitness(#empty)));
        Debug.print(debug_show (MerkleTree.encodeWitness(#labeled("", #leaf("0")))));
        let b23 = "01234567890123456789012" : Blob;
        let b24 = "012345678901234567890123" : Blob;
        Debug.print(debug_show (MerkleTree.encodeWitness(#labeled(b23, #leaf(b24)))));

        // Basic assertion that encoding works
        let encoded = MerkleTree.encodeWitness(#empty);
        assert encoded.size() > 0;
      },
    );
  },
);
