"""Grammar engine tests (run with: python -m unittest discover -s tests)."""

import unittest

from app.engine import (
    AMBIGUOUS,
    REJECTED,
    UNIQUE,
    EngineError,
    analyze,
    static_analysis,
)
from app.grammar import build_grammar


def G(nts, prods, start, tokens=None, terminals=None):
    payload = {"nonterminals": nts, "productions": prods, "start": start,
               "tokens": tokens or []}
    if terminals is not None:
        payload["terminals"] = terminals
    return build_grammar(payload)


def P(pid, lhs, rhs):
    return {"id": pid, "lhs": lhs, "rhs": rhs}


def verdict(g):
    return analyze(g)["verdict"]


def seqs(r):
    return (tuple(r["production_sequences"]["first"]),
            tuple(r["production_sequences"]["second"]))


class TestUniqueAcceptance(unittest.TestCase):
    def test_simple(self):
        g = G(["S"], [P(1, "S", ["a", "b"])], "S", ["a", "b"])
        r = analyze(g)
        self.assertEqual(r["verdict"], UNIQUE)
        self.assertEqual(r["production_sequence"], [1])

    def test_right_recursion(self):
        g = G(["S"], [P(1, "S", ["a", "S"]), P(2, "S", ["b"])],
              "S", ["a", "a", "b"])
        r = analyze(g)
        self.assertEqual(r["verdict"], UNIQUE)
        self.assertEqual(r["production_sequence"], [1, 1, 2])

    def test_left_recursion_unique(self):
        # S -> S a | a ; "aa" is unique despite left recursion:
        # outer pid1 over inner pid2 (preorder [1, 2]).
        g = G(["S"], [P(1, "S", ["S", "a"]), P(2, "S", ["a"])],
              "S", ["a", "a"])
        r = analyze(g)
        self.assertEqual(r["verdict"], UNIQUE)
        self.assertEqual(r["production_sequence"], [1, 2])

    def test_epsilon_in_middle(self):
        g = G(["S", "A"], [P(1, "S", ["A", "x"]), P(2, "A", [])], "S", ["x"])
        r = analyze(g)
        self.assertEqual(r["verdict"], UNIQUE)
        self.assertEqual(r["production_sequence"], [1, 2])

    def test_empty_input_epsilon(self):
        g = G(["S"], [P(7, "S", [])], "S", [])
        r = analyze(g)
        self.assertEqual(r["verdict"], UNIQUE)
        self.assertEqual(r["production_sequence"], [7])

    def test_general_recursion_unique(self):
        # S -> ( S ) | x ; "(x)" unique
        g = G(["S"],
              [P(1, "S", ["(", "S", ")"]), P(2, "S", ["x"])],
              "S", ["(", "x", ")"])
        r = analyze(g)
        self.assertEqual(r["verdict"], UNIQUE)
        self.assertEqual(r["production_sequence"], [1, 2])


class TestAmbiguity(unittest.TestCase):
    def test_duplicate_productions(self):
        g = G(["S"], [P(1, "S", ["a"]), P(2, "S", ["a"])], "S", ["a"])
        r = analyze(g)
        self.assertEqual(r["verdict"], AMBIGUOUS)
        self.assertEqual(seqs(r), ((1,), (2,)))

    def test_dangling_else(self):
        # S -> if S | if S else S | x ; "if x" unambiguous,
        # "if x else x" is unique; "if if x else x" ambiguous.
        prods = [P(1, "S", ["if", "S"]),
                 P(2, "S", ["if", "S", "else", "S"]),
                 P(3, "S", ["x"])]
        g = G(["S"], prods, "S", ["if", "if", "x", "else", "x"])
        r = analyze(g)
        self.assertEqual(r["verdict"], AMBIGUOUS)
        s1, s2 = seqs(r)
        self.assertNotEqual(s1, s2)
        # first must be lexicographically smallest
        self.assertEqual(s1, min(s1, s2))

    def test_expression_precedence_ambiguity(self):
        prods = [P(1, "E", ["E", "+", "E"]),
                 P(2, "E", ["E", "*", "E"]),
                 P(3, "E", ["id"])]
        g = G(["E"], prods, "E", ["id", "+", "id", "*", "id"])
        r = analyze(g)
        self.assertEqual(r["verdict"], AMBIGUOUS)
        s1, s2 = seqs(r)
        # first = (+ (* id id) id)-shape chosen by pid ordering:
        # pid 1 is the outer production of first
        self.assertEqual(s1[0], 1)
        self.assertNotEqual(s1, s2)

    def test_epsilon_ambiguity(self):
        prods = [P(1, "S", ["A"]), P(2, "A", ["B"]), P(3, "A", ["C"]),
                 P(4, "B", []), P(5, "C", [])]
        g = G(["S", "A", "B", "C"], prods, "S", [])
        r = analyze(g)
        self.assertEqual(r["verdict"], AMBIGUOUS)
        self.assertEqual(seqs(r), ((1, 2, 4), (1, 3, 5)))

    def test_two_trees_are_distinct_and_stable(self):
        prods = [P(10, "S", ["a", "S"]), P(20, "S", []), P(30, "S", ["a", "S"])]
        # S -> aS (id10) | eps | aS (id30): "a" has two trees
        g = G(["S"], prods, "S", ["a"])
        r1 = analyze(g)
        g2 = G(["S"], [prods[2], prods[0], prods[1]], "S", ["a"])
        r2 = analyze(g2)
        self.assertEqual(r1["production_sequences"], r2["production_sequences"])
        self.assertEqual(
            r1["production_sequences"]["first"], [10, 20]
        )
        self.assertEqual(
            r1["production_sequences"]["second"], [30, 20]
        )

    def test_stable_switch_earliest_preorder(self):
        # Root unique pid1, ambiguity nested deeper.
        prods = [P(1, "S", ["x", "A", "y"]),
                 P(2, "A", ["a"]), P(3, "A", ["a"])]
        g = G(["S", "A"], prods, "S", ["x", "a", "y"])
        r = analyze(g)
        self.assertEqual(r["verdict"], AMBIGUOUS)
        self.assertEqual(seqs(r), ((1, 2), (1, 3)))

    def test_second_is_global_second_smallest_not_first_switch(self):
        # The lexicographically second-smallest sequence diverges at the
        # LAST possible position, not the first: trees are
        # [1,3], [1,4], [2,5] -> second must be [1,4], not [2,5].
        prods = [P(1, "S", ["B"]), P(2, "S", ["C"]),
                 P(3, "B", ["x"]), P(4, "B", ["x"]), P(5, "C", ["x"])]
        g = G(["S", "B", "C"], prods, "S", ["x"])
        r = analyze(g)
        self.assertEqual(r["verdict"], AMBIGUOUS)
        self.assertEqual(seqs(r), ((1, 3), (1, 4)))


class TestRejection(unittest.TestCase):
    def test_token_not_accepted(self):
        g = G(["S"], [P(1, "S", ["a"])], "S", ["b"])
        with self.assertRaises(EngineError) as ctx:
            analyze(g)
        self.assertEqual(ctx.exception.reason, "INPUT_NOT_ACCEPTED")
        self.assertIn("b", ctx.exception.detail)

    def test_prefix_is_not_enough(self):
        g = G(["S"], [P(1, "S", ["a", "b"])], "S", ["a"])
        with self.assertRaises(EngineError) as ctx:
            analyze(g)
        self.assertEqual(ctx.exception.reason, "INPUT_NOT_ACCEPTED")

    def test_start_unproductive(self):
        g = G(["S", "X"], [P(1, "S", ["X"]), P(2, "X", ["X"])], "S", [])
        with self.assertRaises(EngineError) as ctx:
            analyze(g)
        self.assertEqual(ctx.exception.reason, "START_UNPRODUCTIVE")

    def test_unreachable_unproductive_nt_is_ok(self):
        g = G(["S", "X"], [P(1, "S", ["a"]), P(2, "X", ["X"])], "S", ["a"])
        self.assertEqual(verdict(g), UNIQUE)


class TestNonConsumingCycles(unittest.TestCase):
    def test_direct_self_loop_with_epsilon(self):
        g = G(["A"], [P(1, "A", ["A"]), P(2, "A", [])], "A", [])
        with self.assertRaises(EngineError) as ctx:
            static_analysis(g)
        self.assertEqual(ctx.exception.reason, "NONCONSUMING_CYCLE")
        self.assertEqual(ctx.exception.extra["cycle"], ["A", "A"])
        self.assertEqual(ctx.exception.extra["production_ids"], [1])

    def test_indirect_loop(self):
        prods = [P(1, "A", ["B"]), P(2, "B", ["A"]), P(3, "A", [])]
        g = G(["A", "B"], prods, "A", [])
        with self.assertRaises(EngineError) as ctx:
            static_analysis(g)
        self.assertEqual(ctx.exception.reason, "NONCONSUMING_CYCLE")
        self.assertEqual(ctx.exception.extra["production_ids"], [1, 2])

    def test_loop_without_epsilon_exit_still_rejected(self):
        # A -> B, B -> A, A -> a: infinite zero-consumption expansion
        # A => B => A ... exists even though nothing ever closes.
        prods = [P(1, "A", ["B"]), P(2, "B", ["A"]), P(3, "A", ["a"])]
        g = G(["A", "B"], prods, "A", ["a"])
        with self.assertRaises(EngineError) as ctx:
            static_analysis(g)
        self.assertEqual(ctx.exception.reason, "NONCONSUMING_CYCLE")

    def test_left_recursion_consuming_is_not_a_cycle(self):
        # A -> A a | eps: recursion consumes a token -> legal, unique.
        g = G(["A"], [P(1, "A", ["A", "a"]), P(2, "A", [])], "A", ["a"])
        self.assertEqual(verdict(g), UNIQUE)

    def test_SS_without_epsilon_is_not_a_cycle(self):
        g = G(["S"], [P(1, "S", ["S", "S"]), P(2, "S", ["a"])],
              "S", ["a", "a", "a"])
        self.assertEqual(verdict(g), AMBIGUOUS)

    def test_unreachable_null_loop_is_not_rejected(self):
        # U -> U | eps is a loop but U is unreachable from S.
        g = G(["S", "U"],
              [P(1, "S", ["a"]), P(2, "U", ["U"]), P(3, "U", [])],
              "S", ["a"])
        self.assertEqual(verdict(g), UNIQUE)

    def test_conditional_null_loop(self):
        # A -> B A | eps ; B -> b | eps : A's RHS via B nullable gives
        # edge A->A (B derives eps) -> reject.
        prods = [P(1, "A", ["B", "A"]), P(2, "A", []),
                 P(3, "B", ["b"]), P(4, "B", [])]
        g = G(["A", "B"], prods, "A", ["b"])
        with self.assertRaises(EngineError) as ctx:
            static_analysis(g)
        self.assertEqual(ctx.exception.reason, "NONCONSUMING_CYCLE")


class TestForestShapeAndPolynomialBehavior(unittest.TestCase):
    def test_tree_tiles_input(self):
        prods = [P(1, "E", ["E", "+", "E"]),
                 P(2, "E", ["E", "*", "E"]),
                 P(3, "E", ["id"])]
        g = G(["E"], prods, "E", ["id", "+", "id", "*", "id"])
        r = analyze(g)
        grammar = g

        def walk(node, lo, hi):
            if "token" in node:
                i, j = node["span"]
                self.assertEqual((i, j), (lo, lo + 1))
                self.assertEqual(g.tokens[i], node["token"])
                return
            i, j = node["span"]
            self.assertEqual((i, j), (lo, hi))
            prod = grammar.by_id[node["production"]]
            self.assertEqual(prod.lhs, node["symbol"])
            kids = node["children"]
            self.assertEqual(len(kids), len(prod.rhs))
            pos = i
            for child, sym in zip(kids, prod.rhs):
                if "token" in child:
                    self.assertEqual(child["token"], sym)
                    walk(child, pos, pos + 1)
                    pos += 1
                else:
                    self.assertEqual(child["symbol"], sym)
                    _, cj = child["span"]
                    walk(child, pos, cj)
                    pos = cj
            self.assertEqual(pos, j)

        for which in ("first", "second"):
            walk(r["trees"][which], 0, 5)

    def test_no_enumeration_at_48_highly_ambiguous_tokens(self):
        # Catalan(47) parses exist; the verdict must be instant.
        import time

        g = G(["S"], [P(1, "S", ["S", "S"]), P(2, "S", ["a"])],
              "S", ["a"] * 48)
        t0 = time.time()
        r = analyze(g)
        dt = time.time() - t0
        self.assertEqual(r["verdict"], AMBIGUOUS)
        self.assertLess(dt, 5.0)
        s1, s2 = seqs(r)
        self.assertNotEqual(s1, s2)
        self.assertEqual(s1, min(s1, s2))


class TestValidationFirstReason(unittest.TestCase):
    def test_dangling_terminal_with_alphabet(self):
        from app.grammar import ValidationError

        # Q is neither NT nor in alphabet -> ValidationError at build
        with self.assertRaises(ValidationError) as ctx:
            G(["S"], [P(1, "S", ["a", "Q"])], "S", ["a", "b"],
              terminals=["a", "b"])
        self.assertEqual(ctx.exception.reason, "DANGLING_SYMBOL")

    def test_limit_nonterminals(self):
        from app.grammar import ValidationError

        with self.assertRaises(ValidationError) as ctx:
            G([f"N{i}" for i in range(17)],
              [P(1, "N0", ["a"])], "N0", ["a"])
        self.assertEqual(ctx.exception.reason, "LIMIT_EXCEEDED")

    def test_duplicate_production_id(self):
        from app.grammar import ValidationError

        with self.assertRaises(ValidationError) as ctx:
            G(["S"], [P(1, "S", ["a"]), P(1, "S", ["b"])], "S", ["a"])
        self.assertEqual(ctx.exception.reason, "DUP_PRODUCTION_ID")

    def test_non_ascii_symbol(self):
        from app.grammar import ValidationError

        with self.assertRaises(ValidationError) as ctx:
            G(["S"], [P(1, "S", ["中"])], "S", ["中"])
        self.assertEqual(ctx.exception.reason, "INVALID_SYMBOL")


if __name__ == "__main__":
    unittest.main()
