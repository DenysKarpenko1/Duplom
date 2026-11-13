"""Дерева атак: формули AND/OR, мінімальні набори, вплив заходів, валідація."""
import math

import pytest

from app.core.attack_tree import AttackNode, Gate, combine, default_tree, evaluate


def leaf(name, p, vid=None):
    return AttackNode(name=name, probability=p, vulnerability_id=vid)


def test_and_or_formulas():
    assert combine(Gate.AND, [0.5, 0.4]) == pytest.approx(0.2)
    assert combine(Gate.OR, [0.5, 0.4]) == pytest.approx(0.7)
    assert combine(Gate.OR, [0.0, 0.0]) == 0.0
    assert combine(Gate.AND, [1.0, 1.0]) == 1.0


def test_nested_tree_probability():
    #        OR
    #      /    \
    #   AND      c(0.1)
    #  a(.9) b(.5)
    tree = AttackNode("goal", Gate.OR, children=[
        AttackNode("ab", Gate.AND, children=[leaf("a", 0.9), leaf("b", 0.5)]),
        leaf("c", 0.1)])
    result = evaluate(tree)
    assert result.probability == pytest.approx(1 - (1 - 0.45) * (1 - 0.1))
    names, p = result.most_likely_path()
    assert names == ["a", "b"] and p == pytest.approx(0.45)


def test_minimal_cut_sets_absorb_supersets():
    # (a AND b) OR a  -> мінімальний набір лише {a}
    from app.core.attack_tree import build_graph, minimal_cut_sets
    tree = AttackNode("g", Gate.OR, children=[
        AttackNode("ab", Gate.AND, children=[leaf("a", .5), leaf("b", .5)]), leaf("a2", .5)])
    graph, root = build_graph(tree)
    sets = minimal_cut_sets(graph, root)
    assert len(sets) == 2 and all(len(s) in (1, 2) for s in sets)
    # AND над двома OR дає 2 x 2 = 4 набори
    tree = AttackNode("g", Gate.AND, children=[
        AttackNode("x", Gate.OR, children=[leaf("a", .1), leaf("b", .2)]),
        AttackNode("y", Gate.OR, children=[leaf("c", .3), leaf("d", .4)])])
    graph, root = build_graph(tree)
    assert len(minimal_cut_sets(graph, root)) == 4
    assert evaluate(tree).most_likely_path()[0] == ["b", "d"]


def test_leaf_reduction_by_measures():
    tree = AttackNode("g", Gate.OR, children=[leaf("a", 0.8, vid=1), leaf("b", 0.3, vid=2)])
    base = evaluate(tree).probability
    reduced = evaluate(tree, leaf_reduction={1: 0.5}).probability
    assert reduced == pytest.approx(1 - (1 - 0.4) * (1 - 0.3))
    assert reduced < base


def test_monotonic_in_leaf_probability():
    def p(x):
        return evaluate(AttackNode("g", Gate.OR, children=[
            AttackNode("s", Gate.AND, children=[leaf("a", x), leaf("b", .6)]),
            leaf("c", .2)])).probability
    values = [p(x / 10) for x in range(11)]
    assert all(b >= a for a, b in zip(values, values[1:]))


def test_default_tree():
    tree = default_tree("T", 0.875, "V", 7, 0.98)
    result = evaluate(tree)
    assert result.probability == pytest.approx(0.875 * 0.98)
    assert evaluate(tree, {7: 0.1}).probability == pytest.approx(0.875 * 0.098)


@pytest.mark.parametrize("bad", [
    lambda: AttackNode("x", Gate.LEAF, probability=1.5),
    lambda: AttackNode("x", Gate.LEAF),
    lambda: AttackNode("x", Gate.AND),
    lambda: AttackNode("x", Gate.LEAF, probability=.5, children=[leaf("y", .1)]),
    lambda: AttackNode("x", "XOR", children=[leaf("y", .1)]),
])
def test_invalid_nodes(bad):
    with pytest.raises(ValueError):
        bad()


def test_cycle_detected():
    import networkx as nx
    from app.core.attack_tree import validate_graph
    g = nx.DiGraph([(0, 1), (1, 0)])
    with pytest.raises(ValueError):
        validate_graph(g, 0)


def test_probability_bounds_random():
    import random
    rnd = random.Random(42)
    for _ in range(200):
        leaves = [leaf(str(i), rnd.random()) for i in range(rnd.randint(1, 5))]
        gate = rnd.choice([Gate.AND, Gate.OR])
        p = evaluate(AttackNode("g", gate, children=leaves)).probability
        probs = [lf.probability for lf in leaves]
        if gate is Gate.AND:
            assert p <= min(probs) + 1e-12
            assert p == pytest.approx(math.prod(probs))
        else:
            assert p >= max(probs) - 1e-12
