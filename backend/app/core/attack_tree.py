"""Дерева атак (Attack Trees, B. Schneier, 1999) на основі networkx.

Дерево — орієнтований ациклічний граф з одним коренем (метою порушника).
Вузли бувають трьох типів:
    LEAF — елементарна дія порушника з імовірністю успіху p_i;
    AND  — мета досягається, лише якщо успішні всі дочірні дії;
    OR   — мета досягається, якщо успішна хоча б одна дочірня дія.

За припущення незалежності елементарних подій:
    P(AND) = П p_i
    P(OR)  = 1 - П (1 - p_i)

Захід захисту з ефективністю e_j, що закриває вразливість листка,
зменшує ймовірність листка: p_i' = p_i * П (1 - e_j).
"""
from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field
from enum import StrEnum

import networkx as nx


class Gate(StrEnum):
    LEAF = "LEAF"
    AND = "AND"
    OR = "OR"


@dataclass
class AttackNode:
    """Вузол дерева атак (вхідна структура, не залежить від БД)."""

    name: str
    gate: Gate = Gate.LEAF
    probability: float | None = None  # лише для листків
    vulnerability_id: int | None = None  # вразливість, яку експлуатує листок
    children: list[AttackNode] = field(default_factory=list)

    def __post_init__(self):
        self.gate = Gate(self.gate)
        if self.gate is Gate.LEAF:
            if self.children:
                raise ValueError(f"Листок «{self.name}» не може мати дочірніх вузлів")
            if self.probability is None or not 0.0 <= self.probability <= 1.0:
                raise ValueError(f"Листок «{self.name}»: імовірність має лежати в [0, 1]")
        elif not self.children:
            raise ValueError(f"Вузол {self.gate} «{self.name}» повинен мати дочірні вузли")


@dataclass
class TreeEvaluation:
    """Результат обчислення дерева."""

    probability: float  # імовірність досягнення кореня
    node_probabilities: dict[int, float]  # id вузла графа -> імовірність
    graph: nx.DiGraph
    root: int

    def most_likely_cut_set(self) -> tuple[frozenset[int], float]:
        """Найімовірніший мінімальний набір листків (сценарій атаки) та його ймовірність."""
        sets = minimal_cut_sets(self.graph, self.root)
        best = max(sets, key=lambda s: (_set_probability(self.graph, s), -min(s)))
        return best, _set_probability(self.graph, best)

    def most_likely_path(self) -> tuple[list[str], float]:
        """Назви листків найімовірнішого сценарію атаки."""
        best, p = self.most_likely_cut_set()
        return [self.graph.nodes[n]["name"] for n in sorted(best)], p

    def critical_nodes(self) -> set[int]:
        """Вузли найімовірнішого сценарію атаки разом з усіма їхніми предками."""
        best, _ = self.most_likely_cut_set()
        nodes = set(best)
        for leaf in best:
            nodes |= nx.ancestors(self.graph, leaf)
        return nodes


def build_graph(root: AttackNode) -> tuple[nx.DiGraph, int]:
    """Перетворює вкладену структуру AttackNode на граф networkx."""
    graph = nx.DiGraph()
    counter = itertools.count()

    def add(node: AttackNode) -> int:
        nid = next(counter)
        graph.add_node(nid, name=node.name, gate=node.gate, probability=node.probability,
                       vulnerability_id=node.vulnerability_id)
        for child in node.children:
            graph.add_edge(nid, add(child))
        return nid

    root_id = add(root)
    return graph, root_id


def validate_graph(graph: nx.DiGraph, root: int) -> None:
    if not nx.is_directed_acyclic_graph(graph):
        raise ValueError("Дерево атак містить цикл")
    if graph.in_degree(root) != 0:
        raise ValueError("Корінь не може мати батьківських вузлів")
    unreachable = set(graph) - nx.descendants(graph, root) - {root}
    if unreachable:
        raise ValueError(f"Вузли не досяжні з кореня: {sorted(unreachable)}")


def combine(gate: Gate, probabilities: list[float]) -> float:
    """Імовірність вузла AND/OR за імовірностями дочірніх вузлів."""
    if gate is Gate.AND:
        return math.prod(probabilities)
    if gate is Gate.OR:
        return 1.0 - math.prod(1.0 - p for p in probabilities)
    raise ValueError(f"Невідомий тип вузла: {gate}")


def evaluate(root: AttackNode | tuple[nx.DiGraph, int],
             leaf_reduction: dict[int, float] | None = None) -> TreeEvaluation:
    """Обчислює ймовірність досягнення мети знизу вгору.

    leaf_reduction: vulnerability_id -> множник (1 - E), де E — сумарна
    ефективність заходів, що закривають цю вразливість.
    """
    graph, root_id = build_graph(root) if isinstance(root, AttackNode) else root
    validate_graph(graph, root_id)
    leaf_reduction = leaf_reduction or {}
    probs: dict[int, float] = {}
    # Обхід у зворотному порядку: дочірні вузли обчислюються раніше за батьківські
    for nid in nx.dfs_postorder_nodes(graph, root_id):
        data = graph.nodes[nid]
        if data["gate"] is Gate.LEAF:
            factor = leaf_reduction.get(data["vulnerability_id"], 1.0)
            probs[nid] = data["probability"] * factor
        else:
            probs[nid] = combine(data["gate"], [probs[c] for c in graph.successors(nid)])
        graph.nodes[nid]["computed"] = probs[nid]
    return TreeEvaluation(probability=probs[root_id], node_probabilities=probs,
                          graph=graph, root=root_id)


def minimal_cut_sets(graph: nx.DiGraph, root: int) -> list[frozenset[int]]:
    """Мінімальні набори листків, успіх яких гарантує досягнення мети.

    OR об'єднує набори дочірніх вузлів, AND — утворює їх декартів добуток.
    Надмножини інших наборів відкидаються.
    """
    memo: dict[int, list[frozenset[int]]] = {}

    def sets(nid: int) -> list[frozenset[int]]:
        if nid in memo:
            return memo[nid]
        gate = graph.nodes[nid]["gate"]
        if gate is Gate.LEAF:
            result = [frozenset([nid])]
        elif gate is Gate.OR:
            result = [s for c in graph.successors(nid) for s in sets(c)]
        else:
            result = [frozenset().union(*combo)
                      for combo in itertools.product(*(sets(c) for c in graph.successors(nid)))]
        unique = set(result)
        memo[nid] = [s for s in unique if not any(o < s for o in unique)]
        return memo[nid]

    return sets(root)


def _set_probability(graph: nx.DiGraph, leaves: frozenset[int]) -> float:
    return math.prod(graph.nodes[n].get("computed", graph.nodes[n]["probability"])
                     for n in leaves)


def default_tree(threat_name: str, threat_likelihood: float, vulnerability_name: str,
                 vulnerability_id: int | None, exploit_probability: float) -> AttackNode:
    """Типове дерево для сценарію без явно побудованого дерева:
    мета = ініціювання загрози AND експлуатація вразливості."""
    return AttackNode(
        name=f"Реалізація загрози «{threat_name}»", gate=Gate.AND, children=[
            AttackNode(name="Ініціювання загрози джерелом", probability=threat_likelihood),
            AttackNode(name=f"Експлуатація вразливості «{vulnerability_name}»",
                       probability=exploit_probability, vulnerability_id=vulnerability_id),
        ])
