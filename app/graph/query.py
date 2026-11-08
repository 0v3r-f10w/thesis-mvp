"""graph.json 查询层：为 Planner 提供「权限集 → 可达隐式路径」的只读查询。

设计原则（严格 Ablation 隔离）
------------------------------
本模块**只做数据检索与摘要**，绝不做结论式推断。
它把图里与当前权限集相关的边**原样列出**，由 LLM 自己判断哪条能用。
从而保证 Group B 相对 Group A 的唯一变量是「是否能看到图谱数据」，
而不是「是否被喂了答案」。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from app.config import OUTPUTS_GRAPH_DIR

#: 与「高价值目标」相关的资源关键字（用于给 Planner 摘要时排序，
#: 不做任何结论，只影响展示顺序）
_HIGH_VALUE_HINTS = (
    "secrets",
    "serviceaccounts/token",
    "clusterrolebindings",
    "pods",
    "nodes",
)


@dataclass(slots=True)
class GraphQuery:
    """对 graph.json 的只读查询封装。"""

    nodes: dict[str, dict] = field(default_factory=dict)
    edges: list[dict] = field(default_factory=list)
    loaded: bool = False
    source_path: str = ""

    @classmethod
    def load(cls, path: Path | None = None) -> "GraphQuery":
        """加载 graph.json。不存在时返回空图（不报错，降级为无图模式）。"""
        target = path or (OUTPUTS_GRAPH_DIR / "graph.json")
        if not target.is_file():
            return cls(loaded=False, source_path=str(target))

        payload = json.loads(target.read_text(encoding="utf-8"))
        nodes = {n["node_id"]: n for n in payload.get("nodes", [])}
        return cls(nodes=nodes, edges=payload.get("edges", []), loaded=True,
                   source_path=str(target))

    # -- 查询 ---------------------------------------------------------------

    def outgoing(self, permission_keys: set[str]) -> list[dict]:
        """返回从给定权限键集合出发的所有隐式边。

        Args:
            permission_keys: 形如 ``{"create:pods", "get:pods/log"}``。
        """
        return [e for e in self.edges if e["from"] in permission_keys]

    def reachable_within(
        self, permission_keys: set[str], max_depth: int = 2
    ) -> list[dict]:
        """返回给定权限集在 max_depth 跳内可达的边（BFS）。

        只返回**边**，不返回「结论路径」，让模型自己组织。
        """
        frontier = set(permission_keys)
        visited: set[str] = set(permission_keys)
        collected: list[dict] = []

        for _ in range(max_depth):
            next_frontier: set[str] = set()
            for e in self.edges:
                if e["from"] in frontier:
                    collected.append(e)
                    if e["to"] not in visited:
                        visited.add(e["to"])
                        next_frontier.add(e["to"])
            if not next_frontier:
                break
            frontier = next_frontier

        return collected

    def summarize_for_planner(
        self,
        permission_keys: set[str],
        *,
        max_edges: int = 30,
        max_targets: int = 25,
    ) -> dict[str, object]:
        """为 Planner 生成**纯事实性**的图摘要。

        返回结构只含计数与边列表，不含任何「建议」「结论」「推荐」字段，
        以维持 Ablation 隔离。

        Returns:
            {
              "graph_loaded": bool,
              "graph_source": str,
              "total_nodes": int,
              "total_edges": int,
              "known_permission_count": int,
              "reachable_edges": [ {from,to,severity,verified,source}, ... ],
              "reachable_target_count": int,
            }
        """
        if not self.loaded:
            return {
                "graph_loaded": False,
                "graph_source": self.source_path,
                "total_nodes": 0,
                "total_edges": 0,
                "known_permission_count": len(permission_keys),
                "reachable_edges": [],
                "reachable_target_count": 0,
            }

        edges = self.reachable_within(permission_keys, max_depth=2)

        # 只保留有 severity 或较高价值的边优先展示（纯排序，不做结论）
        def _rank(e: dict) -> tuple[int, str]:
            to_res = e["to"].split(":", 1)[-1]
            hint = 0 if any(h in to_res for h in _HIGH_VALUE_HINTS) else 1
            sev_rank = {"critical": 0, "high_dos": 1, "medium": 2, "low": 3}.get(
                e.get("severity") or "", 4
            )
            return (hint, sev_rank, e["to"])

        ordered = sorted(edges, key=_rank)[:max_edges]
        targets = sorted({e["to"] for e in edges})[:max_targets]

        return {
            "graph_loaded": True,
            "graph_source": self.source_path,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "known_permission_count": len(permission_keys),
            "reachable_edges": [
                {
                    "from": e["from"],
                    "to": e["to"],
                    "severity": e.get("severity"),
                    "verified": e.get("verified"),
                    "source": e.get("source"),
                }
                for e in ordered
            ],
            "reachable_target_count": len({e["to"] for e in edges}),
            "reachable_targets": targets,
        }
