"""graph.json / actions.json 的数据结构与序列化。

设计要点（对应需求）：
- actions.json 独立于 graph.json，便于物理链 preconditions 对齐。
- graph.json 的隐式边属性固定为 {severity, verified, source}，其中 trigger.txt 为权威起点。
- 所有 id 稳定可复现（不用随机/UUID），便于多次运行 diff。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import KUBERNETES_SOURCE_VERSION, SCHEMA_VERSION


# ---------------------------------------------------------------------------
# 枚举值（字符串常量，避免 Enum 序列化开销）
# ---------------------------------------------------------------------------

#: 边的来源：trigger = 动态验证过的权威起点
SOURCE_TRIGGER = "trigger"
#: 边的来源：仅出现在 permission-reference.txt（LLM + 静态合并的全量参考）
SOURCE_STATIC_LLM = "static_llm"
#: 边的来源：仅出现在 classification.txt（如 ResourceQuota / ValidatingAdmissionPolicy
#: 的 deny/allow 副作用边），未见于 permission-reference / trigger
SOURCE_CLASSIFICATION = "classification"
#: 边的来源：由传递闭包推导
SOURCE_CLOSURE = "closure"

VALID_SOURCES = (
    SOURCE_TRIGGER,
    SOURCE_STATIC_LLM,
    SOURCE_CLASSIFICATION,
    SOURCE_CLOSURE,
)

#: 边的推导方式
DERIVATION_DIRECT = "direct"
DERIVATION_CLOSURE = "closure"

#: severity 取值，与 classification.txt 的四个段头一一对应
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH_DOS = "high_dos"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

VALID_SEVERITIES = (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH_DOS,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
)


# ---------------------------------------------------------------------------
# 权限节点键的规范形式
# ---------------------------------------------------------------------------


def permission_key(verb: str, resource: str) -> str:
    """生成权限节点的规范键，例如 ``create:pods/exec``。"""
    return f"{verb}:{resource}"


def node_id_for_permission(verb: str, resource: str) -> str:
    """权限节点的全局 id，例如 ``perm:create:pods/exec``。"""
    return f"perm:{permission_key(verb, resource)}"


def is_wildcard(verb: str, resource: str) -> bool:
    """是否为通配符权限（``* *``），即 RBAC 全域授权。"""
    return verb == "*" and resource == "*"


# ---------------------------------------------------------------------------
# actions.json
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ActionPrimitive:
    """一条显式权限动作原语：某资源上的某个 verb。

    由 Explicit_Permission_Analysis/results/result.txt 的
    ``<resource> [<Verb> ...]`` 五段式解析而来。
    """

    action_id: str
    resource: str
    verb: str
    parent_resource: str
    subresource: str | None
    is_subresource: bool
    #: 语义原语名（如 ``exec_into_pod``），未映射时为 None
    action_primitive: str | None = None
    #: 物理链前置条件（批次 4 由 design 补全，第一版仅结构位）
    physical_precondition: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "resource": self.resource,
            "verb": self.verb,
            "parent_resource": self.parent_resource,
            "subresource": self.subresource,
            "is_subresource": self.is_subresource,
            "action_primitive": self.action_primitive,
            "physical_precondition": self.physical_precondition,
        }


@dataclass(slots=True)
class ActionsDocument:
    """actions.json 顶层结构。"""

    source_file: str
    source_line_count: int
    actions: list[ActionPrimitive]
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "source": {
                "file": self.source_file,
                "kubernetes_version": KUBERNETES_SOURCE_VERSION,
                "line_count": self.source_line_count,
            },
            "actions": [a.to_dict() for a in self.actions],
            "stats": self.stats,
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=False),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# graph.json
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class GraphNode:
    """隐式权限图的节点。

    kind 取值：
    - ``permission``：一个 (verb, resource) 权限原语
    - ``wildcard``：``* *`` 全域授权
    """

    node_id: str
    kind: str
    verb: str
    resource: str
    is_subresource: bool
    #: 该权限是否出现在显式权限转换表（actions.json）中
    explicit: bool
    action_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind,
            "verb": self.verb,
            "resource": self.resource,
            "is_subresource": self.is_subresource,
            "explicit": self.explicit,
            "action_ref": self.action_ref,
        }


@dataclass(slots=True)
class GraphEdge:
    """隐式权限图的边：``from_perm --> to_perm``。

    severity / verified / source 是三条固定属性（需求明确要求）。
    """

    edge_id: str
    from_key: str
    to_key: str
    severity: str | None
    verified: bool
    source: str
    derivation: str
    #: 该边在三份文件中的出现证据
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "from": self.from_key,
            "to": self.to_key,
            "type": "implicit",
            "severity": self.severity,
            "verified": self.verified,
            "source": self.source,
            "derivation": self.derivation,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class GraphDocument:
    """graph.json 顶层结构。"""

    sources: dict[str, Any]
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "sources": self.sources,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "stats": self.stats,
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=False),
            encoding="utf-8",
        )
