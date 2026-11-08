"""传递闭包：复刻 ImplicitPermission Static_Analysis/SA/libs.go 的 multiRef()。

原版逻辑（Go）::

    func deriveMappings(mappings map[string][]string) map[string][]string {
        for key, midValues := range mappings {
            if strings.Contains(key, "/") { continue }   // 子资源不参与闭包
            for _, midValue := range midValues {
                if targets, exists := mappings[midValue]; exists {
                    newMappings[key] = append(newMappings[key], targets...)
                }
            }
        }
    }

即：``A --> B`` 且 ``B --> C`` ⇒ 推导 ``A --> C``，且**只对不含 ``/`` 的 key 做**
（主资源才扩散，子资源不做中转）。

本实现的增强（需求「加权限交集约束」）：
1. 保留「子资源 key 不扩散」的原版规则。
2. 额外要求**中转节点 B 必须存在于显式权限表**（verb∩resource 交集约束），
   即 B 必须是一个真实可授予的 RBAC 权限原语，避免推导出不存在的权限。
3. 深度上限 CLOSURE_MAX_DEPTH（默认 2），防组合爆炸。
4. 不推导自环（A --> A）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.config import CLOSURE_MAX_DEPTH, CLOSURE_REQUIRE_VERB_INTERSECTION

#: 解析 ``verb resource``，例如 ``create pods/exec`` 或 ``* *``
_EDGE_SIDE_RE = re.compile(r"^\s*(?P<verb>\S+)\s+(?P<resource>\S+)\s*$")

#: 解析带效应修饰符的右侧，例如 ``deny create pods``、
#: ``deny create [any kubernetes api resource]``、``allow update ...``。
#: classification.txt 的 low 段含有 53 条此类边（deny=45 / allow=8）。
_EFFECT_SIDE_RE = re.compile(
    r"^\s*(?P<effect>deny|allow)\s+(?P<verb>\S+)\s+(?P<rest>.+?)\s*$"
)

#: ``[any kubernetes api resource]`` 这类占位符归一化为通配资源 ``*``
_ANY_RESOURCE_RE = re.compile(r"^\[.*\]$")

#: 效应修饰符
EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"


@dataclass(frozen=True, slots=True)
class ClosureEdge:
    """一条闭包推导结果。"""

    from_key: str
    to_key: str
    depth: int
    via: tuple[str, ...]


def parse_edge_side(side: str) -> tuple[str, str] | None:
    """把 ``"create pods/exec"`` 解析为 ``("create", "pods/exec")``。

    Returns:
        (verb, resource)；无法解析返回 None。
    """
    m = _EDGE_SIDE_RE.match(side)
    if not m:
        return None
    return m.group("verb").lower(), m.group("resource")


def parse_edge_side_effect(side: str) -> tuple[str, str, str | None] | None:
    """解析可能带 ``deny`` / ``allow`` 效应修饰符的一侧。

    支持三种形态：
    - ``create pods/exec``            → (``create``, ``pods/exec``, None)
    - ``deny create pods``            → (``create``, ``pods``, ``deny``)
    - ``deny create [any kubernetes api resource]``
                                      → (``create``, ``*``, ``deny``)

    Returns:
        (verb, resource, effect)；无法解析返回 None。
    """
    m = _EFFECT_SIDE_RE.match(side)
    if m:
        effect = m.group("effect").lower()
        verb = m.group("verb").lower()
        rest = m.group("rest").strip()
        resource = "*" if _ANY_RESOURCE_RE.match(rest) else rest
        return verb, resource, effect

    plain = parse_edge_side(side)
    if plain is None:
        return None
    verb, resource = plain
    return verb, resource, None


def key_of(verb: str, resource: str) -> str:
    """规范化权限键：``verb:resource``。"""
    return f"{verb}:{resource}"


def split_key(key: str) -> tuple[str, str]:
    """把 ``verb:resource`` 拆回 (verb, resource)。"""
    verb, _, resource = key.partition(":")
    return verb, resource


def _is_subresource_key(key: str) -> bool:
    """key 的 resource 部分是否含子资源斜杠（原版 ``strings.Contains(key, "/")``）。"""
    _, resource = split_key(key)
    return "/" in resource


def derive_closure(
    adjacency: dict[str, list[str]],
    explicit_keys: set[str],
    max_depth: int = CLOSURE_MAX_DEPTH,
    require_verb_intersection: bool = CLOSURE_REQUIRE_VERB_INTERSECTION,
) -> list[ClosureEdge]:
    """推导传递闭包边。

    Args:
        adjacency: 直接边邻接表 {``verb:resource``: [``verb:resource``, ...]}。
        explicit_keys: 显式权限表中存在的 ``verb:resource`` 键集合（交集约束用）。
        max_depth: 最大跳数（>=1）。
        require_verb_intersection: 是否要求中转节点在显式权限表中存在。

    Returns:
        推导出的闭包边列表（不含原始直接边，不含自环）。
    """
    if max_depth < 1:
        return []

    # 直接边集合，用于最终排除「已存在的边」
    direct: set[tuple[str, str]] = {
        (src, dst) for src, dsts in adjacency.items() for dst in dsts
    }

    results: dict[tuple[str, str], ClosureEdge] = {}

    for start in adjacency:
        # 原版规则：子资源 key 不参与闭包扩散
        if _is_subresource_key(start):
            continue

        # BFS，但记录路径以便标注 via
        # frontier 元素：(当前节点, 已走路径(不含起点))
        frontier: list[tuple[str, tuple[str, ...]]] = [
            (dst, (dst,)) for dst in adjacency.get(start, ())
        ]

        for depth in range(1, max_depth + 1):
            next_frontier: list[tuple[str, tuple[str, ...]]] = []
            for node, path in frontier:
                # 交集约束：中转节点必须是真实存在的显式权限
                if require_verb_intersection and node not in explicit_keys:
                    continue

                for nxt in adjacency.get(node, ()):
                    new_path = path + (nxt,)
                    # 防环 / 自环
                    if nxt == start or nxt in path:
                        continue
                    # 已存在直接边的不重复推导
                    if (start, nxt) in direct:
                        continue

                    pair = (start, nxt)
                    existing = results.get(pair)
                    # 保留最短路径那条
                    if existing is None or depth < existing.depth:
                        results[pair] = ClosureEdge(
                            from_key=start,
                            to_key=nxt,
                            depth=depth,
                            via=new_path[:-1],
                        )
                    next_frontier.append((nxt, new_path))

            frontier = next_frontier
            if not frontier:
                break

    # 稳定排序，保证输出可复现
    return sorted(results.values(), key=lambda e: (e.from_key, e.to_key))
