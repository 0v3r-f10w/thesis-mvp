"""[入口] python -m app.parse_implicit

把 ImplicitPermission 的三份文本 + 116 行转换表转成 graph.json + actions.json。

数据来源（只读，见 config.py）：
- Explicit_Permission_Analysis/results/result.txt        → actions.json
- Combined_LLM&Static_permission_analysis/permission-reference.txt  → 隐式边（全量）
- Combined_LLM&Static_permission_analysis/assessment/trigger.txt    → 隐式边（权威起点）
- Combined_LLM&Static_permission_analysis/assessment/classification.txt → severity
"""

from __future__ import annotations

import sys
from pathlib import Path

from app.config import (
    ACTIONS_JSON_NAME,
    CLOSURE_MAX_DEPTH,
    CLOSURE_REQUIRE_VERB_INTERSECTION,
    GRAPH_JSON_NAME,
    KUBERNETES_SOURCE_VERSION,
    OUTPUTS_GRAPH_DIR,
    SCHEMA_VERSION,
    SOURCE_CLASSIFICATION,
    SOURCE_PERMISSION_REFERENCE,
    # 注意：config.SOURCE_TRIGGER 是 Path，schema.SOURCE_TRIGGER 是字符串，
    # 两者同名，这里分别加别名避免冲突。
    SOURCE_TRIGGER as TRIGGER_PATH,
    check_required_inputs,
    ensure_output_dirs,
)
from app.graph.closure import (
    derive_closure,
    key_of,
    parse_edge_side,
    parse_edge_side_effect,
    split_key,
)
from app.graph.parse_actions import parse_actions_file
from app.graph.schema import (
    DERIVATION_CLOSURE,
    DERIVATION_DIRECT,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH_DOS,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SOURCE_CLOSURE,
    SOURCE_CLASSIFICATION as CLASSIFICATION_SOURCE_TAG,
    SOURCE_STATIC_LLM,
    SOURCE_TRIGGER,
    GraphDocument,
    GraphEdge,
    GraphNode,
    is_wildcard,
    node_id_for_permission,
)

# ---------------------------------------------------------------------------
# classification.txt 段头 → severity 映射
# ---------------------------------------------------------------------------

_SECTION_TO_SEVERITY: dict[str, str] = {
    "critical": SEVERITY_CRITICAL,
    "high dos": SEVERITY_HIGH_DOS,
    "medium": SEVERITY_MEDIUM,
    "low": SEVERITY_LOW,
}


# ---------------------------------------------------------------------------
# 通用解析
# ---------------------------------------------------------------------------


def _read_lines(path: Path) -> list[str]:
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def parse_reference_edges(path: Path) -> dict[tuple[str, str], int]:
    """解析 ``verb resource --> verb resource`` 形式的文件（reference / trigger）。

    Args:
        path: 文件路径（只读）。

    Returns:
        {(from_key, to_key): 首次出现的行号}，key 形如 ``verb:resource``。
    """
    edges: dict[tuple[str, str], int] = {}
    for lineno, raw in enumerate(_read_lines(path), start=1):
        if "-->" not in raw:
            continue
        left, _, right = raw.partition("-->")
        lhs = parse_edge_side(left)
        rhs = parse_edge_side(right)
        if lhs is None or rhs is None:
            continue
        pair = (key_of(*lhs), key_of(*rhs))
        edges.setdefault(pair, lineno)
    return edges


def parse_classification(
    path: Path,
) -> tuple[dict[tuple[str, str], str], dict[str, int], int, dict[str, int]]:
    """解析分类表，返回 {边: severity} 与各段计数。

    文件形如::

        # Critical
        update certificatesigningrequests/approval --> update certificatesigningrequests
        ...
        # high DOS
        ...
        # low
        create resourcequotas --> deny create pods
        create validatingadmissionpolicies --> deny create [any kubernetes api resource]

    注意：``low`` 段含 53 条带 ``deny``/``allow`` 修饰符的边（deny=45 / allow=8），
    其右侧可能是 ``[any kubernetes api resource]`` 占位符，归一化为资源通配 ``*``。
    这类边描述的是**副作用**（如 ResourceQuota 使某类创建被拒绝），
    与普通的「权限 A 触发权限 B」语义不同，需单独计数以便下游甄别。

    Returns:
        (severities, section_counts, unparsed_line_count, effect_counts)
    """
    severities: dict[tuple[str, str], str] = {}
    section_counts: dict[str, int] = {}
    effect_counts: dict[str, int] = {}
    unparsed = 0
    current: str | None = None

    for raw in _read_lines(path):
        stripped = raw.strip()
        if stripped.startswith("#"):
            header = stripped.lstrip("#").strip().lower()
            current = _SECTION_TO_SEVERITY.get(header)
            if current is not None:
                section_counts[current] = 0
            continue

        if current is None or "-->" not in stripped:
            continue

        left, _, right = stripped.partition("-->")
        lhs = parse_edge_side_effect(left)
        rhs = parse_edge_side_effect(right)
        if lhs is None or rhs is None:
            unparsed += 1
            continue

        l_verb, l_res, l_effect = lhs
        r_verb, r_res, r_effect = rhs

        pair = (key_of(l_verb, l_res), key_of(r_verb, r_res))
        severities.setdefault(pair, current)
        section_counts[current] = section_counts.get(current, 0) + 1

        effect = r_effect or l_effect
        if effect is not None:
            effect_counts[effect] = effect_counts.get(effect, 0) + 1

    return severities, section_counts, unparsed, dict(sorted(effect_counts.items()))


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def build_graph() -> tuple[GraphDocument, object, dict[str, object]]:
    """构建 graph.json 与 actions.json 所需数据。"""
    # 1) 显式权限表 → actions
    actions_doc = parse_actions_file()
    explicit_keys: set[str] = {
        key_of(a.verb, a.resource) for a in actions_doc.actions
    }

    # 2) 三份来源
    ref_edges = parse_reference_edges(SOURCE_PERMISSION_REFERENCE)
    trigger_edges = parse_reference_edges(TRIGGER_PATH)
    severities, section_counts, unparsed_classification, effect_counts = (
        parse_classification(SOURCE_CLASSIFICATION)
    )

    # 3) 合并边：trigger 为权威起点
    #    reference / trigger 是主体；classification 中独有、且未见于前两者的边
    #    （如 ResourceQuota / ValidatingAdmissionPolicy 的 deny/allow 副作用边，
    #      共 53 条）也必须入图，否则会静默丢失分类数据。
    ref_pairs: set[tuple[str, str]] = set(ref_edges)
    trigger_pairs: set[tuple[str, str]] = set(trigger_edges)
    classification_pairs: set[tuple[str, str]] = set(severities)

    all_pairs: set[tuple[str, str]] = (
        ref_pairs | trigger_pairs | classification_pairs
    )

    edges: list[GraphEdge] = []
    node_accumulator: dict[str, tuple[str, str]] = {}

    def _register_node(key: str) -> None:
        if key in node_accumulator:
            return
        verb, resource = split_key(key)
        node_accumulator[key] = (verb, resource)

    for idx, pair in enumerate(sorted(all_pairs), start=1):
        from_key, to_key = pair
        _register_node(from_key)
        _register_node(to_key)

        in_ref = pair in ref_pairs
        in_trigger = pair in trigger_pairs
        in_classification = pair in classification_pairs

        if in_trigger:
            # 动态验证过的权威起点
            source = SOURCE_TRIGGER
            verified = True
        elif in_ref:
            source = SOURCE_STATIC_LLM
            verified = False
        else:
            # 仅分类表收录（deny/allow 副作用边）
            source = CLASSIFICATION_SOURCE_TAG
            verified = False

        edges.append(
            GraphEdge(
                edge_id=f"e:{idx:05d}",
                from_key=from_key,
                to_key=to_key,
                severity=severities.get(pair),
                verified=verified,
                source=source,
                derivation=DERIVATION_DIRECT,
                evidence={
                    "in_permission_reference": in_ref,
                    "in_trigger": in_trigger,
                    "in_classification": in_classification,
                    "line_ref": {
                        "permission_reference": ref_edges.get(pair),
                        "trigger": trigger_edges.get(pair),
                    },
                },
            )
        )

    # 4) 传递闭包（带权限交集约束）
    adjacency: dict[str, list[str]] = {}
    for from_key, to_key in all_pairs:
        adjacency.setdefault(from_key, []).append(to_key)
    for k in adjacency:
        adjacency[k] = sorted(set(adjacency[k]))

    closure_edges = derive_closure(
        adjacency=adjacency,
        explicit_keys=explicit_keys,
        max_depth=CLOSURE_MAX_DEPTH,
        require_verb_intersection=CLOSURE_REQUIRE_VERB_INTERSECTION,
    )

    next_idx = len(edges) + 1
    existing_pairs = set(all_pairs)
    for ce in closure_edges:
        if (ce.from_key, ce.to_key) in existing_pairs:
            continue  # 已有直接边，不重复
        _register_node(ce.from_key)
        _register_node(ce.to_key)
        edges.append(
            GraphEdge(
                edge_id=f"e:{next_idx:05d}",
                from_key=ce.from_key,
                to_key=ce.to_key,
                severity=severities.get((ce.from_key, ce.to_key)),
                verified=False,
                source=SOURCE_CLOSURE,
                derivation=DERIVATION_CLOSURE,
                evidence={"closure_depth": ce.depth, "via": list(ce.via)},
            )
        )
        next_idx += 1

    # 5) 节点
    nodes: list[GraphNode] = []
    for key in sorted(node_accumulator):
        verb, resource = node_accumulator[key]
        wildcard = is_wildcard(verb, resource)
        nodes.append(
            GraphNode(
                node_id=(
                    "wildcard:*:*"
                    if wildcard
                    else node_id_for_permission(verb, resource)
                ),
                kind="wildcard" if wildcard else "permission",
                verb=verb,
                resource=resource,
                is_subresource="/" in resource,
                explicit=key in explicit_keys,
                action_ref=None if wildcard else f"act:{resource}:{verb}",
            )
        )

    # 6) 统计
    def _count_by(field_name: str) -> dict[str, int]:
        acc: dict[str, int] = {}
        for e in edges:
            value = getattr(e, field_name)
            if value is None:
                continue
            acc[str(value)] = acc.get(str(value), 0) + 1
        return dict(sorted(acc.items()))

    direct_count = sum(1 for e in edges if e.derivation == DERIVATION_DIRECT)
    closure_count = sum(1 for e in edges if e.derivation == DERIVATION_CLOSURE)

    stats: dict[str, object] = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "explicit_node_count": sum(1 for n in nodes if n.explicit),
        "wildcard_node_count": sum(1 for n in nodes if n.kind == "wildcard"),
        "by_source": _count_by("source"),
        "by_severity": _count_by("severity"),
        "by_derivation": _count_by("derivation"),
        "by_verification": {
            "verified": sum(1 for e in edges if e.verified),
            "unverified": sum(1 for e in edges if not e.verified),
        },
        "classification_section_counts": dict(sorted(section_counts.items())),
        "classification_effect_counts": dict(sorted(effect_counts.items())),
        "classification_unparsed_lines": unparsed_classification,
        "source_line_counts": {
            "permission_reference": len(_read_lines(SOURCE_PERMISSION_REFERENCE)),
            "trigger": len(_read_lines(TRIGGER_PATH)),
        },
        "direct_edge_count": direct_count,
        "closure_edge_count": closure_count,
        "closure_params": {
            "max_depth": CLOSURE_MAX_DEPTH,
            "require_verb_intersection": CLOSURE_REQUIRE_VERB_INTERSECTION,
        },
    }

    sources = {
        "permission_reference": {
            "file": str(SOURCE_PERMISSION_REFERENCE),
            "lines": len(_read_lines(SOURCE_PERMISSION_REFERENCE)),
            "edges": len(ref_edges),
        },
        "trigger": {
            "file": str(TRIGGER_PATH),
            "lines": len(_read_lines(TRIGGER_PATH)),
            "edges": len(trigger_edges),
            "authoritative": True,
        },
        "classification": {
            "file": str(SOURCE_CLASSIFICATION),
            "lines": len(_read_lines(SOURCE_CLASSIFICATION)),
            "section_counts": dict(sorted(section_counts.items())),
            "effect_counts": dict(sorted(effect_counts.items())),
            "unparsed_lines": unparsed_classification,
        },
        "explicit_permissions": {
            "file": actions_doc.source_file,
            "lines": actions_doc.source_line_count,
            "action_count": len(actions_doc.actions),
        },
        "kubernetes_version": KUBERNETES_SOURCE_VERSION,
        "schema_version": SCHEMA_VERSION,
    }

    graph_doc = GraphDocument(
        sources=sources, nodes=nodes, edges=edges, stats=stats
    )
    return graph_doc, actions_doc, stats


def main() -> int:
    """入口。返回进程退出码。"""
    missing = check_required_inputs()
    if missing:
        print("[error] 以下输入文件缺失（参考目录应为只读挂载）:", file=sys.stderr)
        for p in missing:
            print(f"  - {p}", file=sys.stderr)
        return 2

    ensure_output_dirs()

    graph_doc, actions_doc, stats = build_graph()

    graph_path = OUTPUTS_GRAPH_DIR / GRAPH_JSON_NAME
    actions_path = OUTPUTS_GRAPH_DIR / ACTIONS_JSON_NAME
    graph_doc.write(graph_path)
    actions_doc.write(actions_path)

    # ---- 打印（验收标准要求精确数量）----
    a_stats = actions_doc.stats
    print("=" * 68)
    print("actions.json")
    print("=" * 68)
    print(f"  source_lines        = {actions_doc.source_line_count}")
    print(f"  resources           = {a_stats['resource_count']}")
    print(f"  action_primitives   = {a_stats['action_count']}")
    print(f"  verbs               = {a_stats['verb_count']} {a_stats['verbs']}")
    print(f"  subresource_actions = {a_stats['subresource_action_count']}")
    print(
        f"  mapped / unmapped   = {a_stats['mapped_primitive_count']} / "
        f"{a_stats['unmapped_primitive_count']}"
    )

    print()
    print("=" * 68)
    print("graph.json")
    print("=" * 68)
    print(f"  nodes               = {stats['node_count']} "
          f"(explicit={stats['explicit_node_count']}, "
          f"wildcard={stats['wildcard_node_count']})")
    print(f"  edges               = {stats['edge_count']} "
          f"(direct={stats['direct_edge_count']}, "
          f"closure={stats['closure_edge_count']})")

    src = stats["by_source"]
    print(f"  by_source           = " +
          "  ".join(f"{k}={v}" for k, v in src.items()))
    sev = stats["by_severity"]
    print(f"  by_severity         = " +
          "  ".join(f"{k}={v}" for k, v in sev.items()))
    ver = stats["by_verification"]
    print(f"  by_verification     = verified={ver['verified']} "
          f"unverified={ver['unverified']}")

    sec = stats["classification_section_counts"]
    print(f"  classification      = " +
          "  ".join(f"{k}={v}" for k, v in sec.items()))
    eff = stats["classification_effect_counts"]
    if eff:
        print(f"  effect_modifiers    = " +
              "  ".join(f"{k}={v}" for k, v in eff.items()) +
              "   (deny/allow：副作用边，语义区别于普通权限触发)")
    unparsed = stats["classification_unparsed_lines"]
    print(f"  unparsed_lines      = {unparsed}"
          + ("" if unparsed == 0 else "   ← 警告：存在未解析行"))
    lc = stats["source_line_counts"]
    print(f"  source_lines        = permission_reference={lc['permission_reference']} "
          f"trigger={lc['trigger']}")

    print()
    print("outputs:")
    print(f"  {graph_path}")
    print(f"  {actions_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
