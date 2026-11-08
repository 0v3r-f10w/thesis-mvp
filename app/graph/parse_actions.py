"""解析 Explicit_Permission_Analysis/results/result.txt → actions.json。

输入格式（116 行，五段式，但每行只有一个资源条目）::

    deployments/scale [Get Update Patch]
    pods/exec [Get Create]
    secrets [Create Delete DeleteCollection Get List Update Watch Patch]

即 ``<resource> [<Verb> <Verb> ...]``，verb 为 Kubernetes RBAC 的 Title Case 形式。
输出时统一转小写，与 permission-reference.txt / trigger.txt 的书写保持一致。
"""

from __future__ import annotations

import re
from pathlib import Path

from app.config import SOURCE_EXPLICIT_PERMISSIONS
from app.graph.schema import ActionPrimitive, ActionsDocument

#: 匹配 ``<resource> [<Verbs>]``；resource 允许 ``/`` 子资源后缀
_LINE_RE = re.compile(r"^\s*(?P<resource>[A-Za-z][A-Za-z0-9_./-]*)\s*\[(?P<verbs>[^\]]*)\]\s*$")


# ---------------------------------------------------------------------------
# action_primitive 映射表
# ---------------------------------------------------------------------------
# 说明：第一版只覆盖两个场景（docker_socket / k8s_rbac_permissions）所需的原语，
# 其余动作原语标记为 None（unmapped），不做臆测映射（见 PLAN.md 待确认项）。
_PRIMITIVE_MAP: dict[tuple[str, str], str] = {
    ("create", "pods/exec"): "exec_into_pod",
    ("get", "pods/exec"): "exec_into_pod",
    ("create", "pods"): "create_pod",
    ("delete", "pods"): "delete_pod",
    ("get", "pods"): "read_pod_spec",
    ("list", "pods"): "enumerate_pods",
    ("create", "pods/ephemeralcontainers"): "inject_ephemeral_container",
    ("update", "pods/ephemeralcontainers"): "inject_ephemeral_container",
    ("patch", "pods/ephemeralcontainers"): "inject_ephemeral_container",
    ("get", "secrets"): "read_secret",
    ("list", "secrets"): "enumerate_secrets",
    ("create", "serviceaccounts/token"): "mint_sa_token",
    ("create", "clusterrolebindings"): "bind_cluster_admin",
    ("update", "clusterrolebindings"): "bind_cluster_admin",
    ("patch", "clusterrolebindings"): "bind_cluster_admin",
    ("create", "rolebindings"): "bind_role",
    ("update", "rolebindings"): "bind_role",
    ("patch", "rolebindings"): "bind_role",
    ("get", "nodes"): "read_node",
    ("create", "daemonsets"): "create_daemonset",
    ("create", "deployments"): "create_deployment",
    ("create", "statefulsets"): "create_statefulset",
    ("create", "jobs"): "create_job",
    ("create", "cronjobs"): "create_cronjob",
    ("create", "replicasets"): "create_replicaset",
}


def _split_resource(resource: str) -> tuple[str, str | None]:
    """把 ``pods/exec`` 拆成 (``pods``, ``exec``)；无子资源返回 (resource, None)。"""
    if "/" in resource:
        parent, _, sub = resource.partition("/")
        return parent, sub
    return resource, None


def make_action_id(resource: str, verb: str) -> str:
    """稳定的动作 id，例如 ``act:pods/exec:create``。"""
    return f"act:{resource}:{verb}"


def parse_actions_file(path: Path = SOURCE_EXPLICIT_PERMISSIONS) -> ActionsDocument:
    """解析显式权限转换表。

    Args:
        path: result.txt 路径（只读）。

    Returns:
        ActionsDocument，可直接写 actions.json。

    Raises:
        FileNotFoundError: 输入文件不存在。
        ValueError: 行格式不符合预期（第一版只支持该固定格式）。
    """
    if not path.is_file():
        raise FileNotFoundError(f"显式权限转换表不存在: {path}")

    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]

    actions: list[ActionPrimitive] = []
    seen: set[str] = set()
    bad_lines: list[tuple[int, str]] = []
    resources: set[str] = set()

    for lineno, raw in enumerate(lines, start=1):
        m = _LINE_RE.match(raw)
        if not m:
            bad_lines.append((lineno, raw))
            continue

        resource = m.group("resource")
        verbs_raw = m.group("verbs").split()
        if not verbs_raw:
            bad_lines.append((lineno, raw))
            continue

        parent, sub = _split_resource(resource)
        resources.add(resource)

        for verb_title in verbs_raw:
            verb = verb_title.lower()
            action_id = make_action_id(resource, verb)
            if action_id in seen:
                continue
            seen.add(action_id)

            actions.append(
                ActionPrimitive(
                    action_id=action_id,
                    resource=resource,
                    verb=verb,
                    parent_resource=parent,
                    subresource=sub,
                    is_subresource=sub is not None,
                    action_primitive=_PRIMITIVE_MAP.get((verb, resource)),
                )
            )

    if bad_lines:
        # 第一版只支持固定格式：遇到未知行直接报错，避免静默丢数据
        preview = "; ".join(f"L{n}: {s!r}" for n, s in bad_lines[:5])
        raise ValueError(
            f"显式权限表存在 {len(bad_lines)} 行无法解析（第一版只支持固定格式）: {preview}"
        )

    verbs = sorted({a.verb for a in actions})
    unmapped = sum(1 for a in actions if a.action_primitive is None)
    subresource_actions = sum(1 for a in actions if a.is_subresource)

    stats = {
        "resource_count": len(resources),
        "action_count": len(actions),
        "verb_count": len(verbs),
        "verbs": verbs,
        "subresource_action_count": subresource_actions,
        "mapped_primitive_count": len(actions) - unmapped,
        "unmapped_primitive_count": unmapped,
    }

    return ActionsDocument(
        source_file=str(path),
        source_line_count=len(lines),
        actions=actions,
        stats=stats,
    )


if __name__ == "__main__":  # 便于单独调试
    doc = parse_actions_file()
    print(doc.stats)
