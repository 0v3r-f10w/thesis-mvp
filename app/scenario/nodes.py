"""节点选择与多节点安全约束（A1）。

为什么需要这个模块
==================
单节点时代，``hostPath: /`` 挂进来的一定是**唯一那个节点**的根文件系统，
flag 写进去必然能读到。换成 1 control-plane + 1 worker 之后出现了**静默失败**：

    helper Pod 把 flag 写到「它被调度到的那个节点」
    eval-container 用 hostPath 读「它被调度到的那个节点」
    —— 两者不保证是同一个节点。

一旦错位，``cat /host/flag.txt`` 不是报错，而是返回**空文件或旧内容**，
Pod 仍然 Running、healthcheck 仍然通过、agent 仍然在“正常探索”，
但漏洞永远打不出来。这比直接失败更难排查，也是本项目最不希望出现的
一类失败（测试空气而不自知）。

本模块的三层防御
----------------
1. **显式节点锁定**：所有场景 Pod 都通过 ``nodeSelector`` 落到同一个
   目标节点。用 ``nodeSelector`` 而不是 ``nodeName``，因为前者会走
   调度器、可被 kubelet 校验、且以后换节点只改一个配置项。
2. **双节点 flag 落位**：即使锁定失效（节点被删/重建/驱逐），
   prepare_host 也会把 flag 写到**所有**节点上，保证 hostPath 无论落到
   哪个节点都能读到。锁定是「让实验可复现」，双写是「让实验不静默出错」。
3. **落位后主动校验**：``verify_flag_visible`` 在 eval 容器里真实
   ``cat`` 一次 flag，读不到就直接让 setup 失败 —— 绝不带病跑 agent。

节点选择策略
------------
默认选 **worker** 节点：
- control-plane 通常带 ``node-role.kubernetes.io/control-plane:NoSchedule``
  污点，业务 Pod 落不上去（落上去要么加 toleration，要么本就该落 worker）；
- worker 无污点、镜像干净、被驱逐的概率最低。
可用环境变量 ``DSH_TARGET_NODE`` 显式覆盖，或 ``DSH_TARGET_NODE=any``
放弃锁定（仅用于对照实验，不建议）。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from app.scenario.k8s_helpers import KubectlRunner

#: 显式指定目标节点的环境变量
TARGET_NODE_ENV = "DSH_TARGET_NODE"

#: 特殊值：不锁定节点（Pod 由调度器自由放置）
ANY_NODE = "any"


class NodeSelectionError(RuntimeError):
    """无法确定一个安全的目标节点。"""


@dataclass(slots=True)
class NodeInfo:
    """集群里一个节点的关键属性（只取本项目关心的字段）。"""

    name: str
    ready: bool
    #: 污点列表，形如 ``[{"key":..., "effect":...}]``
    taints: list[dict] = field(default_factory=list)
    #: 是否带 control-plane 角色
    is_control_plane: bool = False

    @property
    def has_no_schedule_taint(self) -> bool:
        """是否存在 ``NoSchedule`` / ``NoExecute`` 污点（业务 Pod 会被拒）。"""
        return any(
            (t.get("effect") or "") in ("NoSchedule", "NoExecute")
            for t in self.taints
        )


def list_nodes(kubectl: KubectlRunner) -> list[NodeInfo]:
    """从集群读取全部节点及其污点/角色。

    Raises:
        NodeSelectionError: kubectl 失败或返回非 JSON。
    """
    result = kubectl.get_json("nodes")
    if not result.ok:
        raise NodeSelectionError(
            f"cannot list nodes: {(result.stderr or result.stdout).strip()[:400]}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise NodeSelectionError(f"kubectl returned non-JSON node list: {exc}") from exc

    nodes: list[NodeInfo] = []
    for item in payload.get("items", []):
        meta = item.get("metadata", {})
        labels = meta.get("labels") or {}
        status = item.get("status", {})
        conditions = status.get("conditions") or []
        ready = any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in conditions
        )
        nodes.append(
            NodeInfo(
                name=meta.get("name", ""),
                ready=ready,
                taints=list(item.get("spec", {}).get("taints") or []),
                is_control_plane=(
                    "node-role.kubernetes.io/control-plane" in labels
                ),
            )
        )
    return nodes


def pick_target_node(kubectl: KubectlRunner) -> str | None:
    """选出一个安全的目标节点名。

    优先级：
    1. 环境变量 ``DSH_TARGET_NODE`` 显式指定（``any`` 表示不锁定）。
    2. 第一个 Ready 且无 ``NoSchedule`` 污点的 **worker** 节点。
    3. 第一个 Ready 且无污点的节点（任何角色）。
    4. 单个节点时直接用它。

    Returns:
        节点名；``None`` 表示「不锁定节点」（仅单节点或显式 any 时）。

    Raises:
        NodeSelectionError: 没有任何 Ready 节点。
    """
    override = (os.environ.get(TARGET_NODE_ENV) or "").strip()
    if override.lower() == ANY_NODE:
        return None

    nodes = list_nodes(kubectl)
    if not nodes:
        raise NodeSelectionError("cluster reports zero nodes")

    ready = [n for n in nodes if n.ready]
    if not ready:
        raise NodeSelectionError(
            f"no Ready nodes (found: {[(n.name, n.ready) for n in nodes]})"
        )

    # 已显式指定：必须存在且 Ready，否则直接报错（不做静默降级）
    if override:
        for n in ready:
            if n.name == override:
                return n.name
        raise NodeSelectionError(
            f"{TARGET_NODE_ENV}={override!r} but no such Ready node; "
            f"available: {[n.name for n in ready]}"
        )

    # 单节点：锁定没有意义，但也无害 —— 保持 None 让 manifest 干净
    if len(ready) == 1:
        return None

    # 多节点：优先无污点 worker
    for n in ready:
        if not n.has_no_schedule_taint and not n.is_control_plane:
            return n.name
    # 退让：任何无污点的 Ready 节点
    for n in ready:
        if not n.has_no_schedule_taint:
            return n.name

    raise NodeSelectionError(
        "every Ready node has a NoSchedule/NoExecute taint; refusing to guess "
        f"(nodes: {[(n.name, n.taints) for n in ready]}). "
        f"Set {TARGET_NODE_ENV} explicitly."
    )


def all_node_names(kubectl: KubectlRunner) -> list[str]:
    """返回全部节点名（用于双节点 flag 落位）。"""
    return [n.name for n in list_nodes(kubectl)]


def node_pinage_manifest_snippet(node_name: str | None) -> dict:
    """生成写入 Pod ``spec`` 的节点锁定字段。

    Args:
        node_name: 目标节点；``None`` 表示不锁定。

    Returns:
        可直接 **合并** 进 Pod spec 的 dict（空 dict 表示不锁定）。
    """
    if not node_name:
        return {}
    return {"nodeSelector": {"kubernetes.io/hostname": node_name}}


def describe_pin(node_name: str | None) -> str:
    """给人看的锁定说明（写进 setup 日志/结果 JSON）。"""
    if not node_name:
        return "unpinned (scheduler decides)"
    return f"pinned to node {node_name} via nodeSelector/kubernetes.io/hostname"


# ---------------------------------------------------------------------------
# 落位校验
# ---------------------------------------------------------------------------


def verify_flag_visible(
    *,
    pod: str,
    namespace: str,
    container: str,
    in_pod_path: str,
    expected: str,
    shell: str = "sh",
) -> tuple[bool, str]:
    """在**攻击者 Pod 内**校验 flag 是否真的可见。

    这是多节点环境下最重要的一道防线：如果 hostPath 挂到了错误节点，
    ``cat`` 会返回空而不是报错，所以必须**主动比对内容**，
    不能只看命令是否成功。

    Args:
        pod: 攻击者 Pod 名。
        namespace: 命名空间。
        container: 容器名。
        in_pod_path: flag 在**容器内**的路径（如 ``/host/flag.txt``）。
        expected: 期望读到的 flag 内容。
        shell: 容器内 shell（alpine=``sh``，ubuntu=``bash``）。

    Returns:
        ``(ok, detail)``。
    """
    from app.exec.executor import Executor, KubectlTransport

    probe = (
        f"if [ -f {in_pod_path} ]; then "
        f"printf 'VISIBLE:'; cat {in_pod_path}; "
        "else printf 'MISSING'; fi"
    )
    result = Executor(default_timeout=60).execute(
        KubectlTransport(
            pod=pod,
            namespace=namespace,
            container=container,
            shell=shell,
            shell_flags=(),
        ),
        probe,
    )
    text = (result.stdout or "") + (result.stderr or "")
    if expected and expected in text:
        return True, f"flag visible in pod at {in_pod_path}"
    if "MISSING" in text:
        return False, (
            f"flag NOT visible at {in_pod_path} inside {namespace}/{pod} "
            f"(file absent -> hostPath landed on a node without the flag)"
        )
    return False, (
        f"flag mismatch at {in_pod_path}: expected {expected!r}; got {text.strip()[:200]!r}"
    )
