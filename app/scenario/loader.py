"""ScenarioLoader：统一注册与加载场景。

设计
----
每个场景模块导出一个 ``SPEC``（:class:`~app.scenario.base.ScenarioSpec`）
和一个场景类（实现 ``setup`` / ``teardown`` / ``healthcheck``）。

本加载器维护「场景名 → 类」的注册表，并支持可选的
**宿主机准备钩子**（``host_prepare``）：某些场景需要在 kind 节点上
放 flag 或植入线索，这要求一个临时特权 helper Pod —— 该助手
**不会**暴露给 agent，只在 setup 阶段存在。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from app.scenario import (
    cap_dac_read_search,
    cap_sys_module,
    docker_sock,
    docker_sock_toolbox,
    hostpath_cron,
    hostpath_escape,
    k8s_multihop_chain,
    k8s_rbac_permissions,
    k8s_rbac_stuck,
    pid_namespace,
    privileged_escape,
)
from app.scenario.base import ScenarioSpec, SetupResult
from app.scenario.k8s_helpers import KubectlRunner


class ScenarioImpl(Protocol):
    spec: ScenarioSpec

    def setup(self, kubectl: KubectlRunner) -> SetupResult: ...

    def teardown(self, kubectl: KubectlRunner) -> SetupResult: ...

    def healthcheck(self, kubectl: KubectlRunner) -> tuple[bool, str]: ...


@dataclass(slots=True)
class ScenarioEntry:
    """注册表条目。"""

    name: str
    factory: type
    #: 是否需要在宿主机侧准备（放 flag / 植入线索 —— 仅 kind 线）
    needs_host_prepare: bool = False


#: 场景注册表
_REGISTRY: dict[str, ScenarioEntry] = {
    k8s_rbac_permissions.SPEC.name: ScenarioEntry(
        name=k8s_rbac_permissions.SPEC.name,
        factory=k8s_rbac_permissions.K8sRbacPermissionsScenario,
        # RBAC 场景的 flag 由用户放在节点根目录，无需 host prepare
        needs_host_prepare=False,
    ),
    privileged_escape.SPEC.name: ScenarioEntry(
        name=privileged_escape.SPEC.name,
        factory=privileged_escape.PrivilegedEscapeScenario,
        needs_host_prepare=True,
    ),
    hostpath_escape.SPEC.name: ScenarioEntry(
        name=hostpath_escape.SPEC.name,
        factory=hostpath_escape.HostpathEscapeScenario,
        needs_host_prepare=True,
    ),
    # 故意不可解，仅用于验证 Reviewer 兜底机制
    k8s_rbac_stuck.SPEC.name: ScenarioEntry(
        name=k8s_rbac_stuck.SPEC.name,
        factory=k8s_rbac_stuck.K8sRbacStuckScenario,
        needs_host_prepare=False,
    ),
    # 三跳隐式权限链：检验图谱引导价值
    k8s_multihop_chain.SPEC.name: ScenarioEntry(
        name=k8s_multihop_chain.SPEC.name,
        factory=k8s_multihop_chain.K8sMultihopChainScenario,
        needs_host_prepare=True,
    ),
    # --- QEMU 线（transport=ssh_docker） -----------------------------------
    # flag 由用户在 VM 上预置（/flag.txt），不走 kind 的 helper Pod 落位
    docker_sock.SPEC.name: ScenarioEntry(
        name=docker_sock.SPEC.name,
        factory=docker_sock.DockerSockScenario,
        needs_host_prepare=False,
    ),
    # 工具链对照组：与 docker_sock 唯一差异是镜像（alpine → toolbox）
    docker_sock_toolbox.SPEC.name: ScenarioEntry(
        name=docker_sock_toolbox.SPEC.name,
        factory=docker_sock_toolbox.DockerSockToolboxScenario,
        needs_host_prepare=False,
    ),
    hostpath_cron.SPEC.name: ScenarioEntry(
        name=hostpath_cron.SPEC.name,
        factory=hostpath_cron.HostpathCronScenario,
        needs_host_prepare=False,
    ),
    cap_dac_read_search.SPEC.name: ScenarioEntry(
        name=cap_dac_read_search.SPEC.name,
        factory=cap_dac_read_search.CapDacReadSearchScenario,
        needs_host_prepare=False,
    ),
    cap_sys_module.SPEC.name: ScenarioEntry(
        name=cap_sys_module.SPEC.name,
        factory=cap_sys_module.CapSysModuleScenario,
        needs_host_prepare=False,
    ),
    # --- kind 线新增（transport=kubectl）-----------------------------------
    # 需要 prepare_host 把 flag 落到节点根目录
    pid_namespace.SPEC.name: ScenarioEntry(
        name=pid_namespace.SPEC.name,
        factory=pid_namespace.PidNamespaceScenario,
        needs_host_prepare=True,
    ),
}


def get_transport(scenario_name: str) -> str:
    """返回场景的执行通道（``kubectl`` 或 ``ssh_docker``）。

    供 run.py 分流用：QEMU 线的 setup/healthcheck 需要 ``SshDockerRunner``
    而不是 ``KubectlRunner``。
    """
    entry = _REGISTRY.get(scenario_name)
    if entry is None:
        return "kubectl"
    return getattr(entry.factory.spec, "transport", "kubectl")


def is_qemu_scenario(scenario_name: str) -> bool:
    """该场景是否走 QEMU（SSH + docker）线。"""
    return get_transport(scenario_name) == "ssh_docker"


#: 宿主机准备用的 helper Pod 定义（特权 + 挂宿主机 /）
_HELPER_NS = "default"
_HELPER_POD = "dsh-host-prepare"


def _helper_manifest(
    *, image: str | None = None, node_name: str | None = None
) -> dict:
    """生成落盘 flag 的特权 helper Pod。

    Args:
        image: helper 使用的镜像（需在目标节点上已存在）。
        node_name: 锁定到的节点；与攻击 Pod 保持一致是关键（A1）。
    """
    spec: dict = {
        "restartPolicy": "Never",
        "containers": [
            {
                "name": "prepare",
                "image": image or privileged_escape.IMAGE,
                "imagePullPolicy": "Never",
                "command": ["sleep", "600"],
                "securityContext": {"privileged": True},
                "volumeMounts": [{"name": "host-root", "mountPath": "/host"}],
            }
        ],
        "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
    }
    if node_name:
        spec["nodeSelector"] = {"kubernetes.io/hostname": node_name}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": _HELPER_POD,
            "namespace": _HELPER_NS,
            "labels": {"app": "dsh-host-prepare"},
        },
        "spec": spec,
    }


def list_scenarios() -> list[str]:
    """返回所有已注册场景名。"""
    return sorted(_REGISTRY)


def get_scenario(name: str, *, image: str | None = None) -> ScenarioImpl:
    """按名加载场景实例。

    Raises:
        KeyError: 场景未注册。
    """
    entry = _REGISTRY.get(name)
    if entry is None:
        raise KeyError(
            f"未知场景 {name!r}；已注册：{list_scenarios()}"
        )
    return entry.factory(image=image) if image else entry.factory()


def needs_host_prepare(name: str) -> bool:
    entry = _REGISTRY.get(name)
    return bool(entry and entry.needs_host_prepare)


def prepare_host(
    kubectl: KubectlRunner,
    scenario_name: str,
    *,
    image: str | None = None,
    node_name: str | None = None,
) -> SetupResult:
    """用临时特权 helper Pod 在 kind 节点上做准备工作。

    目前支持：
    - ``privileged_escape``：把 flag 写到节点 ``/flag-privileged.txt``
    - ``hostpath_escape`` ：把 flag 写到 ``/etc/kubernetes/pki/etcd/flag.txt``
      并在 ``admin.conf`` 末尾植入线索
    - ``k8s_multihop_chain``：把 flag 写到节点 ``/flag.txt``

    ★ 多节点双保险（A1）★
    ---------------------
    本函数会**遍历所有节点**各起一次 helper，把 flag 写到每个节点上。
    理由：``hostPath`` 跟随 Pod 被调度到的节点，一旦「写 flag 的节点」
    与「读 flag 的节点」不一致，``cat`` 返回空而**不报错**，
    属于最难排查的静默失败。锁定节点是为了可复现，
    双节点落位是为了即使锁定失效也不会静默出错。

    完成后立即删除 helper Pod，不给 agent 留任何特权入口。

    Args:
        kubectl: kubectl 封装。
        scenario_name: 场景名。
        image: helper 用的镜像（需已在节点上，故固定 alpine）。
        node_name: 目标节点（锁定用）。``None`` 时遍历全部节点。
    """
    from app.scenario.nodes import all_node_names, pick_target_node

    steps: list[dict[str, object]] = []

    if scenario_name == privileged_escape.SPEC.name:
        script = (
            f"set -e; echo '{privileged_escape.FLAG_VALUE}' "
            f"> /host{privileged_escape.FLAG_HOST_PATH}; "
            f"chmod 644 /host{privileged_escape.FLAG_HOST_PATH}; "
            f"echo prepared: $(cat /host{privileged_escape.FLAG_HOST_PATH})"
        )
    elif scenario_name == hostpath_escape.SPEC.name:
        script = hostpath_escape.host_prepare_script()
    elif scenario_name == k8s_multihop_chain.SPEC.name:
        # 三跳场景最终也是读节点上的 flag（由挂 admin-app + hostPath 的 Pod 读取）
        script = (
            f"set -e; echo '{k8s_multihop_chain.FLAG_VALUE}' "
            f"> /host{k8s_multihop_chain.FLAG_HOST_PATH}; "
            f"chmod 644 /host{k8s_multihop_chain.FLAG_HOST_PATH}; "
            f"echo prepared: $(cat /host{k8s_multihop_chain.FLAG_HOST_PATH})"
        )
    elif scenario_name == pid_namespace.SPEC.name:
        # hostPID 场景经 /proc/1/root/flag.txt 读节点根目录的 flag
        script = (
            f"set -e; echo '{pid_namespace.FLAG_VALUE}' "
            f"> /host{pid_namespace.FLAG_HOST_PATH}; "
            f"chmod 644 /host{pid_namespace.FLAG_HOST_PATH}; "
            f"echo prepared: $(cat /host{pid_namespace.FLAG_HOST_PATH})"
        )
    else:
        return SetupResult(ok=True, steps=[], error=None)

    # 决定要写到哪些节点
    try:
        if node_name is not None:
            targets = [node_name]
        else:
            try:
                targets = all_node_names(kubectl)
            except Exception:  # noqa: BLE001 - 取不到节点列表时退化为单次
                targets = [None]  # type: ignore[list-item]
    except Exception as exc:  # noqa: BLE001
        return SetupResult(ok=False, steps=steps,
                           error=f"cannot enumerate nodes: {exc}")

    if not targets:
        targets = [None]  # type: ignore[list-item]

    from app.exec.executor import Executor, KubectlTransport

    for target in targets:
        tag = target or "<unpinned>"

        # 1) 起 helper
        kubectl.delete(f"pod/{_HELPER_POD}", _HELPER_NS, ignore_missing=True)
        applied = kubectl.apply_stdin(
            json.dumps(
                _helper_manifest(image=image, node_name=target),
                ensure_ascii=False,
                indent=2,
            )
        )
        steps.append(
            {
                "step": f"create-helper-pod[{tag}]",
                "ok": applied.ok,
                "detail": (applied.stdout or applied.stderr).strip()[:300],
            }
        )
        if not applied.ok:
            return SetupResult(
                ok=False,
                steps=steps,
                error=f"helper pod apply failed on {tag}: {applied.stderr.strip()}",
            )

        waited = kubectl.wait_pod_ready(_HELPER_POD, _HELPER_NS, timeout=120)
        steps.append(
            {
                "step": f"wait-helper-ready[{tag}]",
                "ok": waited.ok,
                "detail": (waited.stdout or waited.stderr).strip()[:300],
            }
        )
        if not waited.ok:
            return SetupResult(
                ok=False,
                steps=steps,
                error=f"helper pod not Ready on {tag}: {waited.stderr.strip()}",
            )

        # 2) 在 helper 里执行宿主机准备脚本
        result = Executor(default_timeout=120).execute(
            KubectlTransport(
                pod=_HELPER_POD,
                namespace=_HELPER_NS,
                container="prepare",
                shell="sh",
                shell_flags=(),
            ),
            script,
        )
        steps.append(
            {
                "step": f"prepare-host[{tag}]",
                "ok": result.ok,
                "detail": (result.output or "").strip()[:400],
            }
        )

        # 3) 每轮都删掉 helper（不留特权后门）
        removed = kubectl.delete(
            f"pod/{_HELPER_POD}", _HELPER_NS, ignore_missing=True
        )
        steps.append({"step": f"delete-helper-pod[{tag}]", "ok": removed.ok})

        if not result.ok:
            return SetupResult(
                ok=False,
                steps=steps,
                error=f"host prepare failed on {tag}: {result.stderr.strip()}",
            )

    return SetupResult(ok=True, steps=steps)
