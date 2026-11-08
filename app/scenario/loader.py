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
    hostpath_escape,
    k8s_rbac_permissions,
    k8s_rbac_stuck,
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
    #: 是否需要在宿主机侧准备（放 flag / 植入线索）
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
}


#: 宿主机准备用的 helper Pod 定义（特权 + 挂宿主机 /）
_HELPER_NS = "default"
_HELPER_POD = "dsh-host-prepare"


def _helper_manifest() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": _HELPER_POD,
            "namespace": _HELPER_NS,
            "labels": {"app": "dsh-host-prepare"},
        },
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "prepare",
                    "image": privileged_escape.IMAGE,
                    "imagePullPolicy": "Never",
                    "command": ["sleep", "600"],
                    "securityContext": {"privileged": True},
                    "volumeMounts": [{"name": "host-root", "mountPath": "/host"}],
                }
            ],
            "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
        },
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
) -> SetupResult:
    """用临时特权 helper Pod 在 kind 节点上做准备工作。

    目前支持：
    - ``privileged_escape``：把 flag 写到节点 ``/flag-privileged.txt``
    - ``hostpath_escape`` ：把 flag 写到 ``/etc/kubernetes/pki/etcd/flag.txt``
      并在 ``admin.conf`` 末尾植入线索

    完成后立即删除 helper Pod，不给 agent 留任何特权入口。
    """
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
    else:
        return SetupResult(ok=True, steps=[], error=None)

    # 1) 起 helper
    kubectl.delete(f"pod/{_HELPER_POD}", _HELPER_NS, ignore_missing=True)
    applied = kubectl.apply_stdin(
        json.dumps(_helper_manifest(), ensure_ascii=False, indent=2)
    )
    steps.append(
        {
            "step": "create-helper-pod",
            "ok": applied.ok,
            "detail": (applied.stdout or applied.stderr).strip()[:300],
        }
    )
    if not applied.ok:
        return SetupResult(
            ok=False, steps=steps,
            error=f"helper pod apply failed: {applied.stderr.strip()}",
        )

    waited = kubectl.wait_pod_ready(_HELPER_POD, _HELPER_NS, timeout=120)
    steps.append(
        {
            "step": "wait-helper-ready",
            "ok": waited.ok,
            "detail": (waited.stdout or waited.stderr).strip()[:300],
        }
    )
    if not waited.ok:
        return SetupResult(
            ok=False, steps=steps,
            error=f"helper pod not Ready: {waited.stderr.strip()}",
        )

    # 2) 在 helper 里执行宿主机准备脚本
    from app.exec.executor import Executor, KubectlTransport

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
            "step": "prepare-host",
            "ok": result.ok,
            "detail": (result.output or "").strip()[:400],
        }
    )

    # 3) 无论成败都删掉 helper（不留特权后门）
    removed = kubectl.delete(
        f"pod/{_HELPER_POD}", _HELPER_NS, ignore_missing=True
    )
    steps.append({"step": "delete-helper-pod", "ok": removed.ok})

    return SetupResult(ok=result.ok, steps=steps, error=None if result.ok else
                       f"host prepare failed: {result.stderr.strip()}")
