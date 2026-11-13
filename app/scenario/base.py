"""场景抽象基类（复刻 SandboxEscapeBench「场景=目录」约定）。

原版约定（task.py + setup.sh + solution*.sh）在本项目的对应关系：
- ``task.py``      → 本文件中的 :class:`ScenarioSpec` 声明
- ``setup.sh``     → :meth:`Scenario.setup`（内部用 kubectl apply，不是 docker run）
- ``solution*.sh`` → ``ScenarioSpec.solution_commands``（参考解，供 mock LLM 回放）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.scenario.k8s_helpers import KubectlRunner


@dataclass(slots=True)
class ScenarioSpec:
    """场景的静态声明。"""

    name: str
    namespace: str
    pod_name: str
    container: str
    #: agent 要读到的 flag 在「假宿主」上的路径
    #: （kind 场景：节点容器内路径；QEMU 场景：VM 宿主路径）
    flag_host_path: str
    #: 场景自带提示（variant=hint 时拼接）
    hint: str
    #: 该场景考察的攻击链类型：physical / logical
    chain_type: str
    #: 默认镜像（需已在集群内可拉取）
    image: str
    #: 已知的期望 flag 值（由用户手动放入节点；用于 scorer 精确匹配）
    target_flag: str = ""
    #: 容器内挂载宿主根文件的路径（若场景用 hostPath 把 flag 暴露进 Pod）
    host_mount_path: str | None = None
    #: 攻击者 Pod 内**直接可见**的 flag 路径（如 ``/host/flag.txt``）。
    #: 用于多节点环境的落位校验：若 hostPath 挂到了没有 flag 的节点，
    #: ``cat`` 会返回空而**不报错**，必须主动比对内容才能发现。
    #: 为 None 表示攻击 Pod 自己读不到 flag（如 RBAC 场景靠越权 Pod 泄露）。
    in_pod_flag_path: str | None = None
    #: 服务账号名（RBAC 场景使用）
    service_account: str = "default"
    #: 目标容器内的 shell（alpine 只有 sh；ubuntu/debian 有 bash）
    shell: str = "sh"
    shell_flags: tuple[str, ...] = ()
    #: ★ 执行通道（双线支持）
    #:   "kubectl"     —— kind 线：kubectl apply / wait / exec
    #:   "ssh_docker"  —— QEMU 线：SSH 到 VM + docker run / exec
    transport: str = "kubectl"
    #: ★ 节点锁定（仅 kubectl 线有意义）。
    #: kind 场景指定 "desktop-worker"；QEMU 场景为 None。
    node: str | None = None
    #: QEMU 线专用：容器的 docker 容器名（ssh_docker 的 exec 目标）
    docker_container: str | None = None
    #: ★ QEMU 线专用：teardown 时需要清理的 **VM 宿主路径**（支持 glob）。
    #:
    #: 为什么需要显式声明而不是盲扫 /tmp 做差分：
    #: agent 在攻击过程中会在宿主文件系统留下文件（如 cap_sys_module 用
    #: ``insmod target=/tmp/flag_out`` 写了 13 个 ``/tmp/vm_*`` 探针文件）。
    #: 但 ``/tmp`` 里同时可能有系统/其他进程的文件，**盲扫差分删除有误删风险**。
    #: 因此由每个场景**显式声明**自己可能写入的路径模式，
    #: teardown 只按这个列表做 glob 删除。
    #:
    #: 示例：``("/tmp/dsh-*", "/tmp/flag_out", "/tmp/vm_*")``
    host_paths_to_cleanup: tuple[str, ...] = ()
    #: 存在的安全暴露点（写进结果 JSON，便于对账）
    exposures: list[str] = field(default_factory=list)
    #: 参考解命令序列（mock LLM 回放 / 文档用）
    solution_commands: list[str] = field(default_factory=list)

    @property
    def is_qemu(self) -> bool:
        """是否走 QEMU（SSH + docker exec）通道。"""
        return self.transport == "ssh_docker"


@dataclass(slots=True)
class SetupResult:
    """场景准备/清理结果。"""

    ok: bool
    steps: list[dict[str, object]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "steps": self.steps, "error": self.error}


class Scenario(Protocol):
    """所有场景实现的接口。"""

    spec: ScenarioSpec

    def setup(self, kubectl: KubectlRunner) -> SetupResult:
        """创建场景（幂等：先删后建）。"""
        ...

    def teardown(self, kubectl: KubectlRunner) -> SetupResult:
        """清理场景资源。"""
        ...

    def healthcheck(self, kubectl: KubectlRunner) -> tuple[bool, str]:
        """场景自身是否成立（Pod Ready、暴露点存在等）。"""
        ...
