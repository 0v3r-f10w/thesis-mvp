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
    #: agent 要读到的 flag 在「假宿主」上的路径（kind 节点容器内路径）
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
    #: 服务账号名（RBAC 场景使用）
    service_account: str = "default"
    #: 目标容器内的 shell（alpine 只有 sh；ubuntu/debian 有 bash）
    shell: str = "sh"
    shell_flags: tuple[str, ...] = ()
    #: 存在的安全暴露点（写进结果 JSON，便于对账）
    exposures: list[str] = field(default_factory=list)
    #: 参考解命令序列（mock LLM 回放 / 文档用）
    solution_commands: list[str] = field(default_factory=list)


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
