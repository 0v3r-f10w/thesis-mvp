"""唯一的执行出口（复刻 SandboxEscapeBench ``tools.py::_execute`` 的单点设计）。

设计要点
--------
1. **全项目只有这一个函数调用 subprocess**。agent 的 bash 工具、场景 setup、
   flag 落位全部走这里，便于统一加超时、分类、审计。
2. 返回结构化的 :class:`ExecResult`（rc / stdout / stderr / 时长 / 分类），
   而不是原版的字符串拼接 —— 因为 health 判别需要 rc 和 stderr。
3. ``shell=False`` + list 参数：Windows 中文路径（"云计算系统"）不经过 shell
   拼接，避免转义问题。
4. 两种 Transport：
   - :class:`KubectlTransport`    给 agent 用，进 Pod 执行
   - :class:`NodeExecTransport`   给场景准备用，进 kind 节点容器（放宿主 flag）
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Protocol, Sequence

from app.exec.k8s_probe import FailureClass, classify


@dataclass(slots=True)
class ExecResult:
    """一次执行的完整记录。"""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    failure: FailureClass
    timed_out: bool = False
    #: 供轨迹记录：这条命令是进 Pod 还是进节点
    target: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        """与原版 ``_execute`` 一致的展示形式：stderr 在前，stdout 在后。"""
        if self.stderr:
            return f"{self.stderr}\n{self.stdout}"
        return self.stdout

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "failure_class": self.failure.value,
            "timed_out": self.timed_out,
            "target": self.target,
        }

    def to_dict_meta(self) -> dict[str, object]:
        """紧凑元数据：写进轨迹的 tool_result，不含完整 stdout（由 output 字段承载）。"""
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "duration_ms": self.duration_ms,
            "failure_class": self.failure.value,
            "timed_out": self.timed_out,
            "target": self.target,
            "stdout_len": len(self.stdout),
            "stderr_len": len(self.stderr),
        }


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class Transport(Protocol):
    """把「内层 shell 命令」翻译成完整的 argv。"""

    def build_argv(self, command: str) -> list[str]: ...

    @property
    def target_label(self) -> str: ...


@dataclass(slots=True)
class KubectlTransport:
    """``kubectl exec <pod> -n <ns> [-c <ctr>] -- <shell> [flags] -c "<cmd>"``。

    对应原版 ``tools.py::k8s_bash``（原版硬编码 ``bash --login``）。

    **与参考代码的差异（重要）**：原 bench 的镜像基于 ``ubuntu:20.04``，
    有 bash；本项目第一场景用 ``alpine:latest``，**只有 sh，没有 bash**。
    硬编码 bash 会导致每条命令都失败且错误信息具有误导性
    （``exec: "bash": executable file not found in $PATH``）。
    因此这里把 shell 与其参数做成可配置项，由场景声明。
    """

    pod: str
    namespace: str
    container: str | None = None
    kubectl_bin: str = "kubectl"
    #: 目标容器内的 shell。alpine → ``sh``；ubuntu/debian → ``bash --login``
    shell: str = "bash"
    shell_flags: tuple[str, ...] = ("--login",)

    def build_argv(self, command: str) -> list[str]:
        argv = [self.kubectl_bin, "exec", self.pod, "-n", self.namespace]
        if self.container:
            argv.extend(["-c", self.container])
        argv.append("--")
        argv.append(self.shell)
        argv.extend(self.shell_flags)
        argv.extend(["-c", command])
        return argv

    @property
    def target_label(self) -> str:
        return f"pod:{self.namespace}/{self.pod}"


@dataclass(slots=True)
class NodeExecTransport:
    """``docker exec <node-container> sh -c "<cmd>"``。

    仅用于**场景准备**（往 kind 节点容器写宿主 flag、探测节点内 runtime），
    **不暴露给 agent**。kind 节点是 Docker 容器，与宿主文件系统不通用。
    """

    container: str
    docker_bin: str = "docker"

    def build_argv(self, command: str) -> list[str]:
        return [self.docker_bin, "exec", self.container, "sh", "-c", command]

    @property
    def target_label(self) -> str:
        return f"node:{self.container}"


# ---------------------------------------------------------------------------
# 执行器
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Executor:
    """收敛所有 subprocess 调用。

    Attributes:
        default_timeout: 默认超时秒数（原版 tools.py 也是 360）。
        binary_override: 可选的可执行文件绝对路径映射（如 kind.exe）。
    """

    default_timeout: int = 360
    binary_override: dict[str, str] = field(default_factory=dict)

    def execute(
        self,
        transport: Transport,
        command: str,
        *,
        timeout: int | None = None,
    ) -> ExecResult:
        """执行一条内层命令。

        Args:
            transport: KubectlTransport 或 NodeExecTransport。
            command: 要在 Pod / 节点容器内执行的 shell 命令。
            timeout: 覆盖默认超时。

        Returns:
            ExecResult —— 永不抛异常（超时也返回结果），便于上层统一记录。
        """
        argv = transport.build_argv(command)
        argv = self._resolve_binary(argv)
        limit = timeout if timeout is not None else self.default_timeout

        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=limit,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            elapsed = int((time.monotonic() - started) * 1000)
            failure = classify(proc.returncode, proc.stderr)
            return ExecResult(
                argv=argv,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                duration_ms=elapsed,
                failure=failure,
                timed_out=False,
                target=transport.target_label,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            return ExecResult(
                argv=argv,
                returncode=-1,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr) or f"command timed out after {limit}s",
                duration_ms=elapsed,
                failure=classify(-1, "", timed_out=True),
                timed_out=True,
                target=transport.target_label,
            )
        except FileNotFoundError as exc:
            # 二进制本身不存在（如 kubectl 不在 PATH）—— 属于部署问题，不是沙箱失效
            elapsed = int((time.monotonic() - started) * 1000)
            return ExecResult(
                argv=argv,
                returncode=-2,
                stdout="",
                stderr=f"executor: binary not found: {exc}",
                duration_ms=elapsed,
                failure=FailureClass.CONTROL_PLANE_UNREACHABLE,
                timed_out=False,
                target=transport.target_label,
            )

    def _resolve_binary(self, argv: Sequence[str]) -> list[str]:
        """把 argv[0] 替换成 binary_override 指定的绝对路径（若配置）。"""
        out = list(argv)
        if not out:
            return out
        override = self.binary_override.get(out[0])
        if override:
            out[0] = override
        return out

    @staticmethod
    def which(binary: str) -> str | None:
        """查找可执行文件（给 preflight 用）。"""
        return shutil.which(binary)


def _as_text(value: object) -> str:
    """subprocess 超时异常的 stdout/stderr 可能是 bytes 或 None。"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
