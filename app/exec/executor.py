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

import shlex
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


@dataclass(slots=True)
class SshDockerTransport:
    """QEMU 线：``ssh <vm> "sudo docker exec <ctr> <shell> -c '<cmd>'"``。

    对应 :class:`KubectlTransport` 在 QEMU 线上的等价物 ——
    agent 的每条命令最终都进到脆弱容器里执行，只是外层换成了
    SSH 到 VM + docker exec。

    ★ 关键：命令用 ``shlex.quote()`` 三次转义 ★
    ------------------------------------------
    命令要穿过三层 shell：

        argv → ssh 的远端 shell → sudo docker exec <ctr> <shell> -c "<cmd>"

    如果不转义，agent 命令里的 ``$变量``、``|``、``'``、``"`` 会被
    **中间层 shell** 解释掉（例如 ``$TOKEN`` 会在 VM 的 shell 里展开成空，
    而不是在容器里展开）。因此：
    1. 内层命令先按容器 shell 转义（``shlex.quote``）
    2. 整个 ``docker exec ...`` 再转义一次给 ssh 的远端 shell
    3. argv 本身用 ``shell=False`` 直接 exec，不经过本机 shell

    这与 kind 线的差异：kubectl exec 的 argv 直接透传，不经过额外 shell，
    所以不需要这一层转义。这是 QEMU 迁移最容易出错的地方。
    """

    container: str
    #: VM 连接参数
    host: str = ""
    port: int = 0
    user: str = ""
    key_path: str = ""
    #: 容器内的 shell（alpine → sh；ubuntu → bash）
    shell: str = "sh"
    shell_flags: tuple[str, ...] = ()
    #: VM 上是否需要 sudo 访问 docker daemon
    sudo_docker: bool = True

    #: ★ 与 KubectlTransport 的接口兼容字段 ★
    #: agent loop 写 trace 时会读 transport.namespace / transport.pod
    #: （见 app/agent/loop.py::run_react 的 trace.run_start）。
    #: QEMU 线没有 K8s namespace 概念，这里给出等价的定位信息，
    #: 保证 loop 无需改动即可同时支持两种 transport。
    namespace: str = ""
    pod: str = ""

    def build_argv(self, command: str) -> list[str]:
        """构造 ``ssh ... <host> <remote-command>`` 的完整 argv。

        ★ 转义链（这是 QEMU 迁移最容易出错的地方）★
        --------------------------------------------
        命令要穿过三层 shell：

            [本机] argv(shell=False) → [VM] sh → [容器] <shell> -c

        正确做法是**分两层**转义，不要给 ssh 的远端命令再加一层引号：

        - 内层：agent 的命令按**容器 shell** 转义（``shlex.quote``）
          → 保证 ``$VAR``、``|``、引号在容器里才被解析
        - 外层：`docker exec ... <shell> -c <内层>` 整串**原样**交给 ssh，
          由 VM 的 sh 解析。这一步必须用 ``shlex.split`` 逆向确认过：
          再加一次 ``shlex.quote`` 会让远端把引号当成命令名的一部分，
          报 ``sudo docker ...: command not found``（实测 rc=127）。

        简言之：**只有内层需要 quote；外层直接拼**。
        """
        # 1) 内层：容器内那条命令，按容器 shell 转义
        inner = shlex.quote(command)
        parts = [
            "docker", "exec",
            shlex.quote(self.container),
            self.shell,
            *self.shell_flags,
            "-c", inner,
        ]

        # 2) 外层：VM 上要执行的一行。sudo 前缀加在最前。
        #    注意这里是**拼接**而非再次 quote —— VM 的 sh 会正常解析
        #    ``docker exec ctr sh -c '<inner>'`` 这一串。
        remote_cmd = ("sudo " if self.sudo_docker else "") + " ".join(parts)

        argv = [
            "ssh",
            "-4",                       # 强制 IPv4，避免 localhost 解析歧义
            "-p", str(self.port),
            *self._common_opts(),
        ]
        if self.key_path:
            argv += ["-i", self.key_path]
        # 远端命令作为**单个 argv 元素**传入：ssh 会把它交给远端 shell 解析，
        # 不需要也不应该在本侧再加引号。
        argv += [f"{self.user}@{self.host}", remote_cmd]
        return argv

    @staticmethod
    def _common_opts() -> tuple[str, ...]:
        """SSH 安全选项（与 qemu_helpers 共用同一份定义）。"""
        from app.config import SSH_COMMON_OPTS

        return SSH_COMMON_OPTS

    @classmethod
    def from_config(cls, *, container: str, **overrides) -> "SshDockerTransport":
        """按 ``app.config`` 的 QEMU 连接参数构造（executor 的默认入口）。"""
        from app.config import (
            qemu_ssh_host,
            qemu_ssh_key_path,
            qemu_ssh_port,
            qemu_ssh_user,
        )

        params = dict(
            container=container,
            host=qemu_ssh_host(),
            port=qemu_ssh_port(),
            user=qemu_ssh_user(),
            key_path=qemu_ssh_key_path(),
        )
        params.update(overrides)
        return cls(**params)

    @property
    def target_label(self) -> str:
        return f"docker:{self.container}@qemu"


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

        ★ 按 transport 类型分流（executor 迁移）★
        ----------------------------------------
        - :class:`KubectlTransport` / :class:`NodeExecTransport`
          → 原有路径，**行为完全不变**（kind 线 4 个场景）。
        - :class:`SshDockerTransport`
          → :meth:`_execute_ssh_docker`，走 SSH + docker exec（QEMU 线）。

        分流依据是 transport 的具体类型，而不是场景名 —— 这样
        场景模块无需知道自己被谁执行，run.py 也无需改。

        Args:
            transport: KubectlTransport / NodeExecTransport / SshDockerTransport。
            command: 要在 Pod / 容器内执行的 shell 命令。
            timeout: 覆盖默认超时。

        Returns:
            ExecResult —— 永不抛异常（超时也返回结果），便于上层统一记录。
        """
        if isinstance(transport, SshDockerTransport):
            return self._execute_ssh_docker(transport, command, timeout=timeout)

        # --- 原有路径：kubectl exec / docker exec（节点）-------------------
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

    def _execute_ssh_docker(
        self,
        transport: SshDockerTransport,
        command: str,
        *,
        timeout: int | None = None,
    ) -> ExecResult:
        """QEMU 线执行：SSH 到 VM + ``sudo docker exec`` 进容器。

        与 kubectl 路径的**唯一结构差异**是外层多了一层 SSH。
        返回值结构与失败分类**完全一致**，因此 run.py / loop.py / health
        无需任何改动。

        ★ 失败分类的额外处理 ★
        ---------------------
        SSH 层自身失败（连不上 VM、认证失败）必须被识别为
        **环境失效**（``CONTROL_PLANE_UNREACHABLE``），否则 health 会把它
        当成「agent 探索失败」，导致卡死时不被终止。

        判定依据：
        - ssh 退出码 255 → SSH 连接层错误（OpenSSH 约定）
        - stderr 含 ``Connection refused`` / ``Permission denied`` /
          ``Could not resolve hostname`` / ``Connection timed out``
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
            stderr_text = proc.stderr or ""

            failure = self._classify_ssh_docker(
                proc.returncode, stderr_text, transport
            )
            return ExecResult(
                argv=argv,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=stderr_text,
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
                stderr=_as_text(exc.stderr) or f"ssh command timed out after {limit}s",
                duration_ms=elapsed,
                failure=classify(-1, "", timed_out=True),
                timed_out=True,
                target=transport.target_label,
            )
        except FileNotFoundError as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            return ExecResult(
                argv=argv,
                returncode=-2,
                stdout="",
                stderr=f"executor: ssh client not found: {exc}",
                duration_ms=elapsed,
                failure=FailureClass.CONTROL_PLANE_UNREACHABLE,
                timed_out=False,
                target=transport.target_label,
            )

    @staticmethod
    def _classify_ssh_docker(
        returncode: int, stderr_text: str, transport: SshDockerTransport
    ) -> FailureClass:
        """把 SSH + docker exec 的结果分类。

        先判 SSH 层（VM 不可达 = 环境失效），再交给原有的
        :func:`classify` 处理容器内命令自身失败（L3，不算环境失效）。
        """
        # OpenSSH 用 255 表示连接层错误
        if returncode == 255:
            return FailureClass.CONTROL_PLANE_UNREACHABLE

        text = (stderr_text or "").lower()
        for marker in (
            "connection refused",
            "connection timed out",
            "could not resolve hostname",
            "permission denied (publickey",
            "no route to host",
            "broken pipe",
            "kex_exchange_identification",
        ):
            if marker in text:
                return FailureClass.CONTROL_PLANE_UNREACHABLE

        # VM 可达但 docker 不可用 → 也是环境问题
        if "cannot connect to the docker daemon" in text:
            return FailureClass.CONTROL_PLANE_UNREACHABLE
        if "no such container" in text or "is not running" in text:
            return FailureClass.TARGET_GONE

        # 其余：容器内命令自身失败（正常探索）
        return classify(returncode, stderr_text)

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
