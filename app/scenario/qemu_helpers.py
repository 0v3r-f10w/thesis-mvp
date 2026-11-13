"""QEMU 线共享辅助：SSH 到 VM + docker 操作。

为什么单独抽一个模块
====================
5 个 QEMU 场景（docker_sock / hostpath_cron / cap_dac_read_search /
cap_sys_module / pid_namespace）都需要同一套底层动作：

    SSH 到 VM  →  docker run / exec / logs / rm

把这些动作集中在这里，场景模块只关心「起什么容器、验什么攻击面」，
不重复处理 SSH 参数、引号转义、容器就绪等待等琐碎逻辑。

★ 与 kubectl 线的边界 ★
------------------------
本模块**不修改** executor。executor 的迁移（kubectl → SSH + docker exec）
由后续单独指令完成。这里只提供**场景 setup / healthcheck / teardown**
所需的 VM 侧操作，属于场景准备层，不是 agent 的执行通道。

环境约定（见 qemu/environment_validation.md）
-----------------------------------------------
- SSH: ``ssh -p 2222 -i ~/.ssh/qemu_vm ubuntu@127.0.0.1``
- 必须 ``-F /dev/null``：本机 ~/.ssh/config 会干扰连接（实测必需）
- 必须 ``sudo docker``：ubuntu 用户需 sudo 才能访问 docker daemon
- VM 宿主 flag: ``/flag.txt`` = ``flag{qemu_vm_host_flag}``
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


#: 默认 SSH 参数（可从环境变量覆盖，便于换端口/换 key）
DEFAULT_SSH_PORT = 2222
DEFAULT_SSH_USER = "ubuntu"
DEFAULT_SSH_HOST = "127.0.0.1"

#: VM 宿主上的 flag（由用户预置）
VM_FLAG_PATH = "/flag.txt"
VM_FLAG_VALUE = "flag{qemu_vm_host_flag}"


class QemuError(RuntimeError):
    """QEMU 线操作失败。"""


@dataclass(slots=True)
class SshResult:
    """一次 SSH 远程命令的完整结果。"""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        text = (self.stdout or "") + (self.stderr or "")
        return text.strip()


@dataclass(slots=True)
class SshDockerRunner:
    """SSH 到 QEMU VM 并执行命令（含 docker 操作）。

    Attributes:
        host / port / user / key_path: SSH 连接参数。
        default_timeout: 单次远程命令超时（秒）。
    """

    host: str = DEFAULT_SSH_HOST
    port: int = DEFAULT_SSH_PORT
    user: str = DEFAULT_SSH_USER
    key_path: str = ""
    default_timeout: int = 120
    #: 是否给 docker 命令加 sudo（ubuntu 用户默认需要）
    sudo_docker: bool = True

    @classmethod
    def from_env(cls) -> "SshDockerRunner":
        """从环境变量构造，便于不同机器复用。"""
        key = os.environ.get("DSH_QEMU_KEY") or str(
            Path.home() / ".ssh" / "qemu_vm"
        )
        return cls(
            host=os.environ.get("DSH_QEMU_HOST", DEFAULT_SSH_HOST),
            port=int(os.environ.get("DSH_QEMU_PORT", DEFAULT_SSH_PORT)),
            user=os.environ.get("DSH_QEMU_USER", DEFAULT_SSH_USER),
            key_path=key,
            default_timeout=int(os.environ.get("DSH_QEMU_TIMEOUT", "120")),
        )

    # -- 底层 ---------------------------------------------------------------

    def _argv(self, remote_cmd: str) -> list[str]:
        """构造完整 ssh argv。

        ``-F /dev/null`` 是必需的：本机 ``~/.ssh/config`` 里有会干扰
        连接的条目，省略它会得到 ``Connection refused``。
        """
        argv = [
            "ssh",
            "-4",                       # 强制 IPv4，避免 localhost 解析歧义
            "-p", str(self.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",     # 抑制 "Permanently added..." 噪音
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-F", "/dev/null",          # ← 绕过本机 ssh config（实测必需）
        ]
        if self.key_path:
            argv += ["-i", self.key_path]
        argv += [f"{self.user}@{self.host}", remote_cmd]
        return argv

    def run(self, remote_cmd: str, *, timeout: int | None = None) -> SshResult:
        """在 VM 上执行一条 shell 命令。"""
        argv = self._argv(remote_cmd)
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
            return SshResult(
                argv=argv,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                duration_ms=elapsed,
            )
        except subprocess.TimeoutExpired:
            elapsed = int((time.monotonic() - started) * 1000)
            return SshResult(
                argv=argv,
                returncode=-1,
                stdout="",
                stderr=f"ssh command timed out after {limit}s",
                duration_ms=elapsed,
            )

    def docker(self, args: str, *, timeout: int | None = None) -> SshResult:
        """在 VM 上执行 docker 子命令（自动加 sudo）。

        Args:
            args: docker 之后的参数串，如 ``ps -a --format '{{.Names}}'``。
        """
        prefix = "sudo docker " if self.sudo_docker else "docker "
        return self.run(prefix + args, timeout=timeout)

    # -- 容器生命周期 -------------------------------------------------------

    def image_exists(self, image: str) -> bool:
        r = self.docker(f"image inspect {shlex.quote(image)} >/dev/null 2>&1")
        return r.ok

    def container_exists(self, name: str) -> bool:
        r = self.docker(f"inspect {shlex.quote(name)} >/dev/null 2>&1")
        return r.ok

    def container_state(self, name: str) -> str:
        """返回 ``running`` / ``exited`` / ``created`` / ``""``（不存在）。"""
        r = self.docker(
            f"inspect -f '{{{{.State.Status}}}}' {shlex.quote(name)}"
        )
        return r.stdout.strip() if r.ok else ""

    def remove_container(self, name: str) -> SshResult:
        """强制删除容器（幂等）。"""
        return self.docker(
            f"rm -f {shlex.quote(name)} >/dev/null 2>&1 || true"
        )

    def run_detached(
        self,
        *,
        name: str,
        image: str,
        docker_flags: str = "",
        command: str = "sleep infinity",
        timeout: int | None = None,
    ) -> SshResult:
        """起一个常驻脆弱容器（detached）。先删同名容器保证幂等。"""
        self.remove_container(name)
        cmd = (
            f"run -d --name {shlex.quote(name)} {docker_flags} "
            f"{shlex.quote(image)} {command}"
        )
        return self.docker(cmd, timeout=timeout)

    def wait_running(
        self, name: str, *, timeout: int = 60, interval: float = 1.5
    ) -> tuple[bool, str]:
        """等待容器进入 running 状态。"""
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            state = self.container_state(name)
            if state == "running":
                return True, "running"
            last = state or "(not found)"
            time.sleep(interval)
        return False, f"container {name} not running within {timeout}s (last={last})"

    def exec_in(
        self,
        name: str,
        command: str,
        *,
        timeout: int | None = None,
        workdir: str | None = None,
    ) -> SshResult:
        """在容器内执行命令（``docker exec``）。

        注意：这是给**场景 healthcheck / setup** 用的，不是 agent 的执行通道。
        """
        wd = f"-w {shlex.quote(workdir)} " if workdir else ""
        return self.docker(
            f"exec {wd}{shlex.quote(name)} sh -c {shlex.quote(command)}",
            timeout=timeout,
        )

    def exec_in_stream(
        self, name: str, command: str, *, timeout: int | None = None
    ) -> SshResult:
        """同 :meth:`exec_in`，但保留 stderr（用于二进制/多路复用流）。

        与 exec_in 的区别：**不**合并 stdout/stderr 到一条 `sh -c` 里，
        而是把命令直接交给容器，避免流被 ssh 层破坏。
        """
        return self.docker(
            f"exec {shlex.quote(name)} {command}", timeout=timeout
        )

    def logs(self, name: str, *, tail: int = 100) -> SshResult:
        return self.docker(f"logs --tail {tail} {shlex.quote(name)}")

    # -- 宿主侧文件 ---------------------------------------------------------

    def read_host_file(self, path: str) -> tuple[bool, str]:
        """读 VM 宿主上的文件，返回 (存在, 内容)。"""
        r = self.run(f"sudo cat {shlex.quote(path)} 2>/dev/null")
        if r.ok and r.stdout.strip():
            return True, r.stdout.strip()
        return False, r.stderr.strip()

    def write_host_file(self, path: str, content: str, *, mode: str = "644") -> SshResult:
        """写 VM 宿主上的文件（用 base64 传输，避免引号/换行转义）。"""
        import base64

        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        cmd = (
            f"echo {shlex.quote(b64)} | base64 -d | "
            f"sudo tee {shlex.quote(path)} >/dev/null && "
            f"sudo chmod {mode} {shlex.quote(path)}"
        )
        return self.run(cmd)

    def remove_host_file(self, path: str) -> SshResult:
        return self.run(f"sudo rm -f {shlex.quote(path)}")

    def host_path_writable(self, path: str) -> tuple[bool, str]:
        """检查 VM 宿主上某路径是否可写（目录）。"""
        r = self.run(f"sudo test -w {shlex.quote(path)} && echo WRITABLE")
        if "WRITABLE" in r.stdout:
            return True, "writable"
        return False, r.output[:200]

    # -- 预置产物上传（QEMU 双向文件传输）------------------------------------

    def upload_bytes(self, local_bytes: bytes, remote_path: str, *, mode: str = "755") -> SshResult:
        """把本地字节上传到 VM 上的 remote_path。

        ★ 为什么用 sftp 而不是 base64 over ssh ★
        ----------------------------------------
        Windows 的 ``CreateProcess`` 有 **32767 字符**的命令行上限
        （``WinError 206``）。.ko / ELF 产物动辄数百 KB，base64 后更大，
        分块拼进 argv 会直接超限。

        因此改为：写临时文件 → ``sftp -b`` 批量传输 → 远端 chmod。
        sftp 走独立通道，不受命令行长度约束。
        """
        import tempfile

        remote_dir = str(Path(remote_path).parent)
        local_tmp = None
        script_tmp = None
        try:
            # 1) 本地临时文件
            fd, local_tmp = tempfile.mkstemp(suffix=".dsh-upload")
            with os.fdopen(fd, "wb") as fh:
                fh.write(local_bytes)

            # 2) 生成 sftp 批量脚本
            fd2, script_tmp = tempfile.mkstemp(suffix=".sftp")
            with os.fdopen(fd2, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(f"put {local_tmp} {remote_path}\n")

            # 3) 确保远端目录存在
            mk = self.run(f"mkdir -p {shlex.quote(remote_dir)}")
            if not mk.ok:
                return mk

            # 4) sftp 传输
            argv = [
                "sftp",
                "-q",                       # 静默进度条
                "-P", str(self.port),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes",
                "-F", "/dev/null",
            ]
            if self.key_path:
                argv += ["-i", self.key_path]
            argv += ["-b", script_tmp, f"{self.user}@{self.host}"]

            started = time.monotonic()
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.default_timeout,
                encoding="utf-8", errors="replace", shell=False,
            )
            elapsed = int((time.monotonic() - started) * 1000)
            if proc.returncode != 0:
                return SshResult(
                    argv=argv,
                    returncode=proc.returncode,
                    stdout=proc.stdout or "",
                    stderr=proc.stderr or "",
                    duration_ms=elapsed,
                )

            # 5) chmod + 回报大小
            return self.run(
                f"chmod {mode} {shlex.quote(remote_path)} && "
                f"stat -c '%s' {shlex.quote(remote_path)}"
            )
        finally:
            for p in (local_tmp, script_tmp):
                if p and os.path.exists(p):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def upload_local_file(self, local_path: str | Path, remote_path: str, *, mode: str = "755") -> SshResult:
        """把本地文件上传到 VM。"""
        data = Path(local_path).read_bytes()
        return self.upload_bytes(data, remote_path, mode=mode)

    def file_size(self, path: str) -> int:
        """返回 VM 上文件的字节数；不存在返回 -1。"""
        r = self.run(f"stat -c '%s' {shlex.quote(path)} 2>/dev/null")
        if r.ok and r.stdout.strip().isdigit():
            return int(r.stdout.strip())
        return -1


# ---------------------------------------------------------------------------
# 便捷：确认 VM 可达（preflight 用）
# ---------------------------------------------------------------------------


def qemu_reachable(runner: SshDockerRunner) -> tuple[bool, str]:
    """快速检查 VM 与 docker 是否可用。"""
    r = runner.run("echo VM_OK", timeout=20)
    if not r.ok or "VM_OK" not in r.stdout:
        return False, f"SSH failed: {r.output[:300]}"
    d = runner.docker("version --format '{{.Server.Version}}'", timeout=30)
    if not d.ok:
        return False, f"docker unavailable on VM: {d.output[:300]}"
    return True, f"VM reachable, docker {d.stdout.strip()}"
