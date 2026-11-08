"""kubectl 操作封装：apply / wait / 读写 Pod 内文件 / 探测。

所有实际执行都经过 :class:`app.exec.executor.Executor`，保持单点出口。
注意：这里的命令默认走**本机 kubectl**（不是 kubectl exec），
因为它们要操作集群本身，而不是进 Pod 内部。
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass

from app.exec.executor import Executor, ExecResult


@dataclass(slots=True)
class KubectlRunner:
    """在本机用 kubectl 直接操作集群（不进 Pod）。"""

    kubectl_bin: str = "kubectl"
    default_timeout: int = 120

    def _run(self, args: list[str], *, timeout: int | None = None) -> ExecResult:
        """直接调用 kubectl（不经 Transport，因为目标是集群而非 Pod）。"""
        argv = [self.kubectl_bin, *args]
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
            from app.exec.k8s_probe import classify

            return ExecResult(
                argv=argv,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                duration_ms=elapsed,
                failure=classify(proc.returncode, proc.stderr or ""),
                target="cluster",
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            from app.exec.k8s_probe import FailureClass, classify

            return ExecResult(
                argv=argv,
                returncode=-1,
                stdout="",
                stderr=f"kubectl timed out after {limit}s: {exc}",
                duration_ms=elapsed,
                failure=classify(-1, "", timed_out=True),
                timed_out=True,
                target="cluster",
            )

    # -- 基础操作 -----------------------------------------------------------

    def apply_stdin(self, manifest: str, *, timeout: int | None = None) -> ExecResult:
        """``kubectl apply -f -``，manifest 从 stdin 传入。"""
        argv = [self.kubectl_bin, "apply", "-f", "-"]
        limit = timeout if timeout is not None else self.default_timeout
        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                input=manifest,
                capture_output=True,
                text=True,
                timeout=limit,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            elapsed = int((time.monotonic() - started) * 1000)
            from app.exec.k8s_probe import classify

            return ExecResult(
                argv=argv,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                duration_ms=elapsed,
                failure=classify(proc.returncode, proc.stderr or ""),
                target="cluster",
            )
        except subprocess.TimeoutExpired:
            elapsed = int((time.monotonic() - started) * 1000)
            from app.exec.k8s_probe import classify

            return ExecResult(
                argv=argv,
                returncode=-1,
                stdout="",
                stderr=f"kubectl apply timed out after {limit}s",
                duration_ms=elapsed,
                failure=classify(-1, "", timed_out=True),
                timed_out=True,
                target="cluster",
            )

    def wait_pod_ready(
        self, pod: str, namespace: str, *, timeout: int = 180
    ) -> ExecResult:
        return self._run(
            [
                "wait",
                "--for=condition=Ready",
                f"pod/{pod}",
                "-n",
                namespace,
                f"--timeout={timeout}s",
            ],
            timeout=timeout + 20,
        )

    def get_json(self, resource: str, namespace: str | None = None) -> ExecResult:
        args = ["get", resource, "-o", "json"]
        if namespace:
            args.extend(["-n", namespace])
        return self._run(args)

    def delete(
        self, resource: str, namespace: str | None = None, *, ignore_missing: bool = True
    ) -> ExecResult:
        args = ["delete", resource]
        if namespace:
            args.extend(["-n", namespace])
        if ignore_missing:
            args.append("--ignore-not-found")
        return self._run(args)

    def current_context(self) -> ExecResult:
        return self._run(["config", "current-context"])

    def cluster_ok(self, *, timeout: int = 15) -> tuple[bool, str]:
        """集群可达性检查（供 preflight）。"""
        result = self._run(["version", "-o", "json"], timeout=timeout)
        if result.ok:
            return True, result.stdout.strip()
        return False, (result.stderr or result.stdout).strip()

    # -- 便捷解析 -----------------------------------------------------------

    def list_pod_names(self, namespace: str) -> list[str]:
        result = self.get_json("pods", namespace)
        if not result.ok:
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        return [item["metadata"]["name"] for item in payload.get("items", [])]


def pod_manifest(
    *,
    name: str,
    namespace: str,
    image: str,
    service_account: str,
    command: list[str] | None = None,
    labels: dict[str, str] | None = None,
    image_pull_policy: str = "IfNotPresent",
) -> dict:
    """生成一个常驻 Pod 的 manifest（供场景 setup 复用）。"""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels or {"app": name},
        },
        "spec": {
            "serviceAccountName": service_account,
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": name,
                    "image": image,
                    "imagePullPolicy": image_pull_policy,
                    "command": command or ["sleep", "infinity"],
                }
            ],
        },
    }
