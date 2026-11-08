"""K8s 执行失败分类：区分「控制面连通性失败」与「Pod 内 CLI 失败」。

这是对 SandboxEscapeBench ``health.py::classify_execution_failure`` 的关键改造。
原版只有一个 runtime 维度，且其 docstring 自认存在误报风险：

    NB: can false-positive if the agent runs docker/kubectl *inside* the
    container (e.g. docker_socket, k8s_rbac_permissions) and those fail with
    the same daemon/API errors for enough consecutive turns.

在 k8s_rbac_permissions 场景下这个风险是**必然触发**的：agent 会反复在 Pod 内
用 wget 打 API server，遇到 403 Forbidden 是正常的探索失败，绝不能被当成
「沙箱已死」。因此这里把判据分成三层，只有前两层计入 health。

层级
----
L0 控制面不可达   ``Unable to connect to the server:`` / ``connection to the
                  server ... was refused`` / 认证失效
L1 控制面超时     ``dial tcp ... i/o timeout`` / ``TLS handshake timeout`` /
                  ``context deadline exceeded``
L2 目标已消失     ``pods "x" not found`` / ``cannot exec into a container in a
                  completed pod`` / ``container not found``
L3 Pod 内 CLI 失败 其余一切非零返回（命令不存在、权限不足、API 403、curl 报错…）

只有 L0/L1/L2 为真失效；L3 一律视为「agent 在正常探索」。
"""

from __future__ import annotations

import re
from enum import Enum


class FailureClass(str, Enum):
    """一次执行结果的分类。"""

    #: 成功（returncode == 0）
    SUCCESS = "success"
    #: L0：控制面不可达 —— 真失效
    CONTROL_PLANE_UNREACHABLE = "control_plane_unreachable"
    #: L1：控制面超时 —— 真失效
    CONTROL_PLANE_TIMEOUT = "control_plane_timeout"
    #: L2：目标 Pod/容器已不存在 —— 真失效
    TARGET_GONE = "target_gone"
    #: L3：Pod 内命令自身失败 —— **不算**环境失效
    POD_CLI_ERROR = "pod_cli_error"
    #: 模型给出的工具参数缺字段/为空 —— 既不执行也不计入 health
    TOOL_ARGUMENT_ERROR = "tool_argument_error"
    #: 执行器层面超时（subprocess timeout）—— 单独标记，不直接计入 health
    EXEC_TIMEOUT = "exec_timeout"

    @property
    def is_environment_failure(self) -> bool:
        """是否属于「环境已死」——只有这些才进入 health 计数。"""
        return self in (
            FailureClass.CONTROL_PLANE_UNREACHABLE,
            FailureClass.CONTROL_PLANE_TIMEOUT,
            FailureClass.TARGET_GONE,
        )


# ---------------------------------------------------------------------------
# 锚定正则
# ---------------------------------------------------------------------------
# 全部使用 ^ 锚定（配合 re.MULTILINE），避免匹配到 agent 命令输出里
# 偶然包含的相似文本。这是保守判据：宁可漏判，不可误判。

_CONTROL_PLANE_UNREACHABLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^Unable to connect to the server:", re.MULTILINE),
    re.compile(r"^The connection to the server .+ was refused", re.MULTILINE),
    re.compile(r"^error: You must be logged in to the server", re.MULTILINE),
    re.compile(
        r"^(?:Error from server \(Unauthorized\): )?Unauthorized$", re.MULTILINE
    ),
    re.compile(r"^error: exec plugin: invalid apiVersion", re.MULTILINE),
    re.compile(r"^E\d{4} .*Unable to connect to the server:", re.MULTILINE),
)

_CONTROL_PLANE_TIMEOUT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^dial tcp .*: i/o timeout", re.MULTILINE),
    re.compile(r"^net/http: TLS handshake timeout", re.MULTILINE),
    re.compile(r"^context deadline exceeded", re.MULTILINE),
    re.compile(r"^error: timed out waiting for the condition", re.MULTILINE),
)

_TARGET_GONE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r'^Error from server \(NotFound\): pods "[^"]+" not found', re.MULTILINE),
    re.compile(
        r"^error: unable to upgrade connection: (?:container not found|pod does not exist)",
        re.MULTILINE,
    ),
    re.compile(
        r"^error: cannot exec into a container in a completed pod;", re.MULTILINE
    ),
    re.compile(r'^Error from server \(NotFound\): container "[^"]+" not found', re.MULTILINE),
)


def classify(returncode: int, stderr: str, *, timed_out: bool = False) -> FailureClass:
    """把一次执行结果分类。

    Args:
        returncode: 进程返回码（超时场景传 -1 或任意非零）。
        stderr: 标准错误输出。
        timed_out: 是否由执行器 timeout 触发。

    Returns:
        FailureClass。
    """
    if timed_out:
        return FailureClass.EXEC_TIMEOUT

    if returncode == 0:
        return FailureClass.SUCCESS

    text = stderr or ""

    for pattern in _CONTROL_PLANE_UNREACHABLE_PATTERNS:
        if pattern.search(text):
            return FailureClass.CONTROL_PLANE_UNREACHABLE

    for pattern in _CONTROL_PLANE_TIMEOUT_PATTERNS:
        if pattern.search(text):
            return FailureClass.CONTROL_PLANE_TIMEOUT

    for pattern in _TARGET_GONE_PATTERNS:
        if pattern.search(text):
            return FailureClass.TARGET_GONE

    # 其余任何非零返回：都是 Pod 内命令自己的问题，环境仍然活着
    return FailureClass.POD_CLI_ERROR


def describe(failure: FailureClass) -> str:
    """给人类阅读的一句话说明（写进 JSONL 轨迹）。"""
    return {
        FailureClass.SUCCESS: "command succeeded",
        FailureClass.CONTROL_PLANE_UNREACHABLE: (
            "kubectl cannot reach the API server (control plane down)"
        ),
        FailureClass.CONTROL_PLANE_TIMEOUT: (
            "kubectl timed out talking to the API server (control plane unresponsive)"
        ),
        FailureClass.TARGET_GONE: (
            "target pod/container no longer exists (scenario torn down)"
        ),
        FailureClass.POD_CLI_ERROR: (
            "command failed inside the pod; this is normal exploration, "
            "NOT an environment failure"
        ),
        FailureClass.EXEC_TIMEOUT: "command exceeded the executor timeout",
    }[failure]
