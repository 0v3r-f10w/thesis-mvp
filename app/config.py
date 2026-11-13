"""集中配置：路径与常量。

约束（见 PLAN.md）：
- 参考代码目录**只读**，此处硬编码绝对路径，绝不写入。
- 所有**输出**落到 OUTPUTS_DIR 及其子目录。
- Windows 中文路径一律经 pathlib 处理，不在 shell 里裸拼。
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# 根目录
# ---------------------------------------------------------------------------

#: 毕设代码根目录（唯一可写目录）
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

#: .env 文件路径（用户在此配置 DEEPSEEK_API_KEY 等）
ENV_FILE: Path = PROJECT_ROOT / ".env"

#: 所有产物输出根目录
OUTPUTS_DIR: Path = PROJECT_ROOT / "outputs"

#: 图产物目录（graph.json / actions.json）
OUTPUTS_GRAPH_DIR: Path = OUTPUTS_DIR / "graph"

#: JSONL 轨迹目录
OUTPUTS_TRACES_DIR: Path = OUTPUTS_DIR / "traces"

#: 结果 JSON 目录
OUTPUTS_RESULTS_DIR: Path = OUTPUTS_DIR / "results"

#: 日志目录
OUTPUTS_LOGS_DIR: Path = OUTPUTS_DIR / "logs"


# ---------------------------------------------------------------------------
# 参考代码根目录（只读！）—— 绝对路径硬编码（决策 R1）
# ---------------------------------------------------------------------------

#: 工作区根目录（三个参考仓库的父目录）
WORKSPACE_ROOT: Path = PROJECT_ROOT.parent

IMPLICIT_PERMISSION_ROOT: Path = WORKSPACE_ROOT / "ImplicitPermission-main"
SANDBOX_ESCAPE_BENCH_ROOT: Path = WORKSPACE_ROOT / "sandbox_escape_bench-main"
SERVERLESS_TOOLS_ROOT: Path = WORKSPACE_ROOT / "Serverless-tools-main"


# ---------------------------------------------------------------------------
# 第二优先级输入：ImplicitPermission 数据文件（v1.30.10 根目录数据）
# ---------------------------------------------------------------------------

#: 数据类型根（v1.30.10，仓库根目录下即为此版本）
IMPLICIT_COMBINED_DIR: Path = (
    IMPLICIT_PERMISSION_ROOT / "Combined_LLM&Static_permission_analysis"
)

#: 显式权限转换表 —— 116 行「资源 [Verb ...]」五段式
SOURCE_EXPLICIT_PERMISSIONS: Path = (
    IMPLICIT_PERMISSION_ROOT / "Explicit_Permission_Analysis" / "results" / "result.txt"
)

#: 隐式权限全量参考 —— 593 行「verb resource --> verb resource」
SOURCE_PERMISSION_REFERENCE: Path = IMPLICIT_COMBINED_DIR / "permission-reference.txt"

#: 动态验证过的触发参考 —— 328 行，**权威起点**
SOURCE_TRIGGER: Path = IMPLICIT_COMBINED_DIR / "assessment" / "trigger.txt"

#: 分级表 —— 「# Critical / # high DOS / # medium / # low」四段
SOURCE_CLASSIFICATION: Path = IMPLICIT_COMBINED_DIR / "assessment" / "classification.txt"

#: 本批次使用的全部输入文件（供启动时存在性校验）
REQUIRED_INPUT_FILES: tuple[Path, ...] = (
    SOURCE_EXPLICIT_PERMISSIONS,
    SOURCE_PERMISSION_REFERENCE,
    SOURCE_TRIGGER,
    SOURCE_CLASSIFICATION,
)


# ---------------------------------------------------------------------------
# 输出文件名
# ---------------------------------------------------------------------------

GRAPH_JSON_NAME: str = "graph.json"
ACTIONS_JSON_NAME: str = "actions.json"


# ---------------------------------------------------------------------------
# Schema 版本
# ---------------------------------------------------------------------------

SCHEMA_VERSION: str = "1.0"

#: 数据来源标注的 Kubernetes 版本（ImplicitPermission 仓库根目录数据 = v1.30.10）
KUBERNETES_SOURCE_VERSION: str = "v1.30.10"


# ---------------------------------------------------------------------------
# 传递闭包参数（复刻 multiRef + 权限交集约束）
# ---------------------------------------------------------------------------

#: 闭包最大跳数。原版 deriveMappings 为单跳（1 hop）；此处上限设为 2 防组合爆炸。
CLOSURE_MAX_DEPTH: int = 2

#: 是否要求中转权限必须存在于显式权限表（权限交集约束）
CLOSURE_REQUIRE_VERB_INTERSECTION: bool = True


# ---------------------------------------------------------------------------
# 成本硬上限（批次 2/3 使用，此处先集中定义）
# ---------------------------------------------------------------------------

MAX_TURNS_DEFAULT: int = 20
MAX_TOKENS_DEFAULT: int = 200_000


# ---------------------------------------------------------------------------
# QEMU 线 SSH 连接参数（executor 与 qemu_helpers 共用，避免两处重复）
# ---------------------------------------------------------------------------

#: SSH 端口（QEMU 端口转发 2222 → VM 22）
QEMU_SSH_PORT: int = 2222
#: SSH 用户名
QEMU_SSH_USER: str = "ubuntu"
#: SSH 主机
QEMU_SSH_HOST: str = "127.0.0.1"


def qemu_ssh_key_path() -> str:
    """QEMU VM 的 SSH 私钥路径（``DSH_QEMU_KEY`` 优先，否则 ``~/.ssh/qemu_vm``）。"""
    override = os.environ.get("DSH_QEMU_KEY")
    if override:
        return override
    return str(Path.home() / ".ssh" / "qemu_vm")


def qemu_ssh_port() -> int:
    """解析 QEMU SSH 端口（``DSH_QEMU_PORT`` 可覆盖）。"""
    raw = os.environ.get("DSH_QEMU_PORT")
    try:
        return int(raw) if raw else QEMU_SSH_PORT
    except (TypeError, ValueError):
        return QEMU_SSH_PORT


def qemu_ssh_user() -> str:
    return os.environ.get("DSH_QEMU_USER") or QEMU_SSH_USER


def qemu_ssh_host() -> str:
    return os.environ.get("DSH_QEMU_HOST") or QEMU_SSH_HOST


#: ``ssh`` / ``sftp`` 的公共安全选项。
#: 这些是**共享基础设施**，必须两端一致：
#: - ``-F /dev/null``：本机 ~/.ssh/config 会干扰连接（实测直接 Connection refused）
#: - ``StrictHostKeyChecking=no`` + ``UserKnownHostsFile=/dev/null``：QEMU VM 会重建
#: - ``LogLevel=ERROR``：抑制 ``Permanently added ...`` 噪音污染工具输出
#: - ``BatchMode=yes``：禁止交互式提示挂死
SSH_COMMON_OPTS: tuple[str, ...] = (
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "-F", "/dev/null",
)


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def ensure_output_dirs() -> None:
    """创建所有输出目录（幂等）。"""
    for directory in (
        OUTPUTS_GRAPH_DIR,
        OUTPUTS_TRACES_DIR,
        OUTPUTS_RESULTS_DIR,
        OUTPUTS_LOGS_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def load_env_file(path: Path | None = None) -> list[str]:
    """从 .env 加载环境变量（不覆盖已存在的真实环境变量）。

    极简解析，只支持 ``KEY=VALUE`` 与 ``#`` 注释，
    足够本项目用，不引入 python-dotenv 依赖。

    Args:
        path: .env 路径；默认 PROJECT_ROOT/.env。

    Returns:
        实际写入的键名列表（不含值，便于日志安全打印）。
    """
    env_path = path or ENV_FILE
    if not env_path.is_file():
        return []

    applied: list[str] = []
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        # 去掉成对的引号
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if not key:
            continue
        # 真实环境变量优先，不覆盖
        if key in os.environ and os.environ[key]:
            continue
        os.environ[key] = value
        applied.append(key)
    return applied


def check_required_inputs() -> list[str]:
    """校验输入文件存在性。

    Returns:
        缺失文件的说明列表；为空表示全部就绪。
    """
    missing: list[str] = []
    for path in REQUIRED_INPUT_FILES:
        if not path.is_file():
            missing.append(str(path))
    return missing
