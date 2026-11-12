"""镜像与工具链的集中配置（A2）。

单一变量原则（本次 A/B 实验的学术红线）
=======================================
「工具升级对比实验」只允许一个自变量：

    底层系统 / 预装工具链：alpine（busybox） → ubuntu + curl/gcc

因此**新镜像严禁包含 kubectl**。理由：
- kubectl 是一个外挂的 K8s 客户端，装上它等于给 agent 增加了一个
  全新的「能力维度」，而不是「同一能力的更好实现」；
- 一旦混入，就无法区分提升来自「多了 curl」还是「多了 kubectl」，
  A/B 结论失效；
- 参考 bench 的原始设定也是 Pod 内无 kubectl，用 HTTP 直接打 API，
  保持这一约束才能与既有数据可比。

镜像如何注入
------------
所有场景的 ``IMAGE`` 都改为调用 :func:`resolve_image`，读取顺序：
1. 环境变量 ``DSH_IMAGE``（推荐，实验脚本用这个传参）；
2. 场景模块自己的默认值（通常是 ``alpine:latest``）。

入口脚本的 ``--image`` 参数会设置 ``DSH_IMAGE`` 后重新加载场景模块，
从而让「换镜像」成为一次运行级开关，而不是需要改代码。
"""

from __future__ import annotations

import os

#: 指定镜像的环境变量名
IMAGE_ENV = "DSH_IMAGE"

#: 指定 imagePullPolicy 的环境变量名
PULL_POLICY_ENV = "DSH_IMAGE_PULL_POLICY"

#: 原始基线镜像（busybox 工具集：sh + wget，无 bash/curl/gcc/kubectl）
DEFAULT_IMAGE = "alpine:latest"

#: 定制工具链镜像（Ubuntu + curl/gcc，**不含 kubectl**）。由用户本地构建导入。
TOOLBOX_IMAGE = "dsh-toolbox:22.04"

#: 离线集群的默认拉取策略：镜像必须先 ctr import 到节点
DEFAULT_PULL_POLICY = "Never"

#: 已知镜像的 shell 声明。用于自动派生 ``KubectlTransport.shell``。
#: 键为镜像的仓库名（去掉 tag），值为 (shell, flags)。
_KNOWN_SHELLS: dict[str, tuple[str, tuple[str, ...]]] = {
    "alpine": ("sh", ()),
    "busybox": ("sh", ()),
    # Ubuntu 基础镜像的 `bash --login` 在无 TTY 的 exec 下也可用；
    # 用非 login shell 更稳（避免 /etc/profile 里意外的输出污染工具结果）
    "dsh-toolbox": ("bash", ()),
    "ubuntu": ("bash", ()),
    "debian": ("bash", ()),
}


def resolve_image(default: str = DEFAULT_IMAGE) -> str:
    """解析本次运行使用的镜像。

    Args:
        default: 场景模块自带的默认镜像。

    Returns:
        镜像引用（含 tag）。
    """
    override = (os.environ.get(IMAGE_ENV) or "").strip()
    return override or default


def resolve_pull_policy(default: str = DEFAULT_PULL_POLICY) -> str:
    """解析本次运行使用的 ``imagePullPolicy``。"""
    override = (os.environ.get(PULL_POLICY_ENV) or "").strip()
    return override or default


def _repo_of(image: str) -> str:
    """从镜像引用里取出仓库短名。

    ``docker.io/library/alpine:latest`` → ``alpine``
    ``dsh-toolbox:22.04``              → ``dsh-toolbox``
    """
    ref = image.split("@", 1)[0]
    # 去掉 registry 和 namespace，只留最后一段仓库名
    name = ref.rsplit("/", 1)[-1]
    # 去掉 tag
    return name.split(":", 1)[0]


def shell_for_image(image: str, fallback: tuple[str, tuple[str, ...]] = ("sh", ())):
    """按镜像推导容器内可用的 shell 与参数。

    历史坑（R11）：alpine 只有 ``sh``，硬编码 ``bash --login`` 会让
    每条命令都失败且错误信息误导。换镜像后同样需要自动适配，
    否则「工具升级实验」会混入一个与工具链无关的 shell 可用性差异。

    Args:
        image: 镜像引用。
        fallback: 不认识的镜像时的兜底 (shell, flags)。

    Returns:
        ``(shell, flags)``。
    """
    repo = _repo_of(image).lower()
    if repo in _KNOWN_SHELLS:
        return _KNOWN_SHELLS[repo]
    # 未知镜像：前缀匹配（如 dsh-toolbox-v2）
    for key, value in _KNOWN_SHELLS.items():
        if repo.startswith(key):
            return value
    return fallback


def describe_environment(image: str) -> dict[str, object]:
    """生成写进结果 JSON 的「运行环境指纹」。

    论文里必须能证明两组实验确实是不同镜像跑出来的，
    所以把镜像、pull 策略、shell 一起固化进结果。
    """
    shell, flags = shell_for_image(image)
    return {
        "image": image,
        "image_pull_policy": resolve_pull_policy(),
        "shell": shell,
        "shell_flags": list(flags),
        "has_kubectl": False,  # ← 学术红线：两种镜像都不含 kubectl
    }
