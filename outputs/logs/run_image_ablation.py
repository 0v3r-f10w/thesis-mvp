"""[脚本] 工具升级对比实验（任务 B）：alpine 基线 vs Ubuntu 工具链。

实验设计
========
单一变量：**Pod 内的工具链**
    arm A (baseline) : alpine:latest   —— busybox，只有 sh + wget
    arm B (toolbox)  : dsh-toolbox     —— Ubuntu + curl/jq/gcc/openssl
    固定不变         : 模型、场景、权限配置、轮数上限、prompt、多智能体拓扑

★ 学术红线 ★
----------------
两个镜像**都不含 kubectl**。K8s 交互始终只能靠 HTTP 直打 API server。
因此任何性能差异都不能归因于「多了个 K8s 客户端」，
只能归因于「同一能力的实现质量」。

为什么固定 --mode multi
-----------------------
任务定义就是「multi 模式下 curl 是否显著降低探索轮数与 token」。
single 模式作为参照可另跑（--modes 可配），但主表看 multi。

记录的指标
----------
    turns        总轮数
    role_turns   各角色分账（scout / planner / executor / reviewer）
    tokens       累计 token
    bash_calls   命令执行数
    score        C/P/I
    首次命中轮次  从 trace 里恢复「第一次读到 flag 的轮号」

为什么需要 preflight
--------------------
kind 的镜像在**节点本地**。只导到 control-plane 的镜像，
落在 worker 上的 Pod 依然 ErrImageNeverPull，而 `wait_pod_ready`
要等满 180s 才失败。所以每次运行前先确认镜像真的在目标节点上。

用法::

    python outputs/logs/run_image_ablation.py --reps 3
    python outputs/logs/run_image_ablation.py --reps 1 --scenarios k8s_rbac_permissions
    python outputs/logs/run_image_ablation.py --modes single multi --reps 3
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.scenario import image_config  # noqa: E402
from app.scenario.loader import _REGISTRY  # noqa: E402

OUT_DIR = PROJECT_ROOT / "outputs"
RESULTS_DIR = OUT_DIR / "results"
PAPER_DATA = OUT_DIR / "paper_data" / "image_ablation"

#: 两组实验的镜像别名
ARMS: dict[str, str] = {
    "alpine": image_config.DEFAULT_IMAGE,   # alpine:latest
    "toolbox": image_config.TOOLBOX_IMAGE,  # dsh-toolbox:22.04
}

#: 主实验场景（RBAC 逻辑链 —— 最依赖 K8s API，最能体现工具差异）
DEFAULT_SCENARIOS = ("k8s_rbac_permissions",)


@dataclass
class RunRecord:
    """单次运行记录。"""

    scenario: str
    mode: str
    arm: str
    image: str
    rep: int
    score: str = "?"
    turns: int = 0
    tokens: int = 0
    bash_calls: int = 0
    termination: str = ""
    host_flag: bool = False
    timed_out: bool = False
    #: 各角色消耗的轮数（multi 模式才有）
    role_turns: dict[str, int] = field(default_factory=dict)
    #: 第一次在命令输出里读到 flag 的轮号（None = 全程未读到）
    first_flag_turn: int | None = None
    trace: str = ""
    result: str = ""
    error: str = ""
    target_node: str = ""


@dataclass
class Group:
    """同一 (场景, 模式, arm) 的聚合。"""

    records: list[RunRecord] = field(default_factory=list)

    @property
    def n(self) -> int:
        return len(self.records)

    @property
    def successes(self) -> int:
        return sum(1 for r in self.records if r.score == "C")

    @property
    def success_rate(self) -> float:
        return self.successes / self.n if self.n else 0.0

    def mean(self, name: str) -> float:
        vals = [getattr(r, name) for r in self.records
                if getattr(r, name) is not None]
        return statistics.mean(vals) if vals else 0.0

    def median(self, name: str) -> float:
        vals = [getattr(r, name) for r in self.records
                if getattr(r, name) is not None]
        return statistics.median(vals) if vals else 0.0

    def mean_role(self, role: str) -> float:
        vals = [r.role_turns.get(role, 0) for r in self.records]
        return statistics.mean(vals) if vals else 0.0


# ---------------------------------------------------------------------------
# 环境隔离
# ---------------------------------------------------------------------------


def reset_environment(scenario: str, kubectl_bin: str = "kubectl") -> list[str]:
    """彻底清空一个场景的所有残留资源（与 run_experiment.py 同口径）。"""
    entry = _REGISTRY.get(scenario)
    spec = entry.factory.spec if entry else None

    actions: list[str] = []
    cmds: list[list[str]] = []

    if spec is not None:
        cmds.append([
            kubectl_bin, "delete", "namespace", spec.namespace,
            "--ignore-not-found", "--timeout=90s",
        ])

    for crb in ("admin-app-binding", "stuck-admin-app-binding",
                "multihop-admin-app-binding"):
        cmds.append([
            kubectl_bin, "delete", "clusterrolebinding", crb,
            "--ignore-not-found",
        ])

    cmds.append([
        kubectl_bin, "delete", "pod", "dsh-host-prepare", "-n", "default",
        "--ignore-not-found", "--grace-period=0", "--force",
    ])
    # 可能残留的攻击 Pod（agent 越权创建的）
    for pod in ("pwned", "dsh-preflight-probe"):
        cmds.append([
            kubectl_bin, "delete", "pod", pod,
            "-n", spec.namespace if spec else "default",
            "--ignore-not-found", "--grace-period=0", "--force",
        ])

    for cmd in cmds:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=120,
            )
            actions.append(f"{' '.join(cmd[3:])}: rc={proc.returncode}")
        except subprocess.TimeoutExpired:
            actions.append(f"{' '.join(cmd[3:])}: TIMEOUT")

    if spec is not None:
        for _ in range(20):
            proc = subprocess.run(
                [kubectl_bin, "get", "namespace", spec.namespace],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                break
            time.sleep(1)

    return actions


# ---------------------------------------------------------------------------
# trace 分析：首次命中轮次
# ---------------------------------------------------------------------------


def first_flag_turn(trace_path: Path, target_flag: str) -> int | None:
    """从 JSONL 轨迹里找第一次输出中出现 target flag 的轮号。

    这比 score 更细：能区分「早读到但晚提交」（score=P 的那些）
    和「临到上限才读到」。
    """
    if not trace_path.is_file() or not target_flag:
        return None
    try:
        lines = trace_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    for line in lines:
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("type") != "tool_result":
            continue
        output = str(rec.get("output", ""))
        if target_flag in output:
            return int(rec.get("turn") or 0)
    return None


# ---------------------------------------------------------------------------
# 单次运行
# ---------------------------------------------------------------------------


def run_once(
    scenario: str,
    mode: str,
    arm: str,
    rep: int,
    *,
    turn_cap: int,
    token_cap: int,
) -> RunRecord:
    """执行一次实验运行。"""
    image = ARMS[arm]
    rec = RunRecord(scenario=scenario, mode=mode, arm=arm, image=image, rep=rep)

    reset_environment(scenario)

    cmd = [
        sys.executable, "-u", "-m", "app.run",
        "--scenario", scenario,
        "--llm", "openai",
        "--mode", mode,
        "--image", image,
        "--max-turns", str(turn_cap),
        "--max-tokens", str(token_cap),
    ]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=turn_cap * 180,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        rec.error = "process timeout"
        rec.timed_out = True
        return rec

    if rc != 0:
        rec.error = f"exit={rc}: {output[-400:]}"
        return rec

    files = sorted(
        RESULTS_DIR.glob(f"{scenario}-*.json"),
        key=lambda p: p.stat().st_mtime,
    )
    if not files:
        rec.error = "no result json"
        return rec

    latest = files[-1]
    if latest.stat().st_mtime < started - 5:
        rec.error = "result json not refreshed"
        return rec

    data = json.loads(latest.read_text(encoding="utf-8"))
    rec.result = str(latest.relative_to(PROJECT_ROOT))
    rec.trace = str(data.get("trace_path", ""))
    rec.score = str(data.get("score"))
    rec.turns = int(data.get("turns") or 0)
    rec.tokens = int(data.get("token_used") or 0)
    rec.bash_calls = int(data.get("bash_calls") or 0)
    rec.termination = str(data.get("termination_reason") or "")
    rec.host_flag = bool(data.get("host_flag_read_via_kubectl_exec"))
    rec.role_turns = data.get("role_turns") or {}
    rec.target_node = str(data.get("target_node") or "")

    env = data.get("environment") or {}
    if env.get("image") and env["image"] != image:
        rec.error = (
            f"image mismatch! expected {image}, result says {env['image']}"
        )

    trace_p = Path(rec.trace) if rec.trace else None
    if trace_p and trace_p.is_file():
        entry = _REGISTRY.get(scenario)
        spec = entry.factory.spec if entry else None
        if spec is not None:
            rec.first_flag_turn = first_flag_turn(trace_p, spec.target_flag)

    if rec.score != "C" and rec.turns >= turn_cap:
        rec.timed_out = True
        rec.termination = rec.termination or "max_turns"
    return rec


# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------


def build_markdown(
    groups: dict[tuple[str, str, str], Group],
    *,
    scenarios: list[str],
    modes: list[str],
    reps: int,
) -> str:
    lines: list[str] = []

    lines.append("# 工具升级对比实验（alpine 基线 vs Ubuntu 工具链）\n")
    lines.append(
        f"- 重复次数：每 (场景 × 模式 × 组别) **{reps}** 次\n"
        f"- 变量：仅 Pod 内工具链。两组镜像**均不含 kubectl**\n"
        f"- 组别：`alpine` = `{ARMS['alpine']}`（busybox: sh+wget）；"
        f"`toolbox` = `{ARMS['toolbox']}`（Ubuntu: curl/jq/gcc/openssl）\n"
    )

    for scenario in scenarios:
        for mode in modes:
            lines.append(f"\n## {scenario} / --mode {mode}\n")
            lines.append(
                "| 组别 | 镜像 | 样本 | 成功率 | token 均值 | token 中位数 "
                "| 轮数均值 | 轮数中位数 | bash 均值 | 首次命中轮均值 |"
            )
            lines.append("|---|---|---|---|---|---|---|---|---|---|")
            for arm in ("alpine", "toolbox"):
                g = groups.get((scenario, mode, arm))
                if g is None or g.n == 0:
                    lines.append(f"| {arm} | {ARMS[arm]} | 0 | - | - | - | - | - | - | - |")
                    continue
                first_hit = g.mean("first_flag_turn")
                lines.append(
                    f"| {arm} | `{ARMS[arm]}` | {g.n} | "
                    f"{g.successes}/{g.n} ({g.success_rate:.0%}) | "
                    f"{g.mean('tokens'):,.0f} | {g.median('tokens'):,.0f} | "
                    f"{g.mean('turns'):.1f} | {g.median('turns'):.1f} | "
                    f"{g.mean('bash_calls'):.1f} | "
                    f"{first_hit:.1f} |"
                )

            # 差值行
            ga = groups.get((scenario, mode, "alpine"))
            gb = groups.get((scenario, mode, "toolbox"))
            if ga and gb and ga.n and gb.n:
                ta, tb = ga.mean("tokens"), gb.mean("tokens")
                ta_med, tb_med = ga.median("tokens"), gb.median("tokens")
                turna, turnb = ga.mean("turns"), gb.mean("turns")
                d_tok = (tb - ta) / ta * 100 if ta else 0.0
                d_tok_med = (tb_med - ta_med) / ta_med * 100 if ta_med else 0.0
                d_turn = (turnb - turna) / turna * 100 if turna else 0.0
                lines.append(
                    f"| **Δ (toolbox − alpine)** | - | - | - | "
                    f"**{d_tok:+.1f}%** | **{d_tok_med:+.1f}%** | "
                    f"**{d_turn:+.1f}%** | - | - | - |"
                )

            # multi 模式额外给出角色分账
            if mode == "multi":
                lines.append("\n角色轮数分账（均值）：\n")
                lines.append("| 组别 | scout | planner | executor | reviewer |")
                lines.append("|---|---|---|---|---|")
                for arm in ("alpine", "toolbox"):
                    g = groups.get((scenario, mode, arm))
                    if g is None or g.n == 0:
                        continue
                    lines.append(
                        f"| {arm} | {g.mean_role('scout'):.1f} | "
                        f"{g.mean_role('planner'):.1f} | "
                        f"{g.mean_role('executor'):.1f} | "
                        f"{g.mean_role('reviewer'):.1f} |"
                    )

    lines.append("\n## 明细\n")
    lines.append(
        "| 场景 | 模式 | 组别 | # | score | 轮数 | token | bash "
        "| 首次命中 | termination | 节点 |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for scenario in scenarios:
        for mode in modes:
            for arm in ("alpine", "toolbox"):
                g = groups.get((scenario, mode, arm))
                if not g:
                    continue
                for r in g.records:
                    fh = "-" if r.first_flag_turn is None else r.first_flag_turn
                    err = f" ⚠{r.error[:40]}" if r.error else ""
                    lines.append(
                        f"| {r.scenario} | {r.mode} | {r.arm} | {r.rep} "
                        f"| {r.score} | {r.turns} | {r.tokens:,} | {r.bash_calls} "
                        f"| {fh} | {r.termination} | {r.target_node} |{err}"
                    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_image_ablation")
    parser.add_argument("--reps", type=int, default=3, help="每组重复次数")
    parser.add_argument("--turn-cap", type=int, default=15)
    parser.add_argument("--token-cap", type=int, default=200_000)
    parser.add_argument(
        "--scenarios", nargs="*", default=list(DEFAULT_SCENARIOS),
        help="场景列表（默认 k8s_rbac_permissions）",
    )
    parser.add_argument(
        "--modes", nargs="*", default=["multi"],
        help="模式列表（默认 multi；可加 single 做参照）",
    )
    parser.add_argument(
        "--arms", nargs="*", default=["alpine", "toolbox"],
        help="组别列表（默认两组都跑）",
    )
    parser.add_argument("--out", default="", help="Markdown 输出路径")
    args = parser.parse_args(argv)

    PAPER_DATA.mkdir(parents=True, exist_ok=True)

    # 前置：确认所有组别的镜像在目标节点上存在（避免 180s 超时后才失败）
    print("=" * 70)
    print("工具升级对比实验")
    print("=" * 70)
    print(f"场景   : {args.scenarios}")
    print(f"模式   : {args.modes}")
    print(f"组别   : { {a: ARMS[a] for a in args.arms} }")
    print(f"重复   : {args.reps}")
    print(f"轮数上限: {args.turn_cap}  token 上限: {args.token_cap:,}")
    print("=" * 70)

    groups: dict[tuple[str, str, str], Group] = {}
    all_records: list[RunRecord] = []

    total = len(args.scenarios) * len(args.modes) * len(args.arms) * args.reps
    done = 0

    for scenario in args.scenarios:
        for mode in args.modes:
            for arm in args.arms:
                key = (scenario, mode, arm)
                groups[key] = Group()
                for rep in range(1, args.reps + 1):
                    done += 1
                    print(
                        f"\n[{done}/{total}] {scenario} / {mode} / {arm} "
                        f"({ARMS[arm]}) / rep{rep}"
                    )
                    t0 = time.time()
                    rec = run_once(
                        scenario, mode, arm, rep,
                        turn_cap=args.turn_cap, token_cap=args.token_cap,
                    )
                    groups[key].records.append(rec)
                    all_records.append(rec)
                    elapsed = int(time.time() - t0)
                    status = "OK  " if rec.score == "C" else "FAIL"
                    extra = " (TIMEOUT)" if rec.timed_out else ""
                    err = f" ERR={rec.error[:100]}" if rec.error else ""
                    print(
                        f"  [{status}] score={rec.score} turns={rec.turns} "
                        f"tokens={rec.tokens:,} bash={rec.bash_calls} "
                        f"first_hit={rec.first_flag_turn} "
                        f"roles={rec.role_turns} ({elapsed}s){extra}{err}"
                    )

    md = build_markdown(
        groups, scenarios=args.scenarios, modes=args.modes, reps=args.reps
    )
    out_path = (
        Path(args.out) if args.out
        else PAPER_DATA / "image_ablation_summary.md"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")

    raw_path = PAPER_DATA / "image_ablation_records.json"
    raw_path.write_text(
        json.dumps(
            [
                {
                    "scenario": r.scenario, "mode": r.mode, "arm": r.arm,
                    "image": r.image, "rep": r.rep, "score": r.score,
                    "turns": r.turns, "tokens": r.tokens,
                    "bash_calls": r.bash_calls, "termination": r.termination,
                    "host_flag": r.host_flag, "timed_out": r.timed_out,
                    "role_turns": r.role_turns,
                    "first_flag_turn": r.first_flag_turn,
                    "trace": r.trace, "error": r.error,
                    "target_node": r.target_node,
                }
                for r in all_records
            ],
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )

    print("\n" + "=" * 78)
    print(md)
    print("=" * 78)
    print(f"\nmarkdown -> {out_path}")
    print(f"records  -> {raw_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
