"""[脚本] 3+3 统计实验：3 场景 × (3 次 single + 3 次 multi)。

严格规则
--------
1. **环境隔离**：每次运行前彻底重置（删除场景 namespace、残留 helper pod、
   ClusterRoleBinding），确保无状态残留。
2. **成本兜底**：单次运行若达到 ``--turn-cap``（默认 15）轮仍未拿到 flag，
   立即终止并记为 ``timeout``，不烧满 200K token。
3. 结果汇总为 Markdown 表格（token/turns 均值 + 成功率）。

用法::

    python outputs/logs/run_experiment.py                # 全量 3 场景 × 3+3
    python outputs/logs/run_experiment.py --reps 1       # 快速冒烟
    python outputs/logs/run_experiment.py --scenarios privileged_escape
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.scenario.loader import _REGISTRY  # noqa: E402

OUT_DIR = PROJECT_ROOT / "outputs"
RESULTS_DIR = OUT_DIR / "results"
PAPER_DATA = OUT_DIR / "paper_data" / "experiment"

#: 实验覆盖的场景（排除故意的 stuck 场景）
EXPERIMENT_SCENARIOS = (
    "k8s_rbac_permissions",
    "privileged_escape",
    "hostpath_escape",
)
MODES = ("single", "multi")


@dataclass
class RunRecord:
    """单次运行的记录。"""

    scenario: str
    mode: str
    rep: int
    score: str = "?"
    turns: int = 0
    tokens: int = 0
    bash_calls: int = 0
    termination: str = ""
    host_flag: bool = False
    timed_out: bool = False
    trace: str = ""
    result: str = ""
    error: str = ""


@dataclass
class Group:
    """同场景同模式的聚合。"""

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

    def mean(self, field_name: str) -> float:
        vals = [getattr(r, field_name) for r in self.records]
        return statistics.mean(vals) if vals else 0.0

    def median(self, field_name: str) -> float:
        vals = [getattr(r, field_name) for r in self.records]
        return statistics.median(vals) if vals else 0.0


# ---------------------------------------------------------------------------
# 环境隔离
# ---------------------------------------------------------------------------


def reset_environment(scenario: str, kubectl_bin: str = "kubectl") -> list[str]:
    """彻底清空一个场景的所有残留资源。

    删除顺序：namespace → helper pod → 场景专属 ClusterRoleBinding。
    每步都用 ``--ignore-not-found``，幂等且不因缺失而失败。
    """
    from app.scenario.base import ScenarioSpec  # noqa: F401

    entry = _REGISTRY.get(scenario)
    spec = entry.factory.spec if entry else None

    actions: list[str] = []
    cmds: list[list[str]] = []

    if spec is not None:
        cmds.append([
            kubectl_bin, "delete", "namespace", spec.namespace,
            "--ignore-not-found", "--timeout=90s",
        ])

    # 所有可能残留的集群级资源
    for crb in (
        "admin-app-binding",
        "stuck-admin-app-binding",
    ):
        cmds.append([
            kubectl_bin, "delete", "clusterrolebinding", crb,
            "--ignore-not-found",
        ])

    # 宿主机准备 helper（若上次异常中断可能残留）
    cmds.append([
        kubectl_bin, "delete", "pod", "dsh-host-prepare", "-n", "default",
        "--ignore-not-found", "--grace-period=0", "--force",
    ])

    for cmd in cmds:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=120,
            )
            actions.append(
                f"{' '.join(cmd[3:])}: rc={proc.returncode}"
            )
        except subprocess.TimeoutExpired:
            actions.append(f"{' '.join(cmd[3:])}: TIMEOUT")

    # 等待 namespace 真正消失，避免后续 apply 撞上 Terminating
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
# 单次运行
# ---------------------------------------------------------------------------


def run_once(
    scenario: str,
    mode: str,
    rep: int,
    *,
    turn_cap: int,
    token_cap: int,
) -> RunRecord:
    """执行一次实验运行。"""
    rec = RunRecord(scenario=scenario, mode=mode, rep=rep)

    # 1) 严格重置
    reset_environment(scenario)

    # 2) 跑一次
    cmd = [
        sys.executable, "-m", "app.run",
        "--scenario", scenario,
        "--llm", "openai",
        "--mode", mode,
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
        rec.error = f"exit={rc}: {output[-300:]}"
        return rec

    # 3) 读取结果 JSON
    files = sorted(
        RESULTS_DIR.glob(f"{scenario}-*.json"),
        key=lambda p: p.stat().st_mtime,
    )
    if not files:
        rec.error = "no result json"
        return rec

    latest = files[-1]
    # 必须是本次跑出来的（修改时间在 started 之后）
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

    # 触达轮数上限且未成功 → 记为 timeout
    if rec.score != "C" and rec.turns >= turn_cap:
        rec.timed_out = True
        rec.termination = rec.termination or "max_turns"
    return rec


# ---------------------------------------------------------------------------
# 汇总表格
# ---------------------------------------------------------------------------


def build_markdown(groups: dict[tuple[str, str], Group]) -> str:
    """生成 Markdown 汇总表。"""
    lines: list[str] = []

    lines.append("### 主表：场景 × 模式\n")
    lines.append(
        "| 场景 | 模式 | 样本数 | 成功率 | token 均值 | 轮数均值 | 轮数中位数 | bash 均值 |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for scenario in EXPERIMENT_SCENARIOS:
        for mode in MODES:
            g = groups.get((scenario, mode))
            if g is None or g.n == 0:
                lines.append(f"| {scenario} | {mode} | 0 | - | - | - | - | - |")
                continue
            lines.append(
                f"| {scenario} | {mode} | {g.n} | "
                f"{g.successes}/{g.n} ({g.success_rate:.0%}) | "
                f"{g.mean('tokens'):,.0f} | {g.mean('turns'):.1f} | "
                f"{g.median('turns'):.1f} | {g.mean('bash_calls'):.1f} |"
            )

    lines.append("\n### 按模式汇总（跨场景）\n")
    lines.append(
        "| 模式 | 样本数 | 成功率 | token 均值 | 轮数均值 | 节省 token |"
    )
    lines.append("|---|---|---|---|---|---|")
    overall: dict[str, Group] = {}
    for mode in MODES:
        agg = Group()
        for scenario in EXPERIMENT_SCENARIOS:
            g = groups.get((scenario, mode))
            if g:
                agg.records.extend(g.records)
        overall[mode] = agg

    base_tokens = overall["single"].mean("tokens")
    for mode in MODES:
        g = overall[mode]
        if g.n == 0:
            continue
        saved = ""
        if mode == "multi" and base_tokens > 0:
            pct = (base_tokens - g.mean("tokens")) / base_tokens * 100
            saved = f"{pct:+.1f}%"
        lines.append(
            f"| {mode} | {g.n} | {g.successes}/{g.n} ({g.success_rate:.0%}) | "
            f"{g.mean('tokens'):,.0f} | {g.mean('turns'):.1f} | {saved or '-'} |"
        )

    lines.append("\n### 明细\n")
    lines.append(
        "| 场景 | 模式 | # | score | turns | tokens | bash | termination | 宿主flag |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for scenario in EXPERIMENT_SCENARIOS:
        for mode in MODES:
            g = groups.get((scenario, mode))
            if not g:
                continue
            for r in g.records:
                lines.append(
                    f"| {r.scenario} | {r.mode} | {r.rep} | {r.score} | "
                    f"{r.turns} | {r.tokens:,} | {r.bash_calls} | "
                    f"{r.termination} | {'✔' if r.host_flag else '-'} |"
                )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_experiment")
    parser.add_argument("--reps", type=int, default=3, help="每模式重复次数")
    parser.add_argument(
        "--turn-cap", type=int, default=15, help="轮数上限（超时记为 timeout）"
    )
    parser.add_argument("--token-cap", type=int, default=200_000)
    parser.add_argument(
        "--scenarios", nargs="*", default=list(EXPERIMENT_SCENARIOS),
        help="限定场景（默认全部 3 个）",
    )
    parser.add_argument("--out", default="", help="Markdown 输出路径")
    args = parser.parse_args(argv)

    PAPER_DATA.mkdir(parents=True, exist_ok=True)
    groups: dict[tuple[str, str], Group] = {}
    all_records: list[RunRecord] = []

    total = len(args.scenarios) * len(MODES) * args.reps
    done = 0

    for scenario in args.scenarios:
        for mode in MODES:
            key = (scenario, mode)
            groups[key] = Group()
            for rep in range(1, args.reps + 1):
                done += 1
                print(f"\n[{done}/{total}] {scenario} / {mode} / rep{rep}")
                rec = run_once(
                    scenario, mode, rep,
                    turn_cap=args.turn_cap, token_cap=args.token_cap,
                )
                groups[key].records.append(rec)
                all_records.append(rec)
                status = "OK " if rec.score == "C" else "FAIL"
                extra = " (TIMEOUT)" if rec.timed_out else ""
                err = f" ERR={rec.error[:80]}" if rec.error else ""
                print(
                    f"  [{status}] score={rec.score} turns={rec.turns} "
                    f"tokens={rec.tokens}{extra}{err}"
                )

    md = build_markdown(groups)
    out_path = (
        Path(args.out) if args.out
        else PAPER_DATA / "experiment_summary.md"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")

    # 机器可读明细
    raw_path = PAPER_DATA / "experiment_records.json"
    raw_path.write_text(
        json.dumps(
            [
                {
                    "scenario": r.scenario, "mode": r.mode, "rep": r.rep,
                    "score": r.score, "turns": r.turns, "tokens": r.tokens,
                    "bash_calls": r.bash_calls, "termination": r.termination,
                    "host_flag": r.host_flag, "timed_out": r.timed_out,
                    "trace": r.trace, "error": r.error,
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
