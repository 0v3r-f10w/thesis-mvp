"""QEMU 线场景 dry-run 入口：只做 setup + healthcheck + teardown，不跑 agent。

为什么不复用 ``app/run.py``
---------------------------
``run.py`` 硬编码了 ``KubectlRunner`` 作为 setup/healthcheck 的传输层。
QEMU 场景需要 ``SshDockerRunner``。executor 的正式迁移（kubectl →
SSH + docker exec）由后续单独指令完成，本轮**不改 run.py**。

因此这里提供一个只做「场景成立性验证」的独立入口，
用途与 ``python -m app.run --dry-run`` 等价，但走 QEMU 传输层。

用法::

    python -m app.scenario.qemu_dryrun --scenario docker_sock
    python -m app.scenario.qemu_dryrun --scenario hostpath_cron --keep
    python -m app.scenario.qemu_dryrun --scenario all
"""

from __future__ import annotations

import argparse
import sys

from app.scenario.loader import _REGISTRY, list_scenarios
from app.scenario.qemu_helpers import SshDockerRunner, qemu_reachable


QEMU_SCENARIOS = [
    name
    for name, entry in _REGISTRY.items()
    if getattr(entry.factory.spec, "transport", "kubectl") == "ssh_docker"
]


def run_one(name: str, *, keep: bool) -> int:
    print("=" * 70)
    print(f"dry-run: {name}")
    print("=" * 70)

    entry = _REGISTRY.get(name)
    if entry is None:
        print(f"[error] unknown scenario {name!r}; available: {sorted(_REGISTRY)}")
        return 2

    scenario = entry.factory()
    transport = getattr(entry.factory.spec, "transport", "kubectl")

    # --- kind 线：走 kubectl + prepare_host ------------------------------
    if transport == "kubectl":
        return _run_kind(name, scenario, entry, keep=keep)

    # --- QEMU 线：走 SSH + docker ----------------------------------------
    runner = SshDockerRunner.from_env()

    ok, why = qemu_reachable(runner)
    print(f"[preflight] {'OK' if ok else 'FAIL'}: {why}")
    if not ok:
        return 3

    print(f"[setup] preparing {name} ...")
    setup = scenario.setup(runner)
    for step in setup.steps:
        mark = "ok" if step.get("ok") else "FAIL"
        print(f"  [{mark}] {step.get('step')}: {str(step.get('detail'))[:180]}")
    if not setup.ok:
        print(f"[error] setup failed: {setup.error}")
        if not keep:
            _safe_teardown(scenario, runner)
        return 4

    healthy, detail = scenario.healthcheck(runner)
    print(f"[healthcheck] {'OK' if healthy else 'FAIL'}: {detail}")

    if keep:
        print("[keep] resources left in place (--keep)")
    else:
        td = _safe_teardown(scenario, runner)
        print(f"[teardown] {'ok' if td else 'partial'}")

    return 0 if healthy else 5


def _run_kind(name: str, scenario, entry, *, keep: bool) -> int:
    """kind 线场景的 dry-run（kubectl + prepare_host）。"""
    from app.scenario.k8s_helpers import KubectlRunner
    from app.scenario.loader import needs_host_prepare, prepare_host
    from app.scenario.nodes import pick_target_node

    kubectl = KubectlRunner()
    ok, detail = kubectl.cluster_ok()
    print(f"[preflight] {'OK' if ok else 'FAIL'}: {detail[:160]}")
    if not ok:
        return 3

    # 宿主机侧准备（落 flag）
    if needs_host_prepare(name):
        try:
            target = pick_target_node(kubectl)
        except Exception as exc:  # noqa: BLE001
            print(f"[error] node selection failed: {exc}")
            return 3
        print(f"[prepare] placing flag on node={target} ...")
        prep = prepare_host(kubectl, name, node_name=target)
        for step in prep.steps:
            mark = "ok" if step.get("ok") else "FAIL"
            print(f"  [{mark}] {step.get('step')}: {str(step.get('detail'))[:160]}")
        if not prep.ok:
            print(f"[error] host prepare failed: {prep.error}")
            return 4

    print(f"[setup] applying {name} ...")
    setup = scenario.setup(kubectl)
    for step in setup.steps:
        mark = "ok" if step.get("ok") else "FAIL"
        print(f"  [{mark}] {step.get('step')}: {str(step.get('detail'))[:160]}")
    if not setup.ok:
        print(f"[error] setup failed: {setup.error}")
        if not keep:
            _safe_teardown_kind(scenario, kubectl)
        return 4

    healthy, why = scenario.healthcheck(kubectl)
    print(f"[healthcheck] {'OK' if healthy else 'FAIL'}: {why}")

    if keep:
        print("[keep] resources left in place (--keep)")
    else:
        td = _safe_teardown_kind(scenario, kubectl)
        print(f"[teardown] {'ok' if td else 'partial'}")

    return 0 if healthy else 5


def _safe_teardown_kind(scenario, kubectl) -> bool:
    try:
        td = scenario.teardown(kubectl)
        for step in td.steps:
            mark = "ok" if step.get("ok") else "FAIL"
            print(f"  [{mark}] {step.get('step')}: {str(step.get('detail'))[:140]}")
        return td.ok
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] teardown error: {exc}")
        return False


def _safe_teardown(scenario, runner) -> bool:
    try:
        td = scenario.teardown(runner)
        for step in td.steps:
            mark = "ok" if step.get("ok") else "FAIL"
            print(f"  [{mark}] {step.get('step')}: {str(step.get('detail'))[:140]}")
        return td.ok
    except Exception as exc:  # noqa: BLE001 - 清理失败不应掩盖主结论
        print(f"  [warn] teardown error: {exc}")
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.scenario.qemu_dryrun")
    parser.add_argument("--scenario", required=True, help="场景名，或 all")
    parser.add_argument(
        "--keep", action="store_true", help="结束后不清理资源（排查用）"
    )
    args = parser.parse_args(argv)

    targets = QEMU_SCENARIOS if args.scenario == "all" else [args.scenario]

    results: dict[str, int] = {}
    for name in targets:
        rc = run_one(name, keep=args.keep)
        results[name] = rc
        print()

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    all_ok = True
    for name, rc in results.items():
        status = {0: "PASS", 3: "VM UNREACHABLE", 4: "SETUP FAILED",
                  5: "HEALTHCHECK FAILED"}.get(rc, f"ERROR({rc})")
        print(f"  {name:24s} {status}")
        if rc != 0:
            all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
