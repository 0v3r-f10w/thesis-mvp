"""多节点 + 镜像升级 的端到端自检（A4 前置检查）。

为什么需要这个脚本
==================
集群迁到 1 control-plane + 1 worker 后，「镜像是否在**目标节点**上存在」
成为一个新的失败点：kind 的 containerd 镜像是 **节点本地**的，
只导到 control-plane 的镜像，落在 worker 上的 Pod 依然 ErrImageNeverPull。

而 `wait_pod_ready` 会一直等到超时（180s），表现为「跑一次要三分钟然后失败」，
很难看出根因。本脚本把每个检查点拆开，快速给出「到底缺什么」。

检查项
------
1. preflight：kubectl 可达、context 正确
2. 节点清单 + 目标节点选择结果（含污点）
3. **每个节点**上目标镜像是否存在（containerd 命名空间 k8s.io）
4. alpine 基线镜像是否存在（多数场景依赖它，helper Pod 也用它）
5. 可选：起一个临时 Pod 验证真的能被 kubelet 用起来

用法::

    python outputs/logs/preflight_check.py
    python outputs/logs/preflight_check.py --image dsh-toolbox:22.04
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.scenario import image_config, nodes  # noqa: E402
from app.scenario.k8s_helpers import KubectlRunner  # noqa: E402

CHECK = "[ok]  "
WARN = "[warn]"
FAIL = "[FAIL]"


def _docker_exec_node(node: str, inner: list[str]) -> tuple[int, str]:
    """在 kind 节点容器里执行命令（kind 节点无 docker daemon，用 ctr）。"""
    argv = ["docker", "exec", node, *inner]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return -1, "docker CLI not found in PATH"
    except subprocess.TimeoutExpired:
        return -1, "docker exec timed out"


def node_images(node: str) -> tuple[bool, list[str]]:
    """列出某节点 containerd(k8s.io) 里的镜像。返回 (可查询, 镜像列表)。"""
    rc, out = _docker_exec_node(
        node, ["ctr", "-n", "k8s.io", "images", "ls", "-q"]
    )
    if rc != 0:
        return False, [out.strip()[:200]]
    return True, [line.strip() for line in out.splitlines() if line.strip()]


def image_present(images: list[str], wanted: str) -> bool:
    """判断镜像是否存在于节点（宽松匹配 tag）。"""
    repo_tag = wanted
    want_name = wanted.split(":", 1)[0]
    want_tag = wanted.split(":", 1)[1] if ":" in wanted else "latest"
    for img in images:
        if img == repo_tag:
            return True
        # 形如 docker.io/library/alpine:latest
        name_part, _, tag_part = img.rpartition(":")
        if not name_part:
            name_part, tag_part = img, "latest"
        if name_part.rsplit("/", 1)[-1] == want_name and tag_part == want_tag:
            return True
    return False


def probe_pod(kubectl: KubectlRunner, image: str, node: str | None) -> tuple[bool, str]:
    """起一个临时 Pod，验证镜像真的能被 kubelet 用起来。"""
    name = "dsh-preflight-probe"
    ns = "default"
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": ns},
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "probe",
                    "image": image,
                    "imagePullPolicy": image_config.resolve_pull_policy(),
                    "command": ["sh", "-c", "echo PROBE_OK; sleep 5"],
                }
            ],
        },
    }
    if node:
        manifest["spec"]["nodeSelector"] = {"kubernetes.io/hostname": node}

    kubectl.delete(f"pod/{name}", ns, ignore_missing=True)
    applied = kubectl.apply_stdin(json.dumps(manifest, indent=2))
    if not applied.ok:
        return False, f"apply failed: {applied.stderr.strip()[:200]}"

    deadline = time.time() + 90
    last = ""
    while time.time() < deadline:
        res = kubectl.get_json(f"pods/{name}", ns)
        if res.ok:
            pod = json.loads(res.stdout)
            phase = pod.get("status", {}).get("phase", "?")
            reasons = [
                cs.get("state", {}).get("waiting", {}).get("reason", "")
                for cs in pod.get("status", {}).get("containerStatuses", []) or []
            ]
            last = f"phase={phase} waiting={[r for r in reasons if r]}"
            if phase in ("Succeeded", "Running"):
                kubectl.delete(f"pod/{name}", ns, ignore_missing=True)
                return True, last
            if phase == "Failed":
                kubectl.delete(f"pod/{name}", ns, ignore_missing=True)
                return False, last
        time.sleep(2)

    kubectl.delete(f"pod/{name}", ns, ignore_missing=True)
    return False, f"not ready within 90s ({last})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="preflight_check")
    parser.add_argument(
        "--image", default="", help="待验证的实验镜像（默认读 DSH_IMAGE）"
    )
    parser.add_argument(
        "--probe", action="store_true", help="额外起临时 Pod 真实验证"
    )
    args = parser.parse_args(argv)

    target_image = args.image or image_config.resolve_image()
    kubectl = KubectlRunner()
    problems: list[str] = []

    print("=" * 70)
    print("多节点 + 镜像 前置检查")
    print("=" * 70)

    # 1) preflight
    print("\n[1] 集群连通性")
    ok, detail = kubectl.cluster_ok()
    if not ok:
        print(f"  {FAIL} kubectl 不可达: {detail[:300]}")
        return 3
    ctx = (kubectl.current_context().stdout or "").strip()
    print(f"  {CHECK} context={ctx}")

    # 2) 节点
    print("\n[2] 节点与选择")
    try:
        node_list = nodes.list_nodes(kubectl)
    except Exception as exc:  # noqa: BLE001
        print(f"  {FAIL} 无法列出节点: {exc}")
        return 3
    for n in node_list:
        flags = []
        if n.is_control_plane:
            flags.append("control-plane")
        if n.has_no_schedule_taint:
            flags.append("NoSchedule-taint")
        print(
            f"  {'ready' if n.ready else 'NOT-READY':9s} {n.name}"
            f"  {','.join(flags) or '-'}"
        )
    try:
        target = nodes.pick_target_node(kubectl)
    except Exception as exc:  # noqa: BLE001
        print(f"  {FAIL} 节点选择失败: {exc}")
        return 3
    print(f"  {CHECK} 目标节点: {nodes.describe_pin(target)}")

    # 3) 各节点镜像
    print("\n[3] 各节点 containerd 镜像")
    unverifiable: list[str] = []
    image_report: dict[str, dict[str, bool]] = {}
    for n in node_list:
        queryable, images = node_images(n.name)
        if not queryable:
            print(f"  {WARN} {n.name}: CANNOT QUERY ({images[0][:120]})")
            print("         (no docker permission in this session — verify in your own terminal)")
            unverifiable.append(n.name)
            continue
        has_exp = image_present(images, target_image)
        has_base = image_present(images, image_config.DEFAULT_IMAGE)
        image_report[n.name] = {"experiment": has_exp, "baseline": has_base}
        mark_exp = CHECK if has_exp else FAIL
        mark_base = CHECK if has_base else FAIL
        print(f"  {mark_exp} {n.name}: experiment {target_image} "
              f"{'PRESENT' if has_exp else 'MISSING'}")
        print(f"  {mark_base} {n.name}: baseline   {image_config.DEFAULT_IMAGE} "
              f"{'PRESENT' if has_base else 'MISSING'}")
        if not has_exp:
            problems.append(f"{n.name}: missing experiment image {target_image}")
        if not has_base:
            problems.append(f"{n.name}: missing baseline image {image_config.DEFAULT_IMAGE}")

    # 4) 真实启动探测
    if args.probe:
        print("\n[4] 真实 Pod 启动探测")
        pod_node = target or (node_list[0].name if node_list else None)
        ok, why = probe_pod(kubectl, target_image, pod_node)
        print(f"  {CHECK if ok else FAIL} {target_image} -> {why}")
        if not ok:
            problems.append(f"实验镜像无法启动: {why}")

    # 汇总
    print("\n" + "=" * 70)
    if problems:
        print("BLOCKING PROBLEMS:")
        for p in problems:
            print(f"  - {p}")
        print("\nFix (run in a terminal WITH docker permission):")
        print("  .\\scripts\\import-baseline.ps1     # import alpine baseline")
        print("  .\\scripts\\import-image.ps1        # build + import dsh-toolbox")
        return 1

    if unverifiable:
        print("INCONCLUSIVE — image state could not be verified on:")
        for name in unverifiable:
            print(f"  - {name}")
        print(
            "\nThis session has no docker permission, so node-local containerd\n"
            "images cannot be listed. Node pinning itself is OK.\n"
            "Verify the images in your own terminal with:\n"
            "  docker exec desktop-worker ctr -n k8s.io images ls -q | Select-String alpine\n"
            "  docker exec desktop-worker ctr -n k8s.io images ls -q | Select-String dsh-toolbox"
        )
        return 2

    print("ALL CHECKS PASSED — ready to run experiments.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
