"""批次 1 回归测试：3 场景 × 2 模式 的 mock 冒烟测试。"""

import json
import subprocess
import sys
from pathlib import Path

CASES = [
    ("k8s_rbac_permissions", "single"),
    ("k8s_rbac_permissions", "multi"),
    ("privileged_escape", "single"),
    ("privileged_escape", "multi"),
    ("hostpath_escape", "single"),
    ("hostpath_escape", "multi"),
]

results = []
for scenario, mode in CASES:
    print("=" * 70)
    print(f"CASE: {scenario} / mode={mode}")
    print("=" * 70)
    proc = subprocess.run(
        [sys.executable, "-m", "app.run", "--scenario", scenario,
         "--llm", "mock", "--mode", mode],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    out = proc.stdout + proc.stderr

    # 从最新结果 JSON 读取
    results_dir = Path("outputs/results")
    files = sorted(results_dir.glob(f"{scenario}-*.json"),
                   key=lambda p: p.stat().st_mtime)
    if not files:
        results.append((scenario, mode, "NO_RESULT", 0, 0, "NO_TRACE"))
        print("  !! no result json")
        continue

    data = json.loads(files[-1].read_text(encoding="utf-8"))
    score = data.get("score")
    turns = data.get("turns")
    tokens = data.get("token_used")
    evidence = "HOST_FLAG" if data.get("host_flag_read_via_kubectl_exec") else "-"
    results.append((scenario, mode, score, turns, tokens, evidence))
    print(f"  score={score}  turns={turns}  tokens={tokens}  {evidence}")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"{'scenario':26s} {'mode':8s} {'score':6s} {'turns':6s} {'tokens':8s} {'flag':10s}")
print("-" * 70)
ok = True
for scenario, mode, score, turns, tokens, evidence in results:
    flag = "C" if score == "C" else "FAIL"
    if score != "C":
        ok = False
    print(f"{scenario:26s} {mode:8s} {str(score):6s} {str(turns):6s} "
          f"{str(tokens):8s} {evidence:10s}  {flag}")
print("-" * 70)
print("ALL GREEN" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
