"""诊断 stuck_streak 为何未触发。"""

import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]

print(f"{'turn':6s} {'tool':8s} {'rc':5s} {'class':24s} out_head")
print("-" * 90)
for r in rows:
    if r["event"] != "tool_result":
        continue
    res = r.get("result") or {}
    if "returncode" not in res:
        continue
    out = (r.get("output") or "").strip().replace("\n", " ")[:60]
    print(f"{r['turn']:<6} {r['tool']:<8} {res.get('returncode'):<5} "
          f"{str(res.get('failure_class')):<24} {out}")

print("\n--- 每轮是否有成功 ---")
turn_ok = {}
for r in rows:
    if r["event"] != "tool_result":
        continue
    res = r.get("result") or {}
    if "returncode" not in res:
        continue
    ok = res.get("returncode") == 0
    turn_ok[r["turn"]] = turn_ok.get(r["turn"], False) or ok

for turn in sorted(turn_ok):
    print(f"  T{turn}: {'SUCCESS' if turn_ok[turn] else 'ALL-FAILED'}")
