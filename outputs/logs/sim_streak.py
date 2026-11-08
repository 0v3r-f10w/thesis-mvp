"""模拟 stuck_streak 判定逻辑，找出为何不触发。"""

import json
import sys
from pathlib import Path

sys.path.insert(0, ".")
from app.agent.loop import _is_ineffective  # noqa: E402

path = Path(sys.argv[1])
rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]

# 按轮聚合 tool_result
by_turn: dict[int, list[dict]] = {}
for r in rows:
    if r["event"] != "tool_result":
        continue
    res = r.get("result") or {}
    if "returncode" not in res:
        continue
    by_turn.setdefault(r["turn"], []).append(
        {
            "returncode": res.get("returncode"),
            "failure_class": res.get("failure_class"),
            "stdout": r.get("output") or "",
            "stderr": "",
        }
    )

streak = 0
print(f"{'turn':6s} {'n':3s} {'all_ineffective':16s} {'streak':7s}")
print("-" * 45)
for turn in sorted(by_turn):
    cmds = by_turn[turn]
    ineffective = [_is_ineffective(c) for c in cmds]
    all_bad = all(ineffective)
    streak = streak + 1 if all_bad else 0
    print(f"{turn:<6} {len(cmds):<3} {str(all_bad):<16} {streak:<7} "
          f"{ineffective}")

print(f"\nmax streak = {streak}")
