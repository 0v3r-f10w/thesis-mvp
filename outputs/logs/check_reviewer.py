"""检查 Reviewer 是否被触发并输出纠偏建议。"""

import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
invocations = 0
outputs = []

for line in path.read_text(encoding="utf-8").splitlines():
    r = json.loads(line)
    if r["event"] == "role_phase" and r.get("role") == "reviewer":
        invocations += 1
        print(f">>> REVIEWER TRIGGERED at turn {r['turn']} — {r['purpose']}")
    if r["event"] == "role_output" and r.get("role") == "reviewer":
        outputs.append((r["turn"], r["payload"]))

print(f"\nreviewer invocations = {invocations}\n")
for turn, payload in outputs:
    print("=" * 70)
    print(f"REVIEWER OUTPUT (turn {turn})")
    print("=" * 70)
    print(json.dumps(payload, ensure_ascii=False, indent=2)[:2000])
    print()
