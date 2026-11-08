"""临时调试脚本：查看 JSONL 轨迹内容。"""

import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
for line in path.read_text(encoding="utf-8").splitlines():
    r = json.loads(line)
    ev = r["event"]
    if ev == "tool_result":
        res = r["result"]
        out = (r.get("output") or "").replace("\n", " | ")
        if "returncode" not in res:
            print(f"[{r['turn']}] {r['tool']} (no execution) out={out[:300]}")
            continue
        print(f"[{r['turn']}] {r['tool']} rc={res['returncode']} "
              f"cls={res['failure_class']}")
        print(f"    out: {out[:500]}")
    elif ev == "tool_call":
        print(f"[{r['turn']}] CALL {r['tool']}: {str(r['args'])[:250]}")
    elif ev == "model_message":
        print(f"[{r['turn']}] MODEL: {str(r.get('text'))[:150]}")
    elif ev == "continue_prompt":
        print(f"[{r['turn']}] CONTINUE_PROMPT")
    elif ev == "health":
        print(f"[{r['turn']}] HEALTH verdict={r.get('verdict')} "
              f"consec={r.get('consecutive_failures')}")
    elif ev in ("run_start", "run_end"):
        payload = {k: v for k, v in r.items() if k not in ("seq", "ts")}
        print(f"--- {ev}: {str(payload)[:400]}")
