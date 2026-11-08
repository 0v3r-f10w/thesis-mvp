"""展示多智能体运行的完整轨迹（角色 + 执行）。"""

import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 320

for line in path.read_text(encoding="utf-8").splitlines():
    r = json.loads(line)
    ev = r["event"]

    if ev == "run_start":
        print("=" * 74)
        print(f"RUN START mode={r.get('mode')} llm={r.get('llm')}")
        print("=" * 74)
    elif ev == "role_phase":
        print(f"\n### T{r['turn']} [{r['role'].upper()}] {r['purpose']}")
    elif ev == "role_output":
        print(f"    -> {r['name']} produced (already shown separately)")
    elif ev == "model_message":
        text = (r.get("text") or "").strip()
        if text:
            print(f"\n[THINK] {text[:limit]}")
    elif ev == "tool_call":
        args = r.get("args") or {}
        cmd = args.get("cmd") or args.get("command") or ""
        if r["tool"] == "bash":
            print(f"  $ {cmd[:limit]}")
        else:
            print(f"  [SUBMIT] {args.get('answer', '')[:limit]}")
    elif ev == "tool_result":
        res = r.get("result") or {}
        if "returncode" not in res:
            continue
        out = (r.get("output") or "").strip().replace("\n", " | ")
        print(f"  [{res.get('returncode')}/{res.get('failure_class')}] {out[:limit]}")
    elif ev == "run_end":
        print("\n" + "=" * 74)
        for k in ("termination_reason", "turns", "token_used", "bash_calls",
                  "submit_calls", "role_turns", "mode"):
            print(f"  {k:18s} = {r.get(k)}")
        print("=" * 74)
