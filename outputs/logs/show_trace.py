"""输出 DeepSeek 运行的完整思考轨迹（人读格式）。"""

import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
max_out = int(sys.argv[2]) if len(sys.argv) > 2 else 700

for line in path.read_text(encoding="utf-8").splitlines():
    r = json.loads(line)
    ev = r["event"]

    if ev == "run_start":
        print("=" * 78)
        print(f"RUN START  llm={r.get('llm')}  scenario={r.get('scenario')}")
        print(f"           max_turns={r.get('max_turns')}  max_tokens={r.get('max_tokens')}")
        print("=" * 78)
        continue

    if ev == "turn":
        print(f"\n{'-' * 78}\nTURN {r['turn']}   (tokens so far: {r.get('tokens_so_far')})")
        continue

    if ev == "model_message":
        text = (r.get("text") or "").strip()
        calls = r.get("tool_calls") or []
        if text:
            print(f"\n[THINKING]\n{text}")
        if calls:
            print(f"\n[TOOL CALLS] {calls}")
        continue

    if ev == "tool_call":
        args = r.get("args") or {}
        cmd = args.get("cmd", "")
        if r.get("tool") == "bash":
            print(f"\n  $ {cmd[:max_out]}")
        else:
            print(f"\n  [SUBMIT] {args.get('answer', '')[:max_out]}")
        continue

    if ev == "tool_result":
        res = r.get("result") or {}
        if "returncode" not in res:
            continue
        out = (r.get("output") or "").strip().replace("\n", "\n    ")
        rc = res.get("returncode")
        cls = res.get("failure_class")
        icon = "OK " if rc == 0 else "ERR"
        print(f"  [{icon}] rc={rc} ({cls})")
        if out:
            print(f"    {out[:max_out]}")
        continue

    if ev == "health":
        if r.get("verdict") != "continue" or r.get("consecutive_failures"):
            print(f"  <health: verdict={r.get('verdict')} consec={r.get('consecutive_failures')}>")
        continue

    if ev == "run_end":
        print("\n" + "=" * 78)
        print("RUN END")
        for k in (
            "termination_reason",
            "turns",
            "token_used",
            "bash_calls",
            "submit_calls",
            "continue_prompts",
            "refusal_detected",
            "crash_onset",
        ):
            print(f"  {k:20s} = {r.get(k)}")
        print("=" * 78)
