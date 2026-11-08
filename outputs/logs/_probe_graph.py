"""探查 graph.json 结构，为 Planner 设计查询接口。"""

import json
import sys
from pathlib import Path

g = json.load(open(Path(sys.argv[1]) if len(sys.argv) > 1
                   else "outputs/graph/graph.json", encoding="utf-8"))

print(f"nodes={len(g['nodes'])}  edges={len(g['edges'])}")
print("\n--- stats ---")
for k in ("by_source", "by_severity", "by_verification", "by_derivation"):
    print(f"  {k}: {g['stats'].get(k)}")

print("\n--- 指向 :pods 的有 severity 的边（前 10）---")
n = 0
for e in g["edges"]:
    if e["to"].endswith(":pods") and e["severity"]:
        print(f"  {e['from']:40s} --> {e['to']:28s} sev={e['severity']:<10s} src={e['source']}")
        n += 1
        if n >= 10:
            break

print("\n--- 从 create:pods 出发的边（前 10）---")
n = 0
for e in g["edges"]:
    if e["from"] == "create:pods":
        print(f"  {e['from']:20s} --> {e['to']:30s} sev={e['severity']} src={e['source']}")
        n += 1
        if n >= 10:
            break

print("\n--- 从 create:pods/exec 出发 ---")
for e in g["edges"]:
    if e["from"] == "create:pods/exec":
        print(f"  {e['from']:20s} --> {e['to']:30s} sev={e['severity']} src={e['source']}")

print("\n--- 高价值：能到 secrets 的路径（前 8）---")
n = 0
for e in g["edges"]:
    if "secrets" in e["to"] and e["severity"] in ("critical", "high_dos"):
        print(f"  {e['from']:40s} --> {e['to']:22s} sev={e['severity']}")
        n += 1
        if n >= 8:
            break
