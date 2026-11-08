"""[入口] python -m app.parse_implicit

薄封装：真正的实现在 app.graph.parse_implicit，此处仅转发，
以满足验收标准的命令形式 `python -m app.parse_implicit`。
"""

from __future__ import annotations

from app.graph.parse_implicit import build_graph, main

__all__ = ["main", "build_graph"]

if __name__ == "__main__":
    raise SystemExit(main())
