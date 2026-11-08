"""单元测试：验证 Reviewer 触发逻辑与纠偏输出链路。

为什么用单元测试而不是再跑一次真模型
------------------------------------
实测 3 次真模型（DeepSeek）都无法自然到达 `stuck_streak >= 阈值`：
模型每轮总能从环境压出一些有效信息（capabilities、API 版本、token 长度、
SelfSubjectRulesReview 结果……），因此「连续 N 轮零进展」几乎不会发生。

这本身是个有价值的观察（**强模型很难被饿死**），但也意味着
Reviewer 这条路径无法靠自然运行触发。为确保该机制正确，
这里用**确定的脚本化场景**直接驱动循环：

- 让 MockLLM 连续发出**必然失败**的命令（403 / 不存在的文件）
- 断言：stuck_streak 达阈值 → Reviewer 被调用 → 纠偏建议进入上下文
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agent.llm import LLMResponse, ToolCall, build_tool_schemas
from app.agent.loop import RunConfig, _has_progress, run_react
from app.agent.trace import TraceWriter
from app.exec.executor import ExecResult, Executor, KubectlTransport
from app.exec.k8s_probe import FailureClass


class AlwaysFailLLM:
    """模拟「每轮都失败且无新信息」的模型，用于逼出 Reviewer。"""

    name = "always-fail"

    def __init__(self) -> None:
        self._n = 0
        self.calls: list[str] = []

    def complete(self, messages, tools, *, turn):
        self._n += 1
        # tools 为空 = Planner/Reviewer 阶段（纯推理）
        if not tools:
            self.calls.append("reasoning")
            return LLMResponse(
                text=json.dumps(
                    {
                        "diagnosis": "The pods/log permission is absent; "
                        "logs cannot be read, so created pods are unusable.",
                        "blocked_by": "environment",
                        "evidence": "HTTP 403 Forbidden on pods/*/log",
                        "revised_direction": {
                            "goal": "Abandon the logs channel",
                            "first_concrete_step": "try /api/v1/namespaces/"
                            "stuck-lab/pods?limit=1 to confirm scope",
                            "why_different": "avoids the blocked subresource",
                        },
                    }
                ),
                tool_calls=[],
                prompt_tokens=50,
                completion_tokens=50,
            )
        self.calls.append("action")
        return LLMResponse(
            text="trying something that will fail",
            tool_calls=[
                ToolCall(
                    call_id=f"c{self._n}",
                    name="bash",
                    arguments={"cmd": f"cat /nonexistent/flag-{self._n}.txt"},
                )
            ],
            prompt_tokens=50,
            completion_tokens=20,
        )


class StubExecutor:
    """总是返回「无进展」的执行器（模拟 403 / 文件不存在）。"""

    def __init__(self) -> None:
        self.count = 0

    def execute(self, transport, command, *, timeout=None):
        self.count += 1
        # 关键：rc=0 但输出是明确的失败信息 —— 正是实测中 busybox wget 的行为
        return ExecResult(
            argv=["kubectl", "exec", "p", "--", "sh", "-c", command],
            returncode=0,
            stdout="",
            stderr="cat: can't open '/nonexistent/flag.txt': No such file or directory",
            duration_ms=5,
            failure=FailureClass.SUCCESS,
            target="pod:test/p",
        )

    def execute_ok(self, *a, **k):  # pragma: no cover
        raise AssertionError("should not be called")


def test_has_progress_detects_hidden_failure():
    """rc=0 但输出含失败标记 → 判定为无进展（实测踩过的坑）。"""
    hidden_failure = {
        "returncode": 0,
        "failure_class": "success",
        "stdout": "",
        "stderr": "wget: server returned error: HTTP/1.1 403 Forbidden",
    }
    assert _has_progress(hidden_failure) is False, (
        "403 with rc=0 must count as NO progress"
    )

    real_success = {
        "returncode": 0,
        "failure_class": "success",
        "stdout": '{"kind":"PodList","items":[]}',
        "stderr": "",
    }
    assert _has_progress(real_success) is True, "real output must count as progress"

    empty = {
        "returncode": 0,
        "failure_class": "success",
        "stdout": "",
        "stderr": "",
    }
    assert _has_progress(empty) is False, "empty output must count as no progress"


def test_reviewer_triggers_on_sustained_stall(tmp_path):
    """连续无进展达阈值 → Reviewer 被调用并注入纠偏建议。"""
    llm = AlwaysFailLLM()
    stub = StubExecutor()
    trace_path = tmp_path / "stuck.jsonl"

    config = RunConfig(
        max_turns=10,
        max_tokens=100_000,
        mode="multi",
        reviewer_after_stuck_turns=2,  # 压低阈值让测试快速触发
        role_max_turns=1,
    )
    transport = KubectlTransport(pod="p", namespace="test", shell="sh", shell_flags=())

    with TraceWriter(trace_path) as trace:
        outcome = run_react(
            llm=llm,
            executor=stub,  # type: ignore[arg-type]
            transport=transport,
            trace=trace,
            config=config,
            scenario_name="unit-test-stuck",
        )

    rows = [json.loads(l) for l in trace_path.read_text(encoding="utf-8").splitlines()]

    reviewer_phases = [
        r for r in rows if r["event"] == "role_phase" and r.get("role") == "reviewer"
    ]
    reviewer_outputs = [
        r for r in rows
        if r["event"] == "role_output" and r.get("role") == "reviewer"
    ]

    assert reviewer_phases, (
        "Reviewer was never invoked — stuck detection failed.\n"
        f"llm calls: {llm.calls}\n"
        f"executor count: {stub.count}"
    )
    assert reviewer_outputs, "Reviewer ran but produced no structured output"

    payload = reviewer_outputs[0]["payload"]
    assert "diagnosis" in payload, f"missing diagnosis: {payload}"
    assert "revised_direction" in payload, f"missing revised_direction: {payload}"

    print("\n" + "=" * 66)
    print("REVIEWER TRIGGERED (unit test)")
    print("=" * 66)
    print(f"reviewer invocations : {len(reviewer_phases)}")
    print(f"executor calls       : {stub.count}")
    print("diagnosis            :", payload.get("diagnosis"))
    print("blocked_by           :", payload.get("blocked_by"))
    print("revised_direction    :", json.dumps(
        payload.get("revised_direction"), ensure_ascii=False))
    print("=" * 66)


if __name__ == "__main__":
    import tempfile

    print("TEST 1: _has_progress hidden-failure detection")
    test_has_progress_detects_hidden_failure()
    print("  PASSED")

    print("\nTEST 2: Reviewer triggers on sustained stall")
    with tempfile.TemporaryDirectory() as td:
        test_reviewer_triggers_on_sustained_stall(Path(td))
    print("  PASSED")

    print("\nALL TESTS PASSED")
