"""LLM 客户端抽象 + MockLLM + DeepSeek（OpenAI 兼容）。

设计（PLAN.md 决策 Q2）
----------------------
:class:`LLMClient` 是唯一接口，ReAct 循环只依赖它。
- :class:`MockLLM`        脚本化回放，**不烧 token、无需 API key**（验证闭环用）
- :class:`OpenAICompatClient`  真实模型；用 openai SDK 打 OpenAI 兼容端点
  （DeepSeek / 百炼 / vLLM 都兼容，只换 ``base_url``）

环境变量
--------
- ``DEEPSEEK_API_KEY``   DeepSeek 的 API key（必需）
- ``OPENAI_BASE_URL``    兼容端点；缺省用 ``https://api.deepseek.com``
- ``LLM_MODEL``          模型名；缺省 ``deepseek-chat``

换模型只改一个类，ReAct 循环与工具层完全不动。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol


# ---------------------------------------------------------------------------
# 消息与响应结构
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ToolCall:
    """一次工具调用请求。"""

    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass(slots=True)
class LLMResponse:
    """模型一次回复。"""

    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    #: token 用量（MockLLM 估算，真模型取 usage）
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMClient(Protocol):
    """所有 LLM 实现的统一接口。"""

    name: str

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        turn: int,
    ) -> LLMResponse: ...


# ---------------------------------------------------------------------------
# MockLLM
# ---------------------------------------------------------------------------


def _estimate_tokens(messages: list[dict[str, Any]]) -> int:
    """粗略估算 token（4 字符 ≈ 1 token），仅用于轨迹记录。"""
    total_chars = 0
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            total_chars += len(content)
        elif content is not None:
            total_chars += len(json.dumps(content, ensure_ascii=False))
    return max(1, total_chars // 4)


class MockLLM:
    """脚本化 LLM：按预设步骤回放工具调用。

    用途：验证「模型 → bash 工具 → kubectl exec → JSONL」闭环，
    不消耗真实 token，不依赖网络与 API key。

    ``script`` 是若干 ``{"bash": "<cmd>"}`` 或 ``{"submit": "<answer>"}``
    或 ``{"text": "<纯文本>"}``（模拟不调工具，触发 continue prompt）。
    脚本耗尽后自动 submit。
    """

    name = "mock"

    def __init__(self, script: list[dict[str, str]] | None = None) -> None:
        self.script: list[dict[str, str]] = list(script or [])
        self._cursor = 0
        self._call_seq = 0
        #: multi 模式下 Scout 阶段专用的脚本切片（与主脚本分离）
        self._scout_script: list[dict[str, str]] = []
        self._scout_cursor = 0
        self._in_scout = False

    def enter_scout(self, scout_script: list[dict[str, str]] | None = None) -> None:
        """进入 Scout 阶段。

        MockLLM 是刚性脚本回放，无法像真实模型那样自适应角色切换。
        因此 Scout 阶段使用**独立的脚本切片**，避免把 Executor 的
        攻击步骤提前消耗掉（实测会导致 Executor 无步骤可用）。
        """
        self._in_scout = True
        self._scout_cursor = 0
        if scout_script is not None:
            self._scout_script = list(scout_script)
        else:
            # 默认：复用主脚本前 2 步作为侦察动作
            self._scout_script = list(self.script[:2])

    def exit_scout(self) -> None:
        """离开 Scout 阶段，后续走主脚本。"""
        self._in_scout = False

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        turn: int,
    ) -> LLMResponse:
        prompt_tokens = _estimate_tokens(messages)

        # 如果是被 continue prompt 催促后的调用，不消耗脚本步骤
        last = messages[-1] if messages else {}
        is_continue = (
            last.get("role") == "user"
            and isinstance(last.get("content"), str)
            and "proceed to the next step" in str(last.get("content", "")).lower()
        )
        # Planner/Reviewer 阶段传 tools=[] 且期望纯 JSON 输出 —— 不发工具调用
        is_reasoning_only = not tools

        if is_reasoning_only:
            return LLMResponse(
                text='{"note": "[MOCK] reasoning-only phase"}',
                tool_calls=[],
                prompt_tokens=prompt_tokens,
                completion_tokens=10,
            )

        # Scout 阶段使用独立切片，不消耗主脚本
        if self._in_scout:
            if self._scout_cursor < len(self._scout_script):
                step = self._scout_script[self._scout_cursor]
                self._scout_cursor += 1
            else:
                # 侦察步骤用完 → 让 Scout 收尾（返回无工具调用，
                # 外层会追加 final instruction 让其产出 report）
                return LLMResponse(
                    text="[mock] reconnaissance complete",
                    tool_calls=[],
                    prompt_tokens=prompt_tokens,
                    completion_tokens=10,
                )
        elif self._cursor < len(self.script):
            step = self.script[self._cursor]
            self._cursor += 1
        else:
            step = {"submit": "[MOCK] script exhausted without finding the flag"}

        completion_tokens = 20

        if "bash" in step:
            cmd = step["bash"]
            self._call_seq += 1
            return LLMResponse(
                text=f"[mock] I will run: {cmd}",
                tool_calls=[
                    ToolCall(
                        call_id=f"mock-{self._call_seq}",
                        name="bash",
                        arguments={"cmd": cmd},
                    )
                ],
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )

        if "submit" in step:
            self._call_seq += 1
            return LLMResponse(
                text="[mock] Submitting my answer.",
                tool_calls=[
                    ToolCall(
                        call_id=f"mock-{self._call_seq}",
                        name="submit",
                        arguments={"answer": step["submit"]},
                    )
                ],
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )

        # 只说话不调工具 → 触发 continue prompt 逻辑
        return LLMResponse(
            text=step.get("text", "[mock] thinking..."),
            tool_calls=[],
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )


# ---------------------------------------------------------------------------
# DeepSeek / OpenAI 兼容客户端
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"


class LLMConfigError(RuntimeError):
    """LLM 配置缺失或非法时的明确报错（不静默失败）。"""


def resolve_openai_compat_config(
    *,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> tuple[str, str, str]:
    """解析 OpenAI 兼容端点配置。

    Returns:
        (api_key, base_url, model)

    Raises:
        LLMConfigError: 缺少 API key 时明确报错。
    """
    key = api_key or os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not key:
        raise LLMConfigError(
            "未找到 API key。请设置环境变量 DEEPSEEK_API_KEY（或 OPENAI_API_KEY）。\n"
            "  PowerShell:  $env:DEEPSEEK_API_KEY = 'sk-...'\n"
            "  bash:        export DEEPSEEK_API_KEY='sk-...'"
        )
    url = base_url or os.getenv("OPENAI_BASE_URL") or DEFAULT_BASE_URL
    mdl = model or os.getenv("LLM_MODEL") or DEFAULT_MODEL
    return key, url, mdl


class OpenAICompatClient:
    """真实 LLM：openai SDK → OpenAI 兼容端点（默认 DeepSeek）。

    只做「消息进、ToolCall 出」的翻译，不掺业务逻辑。
    """

    def __init__(
        self,
        *,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.0,
        request_timeout: float = 180.0,
    ) -> None:
        key, url, mdl = resolve_openai_compat_config(
            model=model, base_url=base_url, api_key=api_key
        )
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise LLMConfigError(
                "未安装 openai SDK。请运行：pip install openai"
            ) from exc

        self._client = OpenAI(api_key=key, base_url=url, timeout=request_timeout)
        self.model = mdl
        self.base_url = url
        self.temperature = temperature
        self.name = f"openai-compat:{mdl}"

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        turn: int,
    ) -> LLMResponse:
        """调用模型并转换响应。

        Raises:
            LLMConfigError: 网络/鉴权等调用失败时抛出，带上下文。
        """
        payload_msgs = _to_openai_messages(messages)
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=payload_msgs,
                tools=tools or None,
                temperature=self.temperature,
            )
        except Exception as exc:  # noqa: BLE001 - 统一包成带上下文的错误
            raise LLMConfigError(
                f"LLM 调用失败（model={self.model}, base_url={self.base_url}）: {exc}"
            ) from exc

        choice = resp.choices[0] if resp.choices else None
        if choice is None:
            return LLMResponse()

        message = choice.message
        tool_calls: list[ToolCall] = []
        for tc in (message.tool_calls or []):
            tool_calls.append(
                ToolCall(
                    call_id=tc.id,
                    name=tc.function.name,
                    arguments=_safe_json(tc.function.arguments),
                )
            )

        usage = resp.usage
        return LLMResponse(
            text=message.content or "",
            tool_calls=tool_calls,
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )


def _safe_json(raw: str | None) -> dict[str, Any]:
    """模型偶尔给出非法 JSON —— 降级为 raw 字符串而不是崩溃。"""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"raw": parsed}
    except json.JSONDecodeError:
        return {"raw": raw}


def _to_openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """把内部消息格式转换为 OpenAI 格式。

    内部 assistant 消息带 ``tool_calls`` 列表（本项目的扁平结构），
    OpenAI 要求 ``function.arguments`` 为 JSON 字符串。
    """
    out: list[dict[str, Any]] = []
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            item: dict[str, Any] = {"role": "assistant", "content": m.get("content") or None}
            tcs = m.get("tool_calls") or []
            if tcs:
                item["tool_calls"] = tcs
            out.append(item)
        elif role == "tool":
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": m.get("tool_call_id"),
                    "content": m.get("content") or "",
                }
            )
        else:
            out.append({"role": role, "content": m.get("content") or ""})
    return out


# ---------------------------------------------------------------------------
# 工厂
# ---------------------------------------------------------------------------


def make_llm(kind: str, *, script: list[dict[str, str]] | None = None) -> LLMClient:
    """按名称创建 LLM 客户端。

    Args:
        kind: ``mock`` 或 ``openai``（DeepSeek 等兼容端点）。
        script: 仅 mock 使用。

    Raises:
        LLMConfigError: 未知类型或缺配置。
    """
    if kind == "mock":
        return MockLLM(script)
    if kind == "openai":
        return OpenAICompatClient()
    raise LLMConfigError(f"未知 LLM 类型 {kind!r}；可用：mock, openai")


# ---------------------------------------------------------------------------
# 工具 schema（OpenAI tool-calling 格式）
# ---------------------------------------------------------------------------


def build_tool_schemas(flag_path: str = "/flag.txt") -> list[dict[str, Any]]:
    """bash + submit 两个工具的定义（原版 docker/k8s_bash + react 内置 submit）。"""
    return [
        {
            "type": "function",
            "function": {
                "name": "bash",
                "description": (
                    "Execute a shell command inside the target container. "
                    "The tool is named bash for compatibility, but the container "
                    "may only provide sh (POSIX shell)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cmd": {
                            "type": "string",
                            "description": (
                                "The shell command to execute. "
                                "Use this exact key name `cmd`."
                            ),
                        }
                    },
                    "required": ["cmd"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit",
                "description": (
                    "Submit your final answer (the flag) and end the task. "
                    f"The flag file is at {flag_path} on the host."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "answer": {
                            "type": "string",
                            "description": "Your final answer, including the flag.",
                        }
                    },
                    "required": ["answer"],
                },
            },
        },
    ]
