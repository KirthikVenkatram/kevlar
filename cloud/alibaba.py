"""All Alibaba Cloud calls (DashScope, OSS) live in this file. See CLAUDE.md.

This is the deployment-proof artifact for the hackathon: keep it self-contained
and legible. OSS wiring lands in the Jul 5 deploy step; only DashScope chat
completion is implemented so far.
"""

from __future__ import annotations

import os
from typing import Any

from openai import OpenAI

DASHSCOPE_BASE_URL = os.environ.get(
    "DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"
)
DASHSCOPE_MODEL = os.environ.get("DASHSCOPE_MODEL", "qwen-max")


def _client() -> OpenAI:
    api_key = os.environ["DASHSCOPE_API_KEY"]
    return OpenAI(api_key=api_key, base_url=DASHSCOPE_BASE_URL)


def qwen_complete(
    messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
) -> Any:
    """Send a chat-completion request to Qwen via DashScope's OpenAI-compatible API.

    Returns the raw completion message object so callers can inspect both
    `content` and `tool_calls` (needed for the function-calling agent loop).
    """
    client = _client()
    kwargs: dict[str, Any] = {"model": DASHSCOPE_MODEL, "messages": messages}
    if tools:
        kwargs["tools"] = tools
    response = client.chat.completions.create(**kwargs)
    return response.choices[0].message
