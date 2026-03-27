"""
HTTP Agent Adapter — wraps any external agent REST API as a LangChain
BaseChatModel so the attack engine can audit it without code access.

Usage:
    from adversarial.adapters.http_agent import HTTPAgentAdapter

    adapter = HTTPAgentAdapter(
        url="https://my-agent.company.com/api/chat",
        headers={"Authorization": "Bearer sk-..."},
        payload_template={"session_id": "audit-001"},
        message_field="message",
        response_field="response",
    )
    attack = ConstraintBypassAttack(adapter, judge, constitution)

Probe before attacking:
    ok, info = await adapter.probe()
    if not ok:
        print(info)
"""

from __future__ import annotations

from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)

import asyncio
from typing import Any

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult


class HTTPAgentAdapter(BaseChatModel):
    """
    Adapts any HTTP/REST agent endpoint to the LangChain BaseChatModel interface.

    The adapter sends the last HumanMessage content to the configured URL and
    extracts the response using a dot-path field selector.
    """

    url:              str
    headers:          dict[str, str] = {}
    payload_template: dict[str, Any] = {}
    message_field:    str = "message"
    response_field:   str = "response"
    timeout:          float = 30.0
    max_retries:      int = 2

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "http_agent_adapter"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return asyncio.get_event_loop().run_until_complete(
            self._agenerate(messages, stop, **kwargs)
        )

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        user_text = next(
            (m.content for m in reversed(messages) if m.type == "human"),
            str(messages[-1].content) if messages else "",
        )

        payload = {**self.payload_template, self.message_field: user_text}

        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(
                        self.url,
                        json=payload,
                        headers=self.headers,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    text = self._extract(data, self.response_field)
                    msg  = AIMessage(content=text)
                    return ChatResult(generations=[ChatGeneration(message=msg)])
            except Exception as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)

        error_text = f"[HTTP_AGENT_ERROR after {self.max_retries + 1} attempts: {last_exc}]"
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=error_text))])

    @staticmethod
    def _extract(data: Any, field_path: str) -> str:
        """Dot-path extractor: 'choices.0.message.content' style."""
        parts = field_path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part, "")
            elif isinstance(current, list) and part.isdigit():
                current = current[int(part)]
            else:
                return str(current)
        return str(current) if current is not None else ""

    async def probe(self) -> tuple[bool, str]:
        """
        Connectivity check before running the full attack campaign.
        Returns (reachable, info_message).
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                payload = {**self.payload_template, self.message_field: "ping"}
                resp = await client.post(self.url, json=payload, headers=self.headers)
                if resp.status_code < 500:
                    return True, f"Agent reachable — HTTP {resp.status_code}"
                return False, f"Agent returned HTTP {resp.status_code}"
        except httpx.ConnectError:
            return False, f"Cannot connect to {self.url}"
        except httpx.TimeoutException:
            return False, f"Timeout connecting to {self.url}"
        except Exception as exc:
            return False, f"Probe failed: {exc}"