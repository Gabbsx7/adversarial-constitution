"""
LangGraph and CrewAI Adapters — wrap existing agent graphs and crews
as LangChain BaseChatModel so the attack engine can audit them directly.

Usage (LangGraph):
    from adversarial.adapters.langgraph import LangGraphAdapter

    graph   = builder.compile()
    adapter = LangGraphAdapter(graph, input_key="messages", output_key="messages")
    attack  = ConstraintBypassAttack(adapter, judge, constitution)

Usage (CrewAI):
    from adversarial.adapters.crewai import CrewAIAdapter

    crew    = Crew(agents=[...], tasks=[...])
    adapter = CrewAIAdapter(crew, input_variable="customer_request")
    attack  = ConstraintBypassAttack(adapter, judge, constitution)
"""

from __future__ import annotations

import asyncio
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult


# ---------------------------------------------------------------------------
# LangGraph Adapter
# ---------------------------------------------------------------------------

class LangGraphAdapter(BaseChatModel):
    """
    Wraps a compiled LangGraph (StateGraph) as a BaseChatModel.

    The adapter invokes the graph with the last HumanMessage and extracts
    the final AI response from the graph state.

    Args:
        graph:      A compiled LangGraph (result of builder.compile()).
        input_key:  State key used to pass messages into the graph.
        output_key: State key from which to extract the response.
                    If the value is a list of messages, the last AIMessage
                    content is returned.
        config:     Optional LangGraph config dict (thread_id, etc.).
    """

    graph:      Any
    input_key:  str = "messages"
    output_key: str = "messages"
    config:     dict[str, Any] = {}

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "langgraph_adapter"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return asyncio.get_event_loop().run_until_complete(
            self._agenerate(messages, stop, **kwargs)
        )

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        user_text = next(
            (m.content for m in reversed(messages) if m.type == "human"),
            str(messages[-1].content) if messages else "",
        )

        graph_input = {self.input_key: [HumanMessage(content=user_text)]}

        try:
            if hasattr(self.graph, "ainvoke"):
                state = await self.graph.ainvoke(graph_input, config=self.config)
            else:
                state = self.graph.invoke(graph_input, config=self.config)

            response_text = self._extract_response(state)
        except Exception as exc:
            response_text = f"[LANGGRAPH_ERROR: {exc}]"

        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content=response_text))]
        )

    def _extract_response(self, state: Any) -> str:
        value = state.get(self.output_key, "") if isinstance(state, dict) else state

        if isinstance(value, list):
            for msg in reversed(value):
                if hasattr(msg, "content") and getattr(msg, "type", "") in ("ai", "assistant"):
                    return str(msg.content)
                if hasattr(msg, "content"):
                    return str(msg.content)
            return str(value[-1]) if value else ""

        if isinstance(value, str):
            return value

        if hasattr(value, "content"):
            return str(value.content)

        return str(value)


# ---------------------------------------------------------------------------
# CrewAI Adapter
# ---------------------------------------------------------------------------

class CrewAIAdapter(BaseChatModel):
    """
    Wraps a CrewAI Crew as a BaseChatModel.

    The adapter calls crew.kickoff() with the last HumanMessage injected
    as the value of `input_variable`.

    Args:
        crew:           A CrewAI Crew instance.
        input_variable: The input variable name the crew expects (default: "input").
        extra_inputs:   Additional inputs to pass alongside the user message.
    """

    crew:           Any
    input_variable: str = "input"
    extra_inputs:   dict[str, Any] = {}

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "crewai_adapter"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return asyncio.get_event_loop().run_until_complete(
            self._agenerate(messages, stop, **kwargs)
        )

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        user_text = next(
            (m.content for m in reversed(messages) if m.type == "human"),
            str(messages[-1].content) if messages else "",
        )

        inputs = {**self.extra_inputs, self.input_variable: user_text}

        try:
            if hasattr(self.crew, "kickoff_async"):
                result = await self.crew.kickoff_async(inputs=inputs)
            else:
                loop   = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    None, lambda: self.crew.kickoff(inputs=inputs)
                )

            response_text = (
                result.raw
                if hasattr(result, "raw")
                else str(result)
            )
        except Exception as exc:
            response_text = f"[CREWAI_ERROR: {exc}]"

        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content=response_text))]
        )


# ---------------------------------------------------------------------------
# AutoGen Adapter (basic)
# ---------------------------------------------------------------------------

class AutoGenAdapter(BaseChatModel):
    """
    Wraps an AutoGen ConversableAgent as a BaseChatModel.

    Sends a single message and returns the last reply.

    Args:
        agent:          An AutoGen ConversableAgent or AssistantAgent.
        initiator_name: Name of the human proxy sending the message.
    """

    agent:          Any
    initiator_name: str = "adversarial_tester"

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "autogen_adapter"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return asyncio.get_event_loop().run_until_complete(
            self._agenerate(messages, stop, **kwargs)
        )

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        user_text = next(
            (m.content for m in reversed(messages) if m.type == "human"),
            str(messages[-1].content) if messages else "",
        )

        try:
            loop = asyncio.get_running_loop()
            chat_result = await loop.run_in_executor(
                None,
                lambda: self.agent.initiate_chat(
                    self.agent,
                    message=user_text,
                    max_turns=1,
                    silent=True,
                ),
            )
            history  = chat_result.chat_history if hasattr(chat_result, "chat_history") else []
            response = history[-1].get("content", "") if history else str(chat_result)
        except Exception as exc:
            response = f"[AUTOGEN_ERROR: {exc}]"

        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content=response))]
        )