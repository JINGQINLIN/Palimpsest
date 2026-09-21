from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from collections.abc import Callable
from typing import Any

import anthropic

from config import PipelineConfig

for _name in ("anthropic", "httpx", "httpcore"):
    logging.getLogger(_name).setLevel(logging.WARNING)

# Centralized token budgets for the two LLM call patterns.
DEFAULT_MAX_TOKENS = 32768
AGENT_MAX_TOKENS = 8192
DEFAULT_LLM_TIMEOUT_SECONDS = 600.0
DEFAULT_COMPLETE_MAX_TOKENS = 8192
DEFAULT_TRANSIENT_ATTEMPTS = 4
DEFAULT_TRANSIENT_BACKOFF_SECONDS = 2.0
DEFAULT_TRANSIENT_BACKOFF_CAP_SECONDS = 20.0


_TRANSIENT_LLM_ERRORS = (
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
    TimeoutError,
)


@dataclass
class TokenUsage:
    input: int          = 0
    output: int         = 0
    thinking: int       = 0   # GLM extended thinking tokens
    cache_read: int     = 0
    cache_creation: int = 0

    @property
    def total(self) -> int:
        return self.input + self.output + self.thinking + self.cache_read + self.cache_creation

    def add_anthropic(self, usage) -> None:
        if not usage:
            return
        self.input          += int(getattr(usage, "input_tokens", 0) or 0)
        self.output         += int(getattr(usage, "output_tokens", 0) or 0)
        self.thinking       += int(getattr(usage, "thinking_tokens", 0) or 0)
        self.cache_read     += int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        self.cache_creation += int(getattr(usage, "cache_creation_input_tokens", 0) or 0)

    def merge(self, other: "TokenUsage") -> None:
        self.input          += other.input
        self.output         += other.output
        self.thinking       += other.thinking
        self.cache_read     += other.cache_read
        self.cache_creation += other.cache_creation

    def format(self) -> str:
        def fmt(n: int) -> str:
            if n < 1_000:     return str(n)
            if n < 1_000_000: return f"{n / 1_000:.1f}K"
            return f"{n / 1_000_000:.2f}M"
        cache = self.cache_read + self.cache_creation
        parts = [f"in {fmt(self.input)}", f"out {fmt(self.output)}"]
        if self.thinking:
            parts.append(f"think {fmt(self.thinking)}")
        if cache:
            parts.append(f"cache {fmt(cache)}")
        parts.append(f"total {fmt(self.total)}")
        return " | ".join(parts)


class LLMClient:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        timeout: float = DEFAULT_LLM_TIMEOUT_SECONDS,
        thinking_type: str = "",
        reasoning_effort: str = "",
    ) -> None:
        self.client = anthropic.Anthropic(api_key=api_key, base_url=base_url, timeout=timeout)
        self.model = model
        # "enabled" | "disabled" | "" (omit → provider default)
        self.thinking_type = (thinking_type or "").strip().lower()
        self.reasoning_effort = (reasoning_effort or "").strip().lower()

    def _with_transient_retries(self, operation: str, fn: Callable[[], Any]) -> Any:
        """Run one provider call with short retries for transport failures only."""
        log = logging.getLogger("pipeline")
        last_error: BaseException | None = None
        for attempt in range(1, DEFAULT_TRANSIENT_ATTEMPTS + 1):
            try:
                return fn()
            except _TRANSIENT_LLM_ERRORS as exc:
                last_error = exc
                if attempt >= DEFAULT_TRANSIENT_ATTEMPTS:
                    break
                delay = min(
                    DEFAULT_TRANSIENT_BACKOFF_CAP_SECONDS,
                    DEFAULT_TRANSIENT_BACKOFF_SECONDS * (2 ** (attempt - 1)),
                )
                delay += random.uniform(0.0, min(1.0, delay * 0.25))
                log.warning(
                    "LLM %s transient error on attempt %d/%d: %s; retrying in %.1fs",
                    operation,
                    attempt,
                    DEFAULT_TRANSIENT_ATTEMPTS,
                    exc.__class__.__name__,
                    delay,
                )
                time.sleep(delay)
        assert last_error is not None
        raise last_error

    def thinking_kwargs(self, override: str | None = None) -> dict[str, Any]:
        """GLM / Anthropic-compat thinking and reasoning controls."""
        thinking_type = self.thinking_type if override is None else (override or "").strip().lower()
        if self.model.strip().lower() == "glm-5.3" and thinking_type == "disabled":
            raise ValueError("glm-5.3 requires thinking.type='enabled'")
        kwargs: dict[str, Any] = {}
        if thinking_type in ("enabled", "disabled"):
            kwargs["thinking"] = {"type": thinking_type}
        if self.reasoning_effort:
            # reasoning_effort is a Z.AI extension to the Anthropic message
            # protocol.  The Anthropic SDK exposes provider-specific body
            # fields through extra_body; passing it as a Python keyword makes
            # messages.create() reject the request before it reaches Z.AI.
            kwargs["extra_body"] = {"reasoning_effort": self.reasoning_effort}
        return kwargs

    def complete(
        self,
        prompt: str,
        max_tokens: int = DEFAULT_COMPLETE_MAX_TOKENS,
        *,
        thinking_type: str | None = None,
    ) -> tuple[str, TokenUsage]:
        msg = self._with_transient_retries(
            "complete",
            lambda: self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
                **self.thinking_kwargs(thinking_type),
            ),
        )
        text = "".join(block.text for block in msg.content if hasattr(block, "text"))
        stop_reason = getattr(msg, "stop_reason", None)
        if stop_reason != "end_turn":
            raise RuntimeError(
                f"LLM stopped before a complete answer (stop_reason={stop_reason or 'unknown'})"
            )
        if not text.strip():
            logging.getLogger("pipeline").warning(
                "LLM complete() returned empty text (prompt head: %r)", prompt[:80]
            )
        usage = TokenUsage()
        usage.add_anthropic(getattr(msg, "usage", None))
        return text, usage

    def run_agent(
        self,
        prompt: str,
        *,
        max_tokens: int = DEFAULT_COMPLETE_MAX_TOKENS,
        tools: list | None = None,
        system: list | None = None,
        max_iterations: int | None = None,
    ) -> tuple[str, TokenUsage]:
        """Send a prompt through the Claude tool_runner and collect the final text reply.

        Iterates over the tool_runner stream, accumulates token usage, and returns
        the concatenation of text blocks from the last message whose stop_reason
        is 'end_turn'. Optional ``tools`` / ``system`` / ``max_iterations`` enable
        agentic loops; when omitted the call behaves like a streaming complete().

        Returns:
            (final_text, usage).
        """
        kwargs: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "tools": tools or [],
            **self.thinking_kwargs(),
        }
        if system is not None:
            kwargs["system"] = system
        if max_iterations is not None:
            kwargs["max_iterations"] = max_iterations

        def consume_runner() -> tuple[str, Any, TokenUsage]:
            runner = self.client.beta.messages.tool_runner(**kwargs)
            final_text = ""
            last_stop = None
            usage = TokenUsage()
            for message in runner:
                usage.add_anthropic(getattr(message, "usage", None))
                last_stop = getattr(message, "stop_reason", None)
                texts = [
                    block.text.strip()
                    for block in message.content
                    if block.type == "text" and block.text.strip()
                ]
                if texts:
                    final_text = "\n".join(texts)
            return final_text, last_stop, usage

        final_text, last_stop, usage = self._with_transient_retries("run_agent", consume_runner)
        if last_stop != "end_turn":
            raise RuntimeError(
                f"LLM stopped before a complete answer (stop_reason={last_stop or 'unknown'})"
            )
        return final_text, usage


def client_from_config(config: PipelineConfig) -> LLMClient:
    return LLMClient(
        api_key=config.anthropic_api_key,
        base_url=config.anthropic_base_url,
        model=config.reconstruction_model,
        timeout=config.llm_timeout_seconds,
        thinking_type=config.thinking_type,
        reasoning_effort=config.reasoning_effort,
    )
