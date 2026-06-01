from __future__ import annotations

import logging
from dataclasses import dataclass

import anthropic

for _name in ("anthropic", "httpx", "httpcore"):
    logging.getLogger(_name).setLevel(logging.WARNING)


@dataclass
class TokenUsage:
    input: int          = 0
    output: int         = 0
    cache_read: int     = 0
    cache_creation: int = 0

    @property
    def total(self) -> int:
        return self.input + self.output + self.cache_read + self.cache_creation

    def add_anthropic(self, usage) -> None:
        if not usage:
            return
        self.input          += int(getattr(usage, "input_tokens", 0) or 0)
        self.output         += int(getattr(usage, "output_tokens", 0) or 0)
        self.cache_read     += int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        self.cache_creation += int(getattr(usage, "cache_creation_input_tokens", 0) or 0)

    def merge(self, other: "TokenUsage") -> None:
        self.input          += other.input
        self.output         += other.output
        self.cache_read     += other.cache_read
        self.cache_creation += other.cache_creation

    def format(self) -> str:
        def fmt(n: int) -> str:
            if n < 1_000:     return str(n)
            if n < 1_000_000: return f"{n / 1_000:.1f}K"
            return f"{n / 1_000_000:.2f}M"
        cache = self.cache_read + self.cache_creation
        return (
            f"in {fmt(self.input)} | out {fmt(self.output)} "
            f"| cache {fmt(cache)} | total {fmt(self.total)}"
        )


class LLMClient:
    def __init__(self, api_key: str, base_url: str, model: str,
                 timeout: float = 600.0) -> None:
        self.client = anthropic.Anthropic(api_key=api_key, base_url=base_url, timeout=timeout)
        self.model = model

    def complete(self, prompt: str, max_tokens: int = 8192) -> tuple[str, TokenUsage]:
        msg = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in msg.content if hasattr(block, "text"))
        usage = TokenUsage()
        usage.add_anthropic(getattr(msg, "usage", None))
        return text, usage
