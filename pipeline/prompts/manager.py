from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_DEFAULT_DIR = Path(__file__).parent


class PromptManager:
    def __init__(self, base_path: str | Path = _DEFAULT_DIR) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(base_path)),
            autoescape=False,
        )

    def load(self, name: str, **kwargs) -> str:
        return self.env.get_template(name).render(**kwargs)
