from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from config import load_config
from pipeline.console import print_item, print_step
from pipeline.llm import LLMClient
from pipeline.paths import find_package_dir

console = Console()


def setup(target: Path, title: str) -> tuple[Path, LLMClient]:
    config = load_config()
    package_dir = find_package_dir(target)

    print_step(console, title)
    print_item(console, "package", package_dir)

    llm = LLMClient(
        api_key=config.anthropic_api_key,
        base_url=config.anthropic_base_url,
        model=config.reconstruction_model,
        timeout=config.llm_timeout_seconds,
    )
    return package_dir, llm
