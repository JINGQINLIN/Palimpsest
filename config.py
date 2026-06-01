from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

CONFIG_FILE = Path("local_config.yaml")


@dataclass(frozen=True)
class PipelineConfig:
    anthropic_api_key: str
    anthropic_base_url: str
    reconstruction_model: str
    codeql_exe: str
    llm_timeout_seconds: float = 600.0
    context: str = "dhcp_server"


def load_config(path: Path = CONFIG_FILE) -> PipelineConfig:
    if not path.is_file():
        raise RuntimeError(f"[config] {path} not found")
    try:
        data: dict = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise RuntimeError(f"[config] failed to parse {path}: {exc}") from exc

    api_key = data.get("ANTHROPIC_API_KEY")
    base_url = data.get("ANTHROPIC_BASE_URL")
    model = data.get("RECONSTRUCTION_MODEL")
    codeql_exe = data.get("CODEQL_EXE")

    missing = [
        name
        for name, value in (
            ("ANTHROPIC_API_KEY", api_key),
            ("ANTHROPIC_BASE_URL", base_url),
            ("RECONSTRUCTION_MODEL", model),
            ("CODEQL_EXE", codeql_exe),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(f"[config] missing required values: {', '.join(missing)}")

    return PipelineConfig(
        anthropic_api_key=str(api_key),
        anthropic_base_url=str(base_url),
        reconstruction_model=str(model),
        codeql_exe=str(codeql_exe),
        llm_timeout_seconds=float(data.get("LLM_TIMEOUT_SECONDS") or 600),
        context=str(data.get("CONTEXT") or "dhcp_server").strip(),
    )
