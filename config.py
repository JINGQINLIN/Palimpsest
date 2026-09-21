from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

CONFIG_FILE = Path("local_config.yaml")


@dataclass(frozen=True)
class AblationConfig:
    """Feature / stage toggles for controlled ablation experiments.

    All flags default to False (= feature ON, stage NOT skipped).
    Set a flag to True to disable that feature / skip that stage.
    """

    # Stage toggles — True = skip this stage
    skip_structure: bool = False       # skip LLM structure pass
    skip_naming: bool = False          # skip LLM naming pass
    skip_agent_review: bool = False    # skip cross-function agent review
    skip_codeql_build: bool = False   # skip final CodeQL database creation

    # Feature toggles — True = disable this feature / enable new feature
    disable_domain_context: bool = True   # disable RAG domain context injection
    enable_prescan: bool = False          # enable Pre-Scan agent before review
    enable_multi_agent: bool = False       # enable multi-agent concurrent review
    reconstruction_workers: int = 1         # parallel workers per topo layer (1=sequential)
    disable_pcode: bool = False           # disable P-Code in structure prompt
    disable_access_evidence: bool = False  # disable deterministic cross-function access evidence

    @property
    def all_stages(self) -> bool:
        """True if no stage is being skipped."""
        return not (self.skip_structure or self.skip_naming or
                    self.skip_agent_review or self.skip_codeql_build)

    @property
    def active(self) -> bool:
        """True if any toggle is non-default (for display purposes)."""
        return (self.skip_structure or self.skip_naming or
                self.skip_agent_review or self.skip_codeql_build or
                self.disable_domain_context or self.disable_pcode or
                self.disable_access_evidence)


@dataclass(frozen=True)
class PipelineConfig:
    anthropic_api_key: str
    anthropic_base_url: str
    reconstruction_model: str
    codeql_exe: str
    ablation: AblationConfig = field(default_factory=AblationConfig)
    llm_timeout_seconds: float = 600.0
    context: str = ""
    language: str = "en"
    ghidra_install_dir: str = ""
    pyghidra_mcp_exe: str = "pyghidra-mcp"
    # GLM / Anthropic-compat reasoning. glm-5.3 requires enabled thinking and
    # an explicit low/high/max effort value.
    thinking_type: str = ""
    reasoning_effort: str = ""


def _parse_ablation(data: dict) -> AblationConfig:
    abl = data.get("ABLATION") or {}
    if not isinstance(abl, dict):
        return AblationConfig()
    return AblationConfig(
        skip_structure=bool(abl.get("skip_structure", False)),
        skip_naming=bool(abl.get("skip_naming", False)),
        skip_agent_review=bool(abl.get("skip_agent_review", False)),
        skip_codeql_build=bool(abl.get("skip_codeql_build", False)),
        disable_domain_context=bool(abl.get("disable_domain_context", True)),
        disable_pcode=bool(abl.get("disable_pcode", False)),
        enable_prescan=bool(abl.get("enable_prescan", False)),
        enable_multi_agent=bool(abl.get("enable_multi_agent", False)),
        reconstruction_workers=int(abl.get("reconstruction_workers", 1)),
        disable_access_evidence=bool(abl.get("disable_access_evidence", False)),
    )


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

    ablation = _parse_ablation(data)

    # THINKING: { type: enabled, reasoning_effort: low|high|max } — GLM format
    thinking_type = ""
    thinking_cfg = data.get("THINKING")
    if isinstance(thinking_cfg, dict):
        thinking_type = str(thinking_cfg.get("type") or "").strip().lower()
    elif isinstance(thinking_cfg, str):
        thinking_type = thinking_cfg.strip().lower()
    if thinking_type and thinking_type not in ("enabled", "disabled"):
        raise RuntimeError(
            f"[config] THINKING.type must be 'enabled' or 'disabled', got {thinking_type!r}"
        )
    reasoning_effort = ""
    if isinstance(thinking_cfg, dict):
        reasoning_effort = str(thinking_cfg.get("reasoning_effort") or "").strip().lower()
    if reasoning_effort and reasoning_effort not in ("low", "high", "max"):
        raise RuntimeError(
            f"[config] THINKING.reasoning_effort must be 'low', 'high', or 'max', got {reasoning_effort!r}"
        )
    if str(model).strip().lower() == "glm-5.3":
        if thinking_type != "enabled":
            raise RuntimeError("[config] glm-5.3 requires THINKING.type: enabled")
        if reasoning_effort not in ("low", "high", "max"):
            raise RuntimeError("[config] glm-5.3 requires THINKING.reasoning_effort: low, high, or max")

    return PipelineConfig(
        anthropic_api_key=str(api_key),
        anthropic_base_url=str(base_url),
        reconstruction_model=str(model),
        codeql_exe=str(codeql_exe),
        ablation=ablation,
        llm_timeout_seconds=float(data.get("LLM_TIMEOUT_SECONDS") or 600),
        context=str(data.get("CONTEXT") or "").strip(),
        language=str(data.get("OUTPUT_LANGUAGE") or "en").strip().lower(),
        ghidra_install_dir=str(data.get("GHIDRA_INSTALL_DIR") or ""),
        pyghidra_mcp_exe=str(data.get("PYGHIDRA_MCP_EXE") or "") or "pyghidra-mcp",
        thinking_type=thinking_type,
        reasoning_effort=reasoning_effort,
    )


def ghidra_settings(config: PipelineConfig) -> tuple[str, str]:
    if not config.ghidra_install_dir:
        raise RuntimeError("Set GHIDRA_INSTALL_DIR in local_config.yaml")
    return config.ghidra_install_dir, config.pyghidra_mcp_exe
