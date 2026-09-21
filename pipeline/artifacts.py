"""Shared data types for reconstruction artifacts.

Defined here (rather than inside the reconstruct package) to avoid a circular
import between ``pipeline.outputs`` and ``pipeline.stages.reconstruct.orchestrate``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pipeline.llm import TokenUsage


@dataclass
class ReconstructionArtifacts:
    """Artifacts produced by reconstructing one function.

    When skip_reason is non-empty, the function was marked as trivial/skippable
    by the structure phase and only usage is meaningful.
    """

    usage: TokenUsage
    skip_reason: str = ""
    raw: str = ""
    structured: str = ""
    named: str = ""
    naming_map: str = ""
    registry_updates: list[dict] = field(default_factory=list)
    struct_updates: list[dict] = field(default_factory=list)
    pcode: str = ""
    access_evidence: str = ""

    @property
    def skipped(self) -> bool:
        """True when the function was skipped (skip_reason is non-empty)."""
        return bool(self.skip_reason)
