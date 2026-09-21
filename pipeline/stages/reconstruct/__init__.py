"""Reconstruction pipeline (per-function, leaf-first).

  raw Ghidra C ──► _run_structure_phase ──► structured C
                          │                       │
                 struct_registry.update()         │
                                                  ▼
                                      _run_naming_phase ──► named C
                                              │
                                 naming_registry.update()

Functions are processed leaf-first via topological order (see stages.order),
so callee names are known before their callers are handled.
"""
from pipeline.artifacts import ReconstructionArtifacts
from pipeline.stages.reconstruct.orchestrate import (
    process_function,
    reconstruct_function,
    run_reconstruction,
)

__all__ = [
    "ReconstructionArtifacts",
    "process_function",
    "reconstruct_function",
    "run_reconstruction",
]
