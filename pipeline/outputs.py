from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from pipeline.paths import (
    CODEQL_DB_SUBDIR,
    CODEQL_SUBDIR,
    FUNCTIONS_SUBDIR,
    REGISTRY_SUBDIR,
    REPORTS_SUBDIR,
    TYPES_HEADER_FILENAME,
)
from pipeline.registry import NamingRegistry


def prepare_package_dirs(package_dir: Path) -> None:
    for sub in ("", FUNCTIONS_SUBDIR, REGISTRY_SUBDIR, CODEQL_SUBDIR, REPORTS_SUBDIR):
        (package_dir / sub).mkdir(parents=True, exist_ok=True)


def reset_core_outputs(package_dir: Path) -> None:
    for sub in (FUNCTIONS_SUBDIR, REGISTRY_SUBDIR, CODEQL_SUBDIR, CODEQL_DB_SUBDIR):
        path = package_dir / sub
        if path.exists():
            shutil.rmtree(path)


def _normalize_c(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip() + "\n"


def write_function_outputs(func_dir: Path, artifacts: dict) -> None:
    func_dir.mkdir(parents=True, exist_ok=True)
    if artifacts.get("raw"):
        (func_dir / "raw.c").write_text(_normalize_c(artifacts["raw"]), encoding="utf-8")
    if artifacts.get("structured"):
        (func_dir / "structured.c").write_text(_normalize_c(artifacts["structured"]), encoding="utf-8")
    if artifacts.get("named"):
        (func_dir / "named.c").write_text(_normalize_c(artifacts["named"]), encoding="utf-8")
    if artifacts.get("naming_map"):
        (func_dir / "naming_map.txt").write_text(artifacts["naming_map"].strip() + "\n", encoding="utf-8")


def copy_to_codeql_src(codeql_dir: Path, addr_hex: str, named_text: str, function_name: str | None) -> None:
    if not named_text:
        return
    codeql_dir.mkdir(parents=True, exist_ok=True)
    token = re.sub(r"[^A-Za-z0-9_-]+", "_", function_name or "").strip("_")
    fname = f"0x{addr_hex}_{token}.c" if token else f"0x{addr_hex}.c"
    include = f'#include "{TYPES_HEADER_FILENAME}"\n\n'
    (codeql_dir / fname).write_text(include + named_text, encoding="utf-8")


def write_registry_exports(package_dir: Path, registry: NamingRegistry) -> None:
    registry_dir = package_dir / REGISTRY_SUBDIR
    registry_dir.mkdir(parents=True, exist_ok=True)
    entries = registry.get_all()

    (registry_dir / "symbol_registry.json").write_text(
        json.dumps(entries, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if not entries:
        (registry_dir / "symbol_registry.txt").write_text("(registry empty)\n", encoding="utf-8")
        return

    lines = []
    for symbol, entry in entries.items():
        type_part = f" :: {entry['inferred_type']}" if entry.get("inferred_type") else ""
        lines.append(
            f"{symbol} -> {entry['canonical_name']}{type_part} "
            f"| kind: {entry['kind']} | confidence: {entry['confidence']} "
            f"| evidence: {entry['evidence']}"
        )
    (registry_dir / "symbol_registry.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def reset_registry_files(registry_path: Path) -> None:
    for path in (
        registry_path,
        Path(str(registry_path) + "-wal"),
        Path(str(registry_path) + "-shm"),
    ):
        path.unlink(missing_ok=True)


def write_skipped_log(package_dir: Path, skipped: list[tuple[str, str, str]]) -> None:
    path = package_dir / Path(FUNCTIONS_SUBDIR).parent / "skipped.txt"
    if not skipped:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"0x{addr} | {name} | {reason}" for addr, name, reason in skipped]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
