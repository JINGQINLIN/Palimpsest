"""Collect function fingerprints from pipeline output at each stage."""

from __future__ import annotations

import json
from pathlib import Path
from pipeline.addresses import normalize_address
from pipeline.paths import CODEQL_SUBDIR, FUNCTIONS_SUBDIR, RAW_PACKAGE_SUBDIR

from benchmark.lib.c_parse import extract_function_features

STAGES = ("raw", "structured", "named", "post_agent")
_STAGE_FILENAMES = {
    "structured": "structured.c",
    "named": "named.c",
}


def format_addr(raw: str) -> str:
    normalized = normalize_address(raw)
    return f"0x{normalized}" if normalized else ""


def addr_from_codeql_file(path: Path) -> str:
    stem = path.stem
    head = stem[2:] if stem.startswith("0x") else stem
    addr_hex = head.split("_", 1)[0]
    return format_addr(addr_hex)


def addr_from_func_dir(name: str) -> str:
    raw = name[2:] if name.startswith("0x") else name
    return format_addr(raw)


def addr_from_raw_file(path: Path) -> str:
    return format_addr(path.stem)


def collect_pred_functions(package_dir: Path, stage: str) -> tuple[dict, list[str]]:
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}; expected one of {STAGES}")

    functions: dict = {}
    warnings: list[str] = []

    if stage == "post_agent":
        src_dir = package_dir / CODEQL_SUBDIR
        if not src_dir.is_dir():
            raise FileNotFoundError(f"missing codeql src dir: {src_dir}")
        items = sorted(src_dir.glob("0x*.c"))
        for path in items:
            addr = addr_from_codeql_file(path)
            if not addr:
                warnings.append(f"skip {path.name}: could not parse address")
                continue
            code = path.read_text(encoding="utf-8", errors="ignore")
            functions[addr] = {
                "addr": addr,
                "file": path.name,
                **extract_function_features(code),
            }
        return functions, warnings

    if stage == "raw":
        raw_dir = package_dir / RAW_PACKAGE_SUBDIR
        if not raw_dir.is_dir():
            raise FileNotFoundError(f"missing raw dir: {raw_dir}")
        for path in sorted(raw_dir.glob("*.json")):
            addr = addr_from_raw_file(path)
            if not addr:
                warnings.append(f"skip {path.name}: could not parse address")
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                warnings.append(f"skip {path.name}: invalid json ({exc})")
                continue
            code = str(data.get("code") or "")
            functions[addr] = {
                "addr": addr,
                "file": path.name,
                "ghidra_name": str(data.get("ghidra_name") or ""),
                **extract_function_features(code),
            }
        return functions, warnings

    filename = _STAGE_FILENAMES[stage]
    func_root = package_dir / FUNCTIONS_SUBDIR
    if not func_root.is_dir():
        raise FileNotFoundError(f"missing functions dir: {func_root}")

    for func_dir in sorted(func_root.glob("0x*")):
        path = func_dir / filename
        if not path.is_file():
            continue
        addr = addr_from_func_dir(func_dir.name)
        if not addr:
            warnings.append(f"skip {func_dir.name}: could not parse address")
            continue
        code = path.read_text(encoding="utf-8", errors="ignore")
        functions[addr] = {
            "addr": addr,
            "file": str(path.relative_to(package_dir)).replace("\\", "/"),
            **extract_function_features(code),
        }
    return functions, warnings
