from __future__ import annotations

import re
from pathlib import Path

RAW_PACKAGE_SUBDIR = "raw"
FUNCTIONS_SUBDIR = "reconstruction/functions"
REGISTRY_SUBDIR = "reconstruction/registry"
CODEQL_SUBDIR = "codeql/src"
CODEQL_DB_SUBDIR = "codeql/db"
REPORTS_SUBDIR = "reports"
OUTPUT_DIR = Path("output")
CONTEXTS_DIR = Path("contexts")
STUB_HEADER_FILENAME = "recopilot_stubs.h"
TYPES_HEADER_FILENAME = "recopilot_types.h"


def safe_dir_name(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return safe.strip("._") or "binary"


def find_package_dir(target: Path) -> Path:
    if target.is_dir():
        return target
    package_dir = OUTPUT_DIR / safe_dir_name(target.name)
    if package_dir.is_dir():
        return package_dir
    raise FileNotFoundError(f"output package not found: {package_dir}")
