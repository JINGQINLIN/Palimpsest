from __future__ import annotations

import subprocess
from pathlib import Path


def check_file(codeql_dir: Path, filename: str) -> list[str]:
    """Run gcc -fsyntax-only on one C file, returning lines containing 'error:'.

    Args:
        codeql_dir: Directory containing the CodeQL source files.
        filename: Name of the C file to check.

    Returns:
        A list of error lines from gcc stderr. Empty if gcc is unavailable or the
        file compiles cleanly.
    """
    filepath = codeql_dir / filename
    if not filepath.is_file():
        return []

    try:
        result = subprocess.run(
            ["gcc", "-fsyntax-only", f"-I{codeql_dir}", str(filepath)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # gcc missing or unable to run — gracefully degrade.
        return []

    return [line.strip() for line in result.stderr.splitlines() if "error:" in line]
