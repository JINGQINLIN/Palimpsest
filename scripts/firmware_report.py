from __future__ import annotations

import argparse
from pathlib import Path

from _common import console, setup
from pipeline.stages.report import run_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate firmware_report.md")
    parser.add_argument("target", type=Path, help="Output package directory or binary name/path")
    args = parser.parse_args()

    try:
        package_dir, llm = setup(args.target, "Report script")
    except (RuntimeError, FileNotFoundError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 1

    run_report(package_dir, llm, console)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
