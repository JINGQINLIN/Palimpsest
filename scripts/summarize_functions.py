from __future__ import annotations

import argparse
from pathlib import Path

from _common import console, setup
from pipeline.stages.summary import run_summarize


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize reconstructed functions")
    parser.add_argument("target", type=Path, help="Output package directory or binary name/path")
    args = parser.parse_args()

    try:
        package_dir, llm = setup(args.target, "Summary script")
    except (RuntimeError, FileNotFoundError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 1

    run_summarize(package_dir, llm, console)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
