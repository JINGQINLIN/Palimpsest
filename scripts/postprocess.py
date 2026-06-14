from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console

from config import load_config
from pipeline.console import print_item, print_step
from pipeline.llm import TokenUsage, client_from_config
from pipeline.paths import find_package_dir
from pipeline.stages.report import run_report
from pipeline.stages.summary import run_summarize

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Post-process pipeline output: summarize functions and/or generate firmware report",
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Output package directory (output/<name>) or firmware binary path/name",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--summarize-only",
        action="store_true",
        help="Only write per-function summary.json files",
    )
    mode.add_argument(
        "--report-only",
        action="store_true",
        help="Only generate reports/firmware_report.md (requires existing summaries)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    do_summarize = not args.report_only
    do_report = not args.summarize_only

    try:
        config = load_config()
        package_dir = find_package_dir(args.target)
        llm = client_from_config(config)
    except (RuntimeError, FileNotFoundError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 1

    print_step(console, "Post-process")
    print_item(console, "package", package_dir)
    if do_summarize and do_report:
        print_item(console, "steps", "summarize → report")
    elif do_summarize:
        print_item(console, "steps", "summarize only")
    else:
        print_item(console, "steps", "report only")

    total_usage = TokenUsage()

    if do_summarize:
        total_usage.merge(run_summarize(package_dir, llm, console))

    if do_report:
        report_path, report_usage = run_report(package_dir, llm, console)
        total_usage.merge(report_usage)
        if report_path is None:
            return 2

    if total_usage.total:
        print_item(console, "tokens", total_usage.format())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
