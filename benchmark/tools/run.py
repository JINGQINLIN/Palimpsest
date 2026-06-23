"""Run benchmark steps 2–4: extract_pred → align → score."""

from __future__ import annotations

import argparse
import subprocess
import sys


def _run(module: str, args: list[str]) -> int:
    cmd = [sys.executable, "-m", module, *args]
    print(f"\n> {' '.join(cmd)}")
    return subprocess.call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run benchmark steps 2–4 (extract → align → score)"
    )
    parser.add_argument("--case", default="r9000_udhcpd")
    parser.add_argument("--stage", default="post_agent")
    parser.add_argument("--package", type=str, default="")
    args = parser.parse_args()

    shared = ["--case", args.case]
    if args.package:
        shared += ["--package", args.package]

    steps = [
        ("benchmark.tools.extract_pred", [*shared, "--stages", args.stage]),
        ("benchmark.tools.align", shared),
        ("benchmark.tools.score", [*shared, "--stage", args.stage]),
    ]

    for module, step_args in steps:
        if _run(module, step_args) != 0:
            return 1
    print("\nbenchmark done (steps 2–4)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
