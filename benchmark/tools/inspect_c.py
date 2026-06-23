"""Debug helper — inspect extracted features from one C file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmark.lib.c_parse import extract_function_features, format_features


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract benchmark features from one C file")
    parser.add_argument("c_file", type=Path, help="Path to a .c file")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text")
    args = parser.parse_args()

    if not args.c_file.is_file():
        print(f"error: file not found: {args.c_file}")
        return 1

    code = args.c_file.read_text(encoding="utf-8", errors="ignore")
    features = extract_function_features(code)

    if args.json:
        print(json.dumps(features, ensure_ascii=False, indent=2))
    else:
        print(format_features(features))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
