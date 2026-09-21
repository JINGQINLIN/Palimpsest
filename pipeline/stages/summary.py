from __future__ import annotations

import json
import re
from pathlib import Path

from rich.console import Console

from pipeline.console import make_progress, print_item, print_step
from pipeline.llm import LLMClient, TokenUsage
from pipeline.paths import FUNCTIONS_SUBDIR
from pipeline.prompts import PromptManager

_HEX_LITERAL_RE = re.compile(r'(?<!["\w])(0x[0-9a-fA-F]+)(?!["\w])')
_FENCE_RE = re.compile(r"\A\s*```(?:json|JSON)?\s*\n(.*?)\n?```\s*\Z", re.DOTALL)


class FunctionSummarizer:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm
        self.prompts = PromptManager()

    def summarize(self, named_code_with_map: str) -> tuple[dict, str, TokenUsage]:
        prompt = self.prompts.load("summary.jinja2", named_code_with_map=named_code_with_map)
        raw, usage = self.llm.complete(prompt, max_tokens=4096)
        return self._parse_json(raw) or {}, raw, usage

    @staticmethod
    def _parse_json(raw: str) -> dict | None:
        text = raw.strip()
        if match := _FENCE_RE.match(text):
            text = match.group(1).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        try:
            return json.loads(_HEX_LITERAL_RE.sub(r'"\1"', text))
        except json.JSONDecodeError:
            return None


def _function_dirs(package_dir: Path) -> list[Path]:
    root = package_dir / FUNCTIONS_SUBDIR
    return [path for path in sorted(root.glob("0x*")) if (path / "named.c").is_file()]


def _read_summary_input(func_dir: Path) -> str:
    named = (func_dir / "named.c").read_text(encoding="utf-8")
    naming_map = func_dir / "naming_map.txt"
    if naming_map.is_file():
        return named + "\n\nNAMING_MAP:\n" + naming_map.read_text(encoding="utf-8")
    return named


def run_summarize(package_dir: Path, llm: LLMClient, console: Console) -> TokenUsage:
    targets = _function_dirs(package_dir)
    total_usage = TokenUsage()
    if not targets:
        print_step(console, "Summaries")
        print_item(console, "status", f"no named.c files found under {package_dir}")
        return total_usage

    summarizer = FunctionSummarizer(llm)
    print_step(console, "Summaries")
    print_item(console, "functions", len(targets))
    failed = 0

    with make_progress(console) as progress:
        task = progress.add_task("", total=len(targets))
        for func_dir in targets:
            progress.update(task, description=func_dir.name)
            try:
                summary, raw, usage = summarizer.summarize(_read_summary_input(func_dir))
                total_usage.merge(usage)
                if summary:
                    (func_dir / "summary.json").write_text(
                        json.dumps(summary, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    (func_dir / "summary.txt").unlink(missing_ok=True)
                else:
                    (func_dir / "summary.txt").write_text(raw, encoding="utf-8")
            except Exception as exc:
                failed += 1
                console.print(f"  [red]failed[/red] {func_dir.name}: {exc}")
            progress.advance(task)

    print_item(console, "tokens", total_usage.format())
    print_item(console, "failed", failed)
    return total_usage
