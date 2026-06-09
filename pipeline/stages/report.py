from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

from pipeline.console import print_item, print_step
from pipeline.llm import LLMClient, TokenUsage
from pipeline.paths import FUNCTIONS_SUBDIR, REPORTS_SUBDIR

REPORT_NAME = "firmware_report.md"
RISK_API_NAMES = {"system", "execle", "execve", "popen", "sprintf", "strcpy", "strcat", "memcpy"}
RISK_KEYWORDS = (
    "system(",
    "execle(",
    "execve(",
    "popen(",
    "sprintf(",
    "strcpy(",
    "strcat(",
    "memcpy(",
    "命令注入",
    "注入",
    "越界",
    "溢出",
    "NEW_DEVICE",
    "usockc",
)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _short(value: Any, limit: int = 240) -> str:
    text = " ".join(("" if value is None else str(value).strip()).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "..."


def _contains_risk(value: Any) -> bool:
    return value is not None and any(keyword in str(value) for keyword in RISK_KEYWORDS)


def _risk_apis(items: list[Any], limit: int = 8) -> list[str]:
    out = []
    for item in items:
        name = str(item).split("(", 1)[0].strip().lower()
        if name in RISK_API_NAMES or _contains_risk(item):
            out.append(str(item))
    return out[:limit]


def _threat_snippets(func_dir: Path, max_lines: int = 6) -> list[dict[str, Any]]:
    snippets = []
    for filename in ("named.c", "structured.c"):
        path = func_dir / filename
        if not path.is_file():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if _contains_risk(line):
                snippets.append({"file": filename, "line": lineno, "text": line.strip()})
    return snippets[:max_lines]


def _load_summary(func_dir: Path) -> dict[str, Any] | None:
    path = func_dir / "summary.json"
    if not path.is_file():
        return None

    summary = json.loads(path.read_text(encoding="utf-8"))
    risk = summary.get("security_relevance") or {}
    return {
        "address": func_dir.name,
        "function": summary.get("function_name_suggestion"),
        "summary": _short(summary.get("summary"), 220),
        "security_level": risk.get("level", "none"),
        "security_reason": _short(risk.get("reason", ""), 360),
        "confirmed_behaviors": [_short(x, 260) for x in _as_list(summary.get("confirmed_behaviors"))[:8]],
        "side_effects": [_short(x, 220) for x in _as_list(summary.get("side_effects")) if _contains_risk(x)][:5],
        "risk_strings": [_short(x, 220) for x in _as_list(summary.get("important_strings")) if _contains_risk(x)][:6],
        "risk_apis": _risk_apis(_as_list(summary.get("api_calls"))),
        "confidence": summary.get("confidence", "unknown"),
        "_dir": func_dir,
    }


def _collect_context(package_dir: Path) -> dict[str, Any]:
    functions = []
    for func_dir in sorted((package_dir / FUNCTIONS_SUBDIR).glob("0x*")):
        if func_dir.is_dir():
            item = _load_summary(func_dir)
            if item:
                functions.append(item)

    candidates = []
    for item in functions:
        if item["security_level"] in {"high", "medium"}:
            candidate = {key: value for key, value in item.items() if key != "_dir"}
            candidate["threat_snippets"] = _threat_snippets(item["_dir"])
            candidates.append(candidate)

    return {
        "firmware_package": package_dir.name,
        "function_count": len(functions),
        "function_map": [
            {
                "address": item["address"],
                "function": item["function"],
                "summary": item["summary"],
                "security_level": item["security_level"],
            }
            for item in functions
        ],
        "vulnerability_candidates": candidates,
    }


def _build_prompt(context: dict[str, Any]) -> str:
    data = json.dumps(context, ensure_ascii=False, indent=2)
    return f"""你是固件安全逆向分析助手。请只基于输入 JSON 生成中文 Markdown 报告。

输入 JSON 中:
- function_map 是所有已缓存 summary.json 的极简函数地图。
- vulnerability_candidates 是 high/medium 安全候选，已经附带少量源码证据。

报告要求:
1. 固件/组件功能概述。
2. 关键函数地图。
3. 攻击面。
4. 漏洞点清单。必须逐项覆盖 vulnerability_candidates，每项包含位置、证据、触发条件、影响、置信度和修复建议。
5. 后续验证建议。

不要编造 JSON 中没有的 API、调用链或漏洞。

输入 JSON:
{data}
"""


def _render_evidence(context: dict[str, Any]) -> str:
    candidates = context.get("vulnerability_candidates") or []
    if not candidates:
        return ""

    lines = [
        "## 自动提取的漏洞候选证据",
        "",
        "> 本节直接由函数级 summary.json 和少量源码证据生成，用于防止报告模型漏掉高/中危候选。",
        "",
    ]
    for idx, item in enumerate(candidates, 1):
        lines += [
            f"### {idx}. {item.get('function') or 'unknown'} ({item.get('address')})",
            "",
            f"- 风险级别: {item.get('security_level')}",
            f"- 置信度: {item.get('confidence')}",
            f"- 风险判断: {item.get('security_reason')}",
        ]
        if item.get("risk_apis"):
            lines.append("- 风险 API:")
            lines += [f"  - `{api}`" for api in item["risk_apis"]]
        if item.get("risk_strings"):
            lines.append("- 风险字符串:")
            lines += [f"  - `{string}`" for string in item["risk_strings"]]
        if item.get("threat_snippets"):
            lines.append("- 原始片段:")
            lines += [
                f"  - `{snippet['file']}:{snippet['line']}` `{snippet['text']}`"
                for snippet in item["threat_snippets"]
            ]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def run_report(package_dir: Path, llm: LLMClient, console: Console) -> tuple[Path | None, TokenUsage]:
    print_step(console, "Firmware report")
    context = _collect_context(package_dir)
    if context["function_count"] == 0:
        print_item(console, "status", "no summary.json files found")
        print_item(console, "hint", "run: python scripts/postprocess.py <target>")
        return None, TokenUsage()

    print_item(console, "functions", context["function_count"])
    print_item(console, "candidates", len(context["vulnerability_candidates"]))
    report, usage = llm.complete(_build_prompt(context), max_tokens=8192)
    final = report.strip()
    if evidence := _render_evidence(context):
        final = final.rstrip() + "\n\n---\n\n" + evidence

    report_dir = package_dir / REPORTS_SUBDIR
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / REPORT_NAME
    report_path.write_text(final + "\n", encoding="utf-8")
    print_item(console, "output", report_path)
    return report_path, usage
