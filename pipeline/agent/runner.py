from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from rich.console import Console

from pipeline.agent.catalog import FunctionCatalog
from pipeline.agent.context import KICKOFF, build_system_blocks
from pipeline.agent.graph import CallGraph
from pipeline.agent.session import ReviewSession
from pipeline.agent.tools import build_tools
from pipeline.console import print_item, print_step
from pipeline.llm import LLMClient, TokenUsage
from pipeline.paths import CODEQL_SUBDIR, REGISTRY_SUBDIR
from pipeline.registry import NamingRegistry, StructRegistry, write_types_header

_MAX_TOKENS = 8192
_MAX_ITERATIONS = 1000
_REVIEW_LOG = "agent_review.json"


def _write_review_log(package_dir: Path, session: ReviewSession, summary: str) -> Path:
    log_path = package_dir / Path(REGISTRY_SUBDIR).parent / _REVIEW_LOG
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        json.dumps({"summary": summary, "changes": session.changes}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return log_path


def _tool_line(block, graph: CallGraph) -> str:
    inp = block.input or {}

    def fn(addr: str) -> str:
        node = graph.resolve(addr) if addr else None
        return f"0x{node.addr} {node.name}" if node else (addr or "?")

    name = block.name
    if name in ("edit_function", "rewrite_function"):
        verb = "edit" if name == "edit_function" else "rewrite"
        return f"  [yellow]✎ {verb}[/yellow] {fn(inp.get('address', ''))}"
    if name in ("rename_symbol", "rename_struct"):
        verb = "rename" if name == "rename_symbol" else "struct"
        return f"  [yellow]✎ {verb}[/yellow] {inp.get('old_name', '')} → {inp.get('new_name', '')}"
    if name in ("read_function", "get_callers", "get_callees", "get_function_info", "get_call_sites"):
        label = name.replace("_", " ")
        return f"  [dim]· {label} {fn(inp.get('address', ''))}[/dim]"
    return f"  [dim]· {name.replace('_', ' ')}[/dim]"


def run_agent_review(
    *,
    package_dir: Path,
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm: LLMClient,
    language_directive: str = "",
    console: Console,
) -> TokenUsage:
    print_step(console, "4. Agent review")
    usage = TokenUsage()

    codeql_dir = package_dir / CODEQL_SUBDIR
    if not codeql_dir.is_dir() or not any(codeql_dir.glob("0x*.c")):
        print_item(console, "status", "no codeql/src files; skip")
        return usage

    graph = CallGraph(codeql_dir)
    catalog = FunctionCatalog(graph, package_dir)
    indirect = sum(len(i.indirect_sites) for i in catalog.all_infos())
    placeholders = sum(len(i.placeholders) for i in catalog.all_infos())
    print_item(console, "functions", len(graph.nodes))
    print_item(console, "placeholders", placeholders)
    print_item(console, "indirect sites", indirect)
    print_item(console, "model", llm.model)

    session = ReviewSession(
        graph=graph,
        catalog=catalog,
        registry=registry,
        struct_registry=struct_registry,
    )

    system = build_system_blocks(graph, catalog, struct_registry)
    kickoff = KICKOFF + ("\n\n" + language_directive if language_directive else "")
    messages = [{"role": "user", "content": kickoff}]

    final_text = ""
    last_stop = None
    calls = 0
    try:
        runner = llm.client.beta.messages.tool_runner(
            model=llm.model,
            max_tokens=_MAX_TOKENS,
            max_iterations=_MAX_ITERATIONS,
            tools=build_tools(session),
            system=system,
            messages=messages,
        )
        with console.status("[dim]reviewing…[/dim]", spinner="dots") as status:
            for message in runner:
                usage.add_anthropic(getattr(message, "usage", None))
                last_stop = getattr(message, "stop_reason", None)
                texts = []
                for block in message.content:
                    if block.type == "tool_use":
                        calls += 1
                        status.update(
                            f"{_tool_line(block, graph).strip()}"
                            f"  ·  calls {calls} · changes {len(session.changes)}"
                        )
                    elif block.type == "text" and block.text.strip():
                        texts.append(block.text.strip())
                if texts and last_stop == "end_turn":
                    final_text = "\n".join(texts)
    except Exception as exc:
        console.print(f"  [red]agent review failed:[/red] {exc}")
        return usage

    write_types_header(codeql_dir, struct_registry.get_all())

    log_path = _write_review_log(package_dir, session, final_text)
    by_tool = Counter(c["tool"] for c in session.changes)
    edited = {c["address"] for c in session.changes if c.get("address")}
    print_item(
        console,
        "changes",
        f"{len(session.changes)} (rename {by_tool.get('rename_symbol', 0)}, "
        f"edit {by_tool.get('edit_function', 0)}, rewrite {by_tool.get('rewrite_function', 0)}, "
        f"struct {by_tool.get('rename_struct', 0)})",
    )
    print_item(console, "functions edited", len(edited))
    print_item(console, "tool calls", calls)
    print_item(console, "tokens", usage.format())
    print_item(console, "log", log_path)
    if last_stop not in ("end_turn", "stop_sequence", None):
        print_item(console, "note", f"stopped at {last_stop}; review may be incomplete (raise _MAX_ITERATIONS)")
    return usage
