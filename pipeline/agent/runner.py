from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from rich.console import Console

from pipeline.agent.graph import CallGraph
from pipeline.agent.tools import ReviewSession, build_tools
from pipeline.console import print_item, print_step
from pipeline.llm import LLMClient, TokenUsage
from pipeline.paths import CODEQL_SUBDIR, REGISTRY_SUBDIR
from pipeline.registry import NamingRegistry, StructRegistry, write_types_header

_PLAYBOOK = (Path(__file__).parent / "playbook.md").read_text(encoding="utf-8")
_CODEQL_GUIDE = (Path(__file__).parent / "codeql_guide.md").read_text(encoding="utf-8")
_MAX_TOKENS = 8192
_MAX_ITERATIONS = 200
_REVIEW_LOG = "agent_review.json"
_KICKOFF = (
    "Start the consistency review. The goal is a clean, high-quality CodeQL database. "
    "Work systematically: build a global picture with list_functions + get_registry + "
    "get_structs, then focus on signature/argument consistency between each definition and "
    "all of its call sites, residual placeholders, struct-pointer call-site alignment, and "
    "cross-function type mismatches. Gather evidence with get_callers / get_callees before "
    "editing. When done, give a short bullet summary of what you changed (by category) and "
    "which suspicious points you left unchanged for lack of evidence."
)


def _build_context(graph: CallGraph, struct_registry: StructRegistry) -> str:
    lines = [f"{len(graph.nodes)} functions in the code set. Index (addr | name | residual placeholders):"]
    unresolved_total = 0
    for addr in sorted(graph.nodes):
        node = graph.nodes[addr]
        unresolved_total += len(node.placeholders)
        ph = ",".join(sorted(node.placeholders)) if node.placeholders else "-"
        lines.append(f"0x{addr} | {node.name} | {ph}")
    lines.append(f"\nTotal residual placeholder symbols: {unresolved_total}. Handle these functions first.")

    structs = struct_registry.get_all()
    if structs:
        lines.append(f"\n{len(structs)} reconstructed structs (defined in the shared header recopilot_types.h):")
        for name, entry in sorted(structs.items()):
            fields = "; ".join(
                f"+0x{f['offset']:x} {f['name']} {f['type']}" for f in entry.get("fields", [])
            )
            lines.append(f"struct {name} (size 0x{entry.get('size', 0):x}): {fields}")
        lines.append(
            "The structure pass changed some signatures to struct pointers; their call sites "
            "may not be aligned yet — check and fix. Field names are authoritative in the shared "
            "header, so do not rename struct fields with rename_symbol."
        )
    return "\n".join(lines)


def _write_review_log(package_dir: Path, session: ReviewSession, summary: str) -> Path:
    log_path = package_dir / Path(REGISTRY_SUBDIR).parent / _REVIEW_LOG
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        json.dumps({"summary": summary, "changes": session.changes}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return log_path


def run_agent_review(
    *,
    package_dir: Path,
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm: LLMClient,
    console: Console,
) -> TokenUsage:
    print_step(console, "4. Agent review")
    usage = TokenUsage()

    codeql_dir = package_dir / CODEQL_SUBDIR
    if not codeql_dir.is_dir() or not any(codeql_dir.glob("0x*.c")):
        print_item(console, "status", "no codeql/src files; skip")
        return usage

    graph = CallGraph(codeql_dir)
    print_item(console, "functions", len(graph.nodes))
    print_item(console, "model", llm.model)

    session = ReviewSession(graph=graph, registry=registry, struct_registry=struct_registry)

    system = [
        {"type": "text", "text": _PLAYBOOK},
        {"type": "text", "text": _CODEQL_GUIDE},
        {"type": "text", "text": _build_context(graph, struct_registry), "cache_control": {"type": "ephemeral"}},
    ]
    messages = [{"role": "user", "content": _KICKOFF}]

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
                        arg = block.input.get("address") or block.input.get("old_name") or ""
                        status.update(
                            f"[dim]tool[/dim] {block.name} {arg}".rstrip()
                            + f"  ·  calls {calls} · changes {len(session.changes)}"
                        )
                    elif block.type == "text" and block.text.strip():
                        texts.append(block.text.strip())
                if last_stop == "end_turn" and texts:
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
