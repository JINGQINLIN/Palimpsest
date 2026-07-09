from __future__ import annotations

from pathlib import Path

from pipeline.agent.catalog import FunctionCatalog
from pipeline.agent.graph import CallGraph
from pipeline.registry import StructRegistry

_PLAYBOOK = (Path(__file__).parent / "playbook.md").read_text(encoding="utf-8")
_CODEQL_GUIDE = (Path(__file__).parent / "codeql_guide.md").read_text(encoding="utf-8")

KICKOFF = (
    "Review the recovered firmware C code set for cross-function consistency and CodeQL readiness. "
    "Start with browse_functions to see the catalog (signatures, callers, indirect calls, placeholders). "
    "Use get_function_info before read_function to pick targets efficiently — especially for functions "
    "with no static callers (likely indirect dispatch) or indirect call sites inside the body. "
    "Use get_call_sites and search_code to trace dispatch tables and function-pointer edges. "
    "Gather evidence, then fix with edit_function / rename_symbol / rename_struct. "
    "Finish with a summary by category: placeholders, signatures, indirect dispatch, structs, parse issues."
)


def build_system_blocks(graph: CallGraph, catalog: FunctionCatalog, struct_registry: StructRegistry) -> list[dict]:
    """Assemble cached system prompt blocks for the review agent."""
    summary_lines = [
        f"{len(graph.nodes)} functions in catalog.",
        "Use browse_functions / get_function_info for full details.",
        "",
    ]
    unresolved_total = 0
    indirect_total = 0
    for info in catalog.all_infos():
        unresolved_total += len(info.placeholders)
        indirect_total += len(info.indirect_sites)

    notable = [info for info in catalog.all_infos() if info.placeholders or info.indirect_sites][:50]
    for info in notable:
        summary_lines.append(catalog.format_row(info))
    if len(notable) == 50:
        summary_lines.append("...(truncated; use browse_functions)")

    entries = [info for info in catalog.all_infos() if info.is_entry]
    if entries:
        summary_lines.append(
            "\nentry points: "
            + ", ".join(f"{i.name}(0x{i.addr})" for i in entries[:20])
        )

    summary_lines.append(f"\nTotals: placeholders={unresolved_total}, indirect_sites={indirect_total}")

    structs = struct_registry.get_all()
    if structs:
        summary_lines.append(f"\n{len(structs)} structs in recopilot_types.h:")
        for name, entry in sorted(structs.items()):
            fields = "; ".join(
                f"+0x{f['offset']:x} {f['name']} {f['type']}" for f in entry.get("fields", [])
            )
            summary_lines.append(f"  struct {name} (0x{entry.get('size', 0):x}): {fields}")

    return [
        {"type": "text", "text": _PLAYBOOK},
        {"type": "text", "text": _CODEQL_GUIDE},
        {"type": "text", "text": "\n".join(summary_lines), "cache_control": {"type": "ephemeral"}},
    ]
