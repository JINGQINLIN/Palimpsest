"""Build ranked source→sink chains to focus agent review.

Before the consistency-review agent runs, scan ``codeql/src`` for security sinks
(command execution, memory writes), walk the static call graph upward, and emit a
ranked task list (``reconstruction/flows.json``). The agent system prompt and
``get_flows`` tool consume this list so effort concentrates on restoring taint
paths instead of polishing unrelated functions.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from pipeline.agent.graph import CallGraph

# --- sink catalogs -----------------------------------------------------------

COMMAND_EXEC = [
    "system", "___system", "popen", "execl", "execlp", "execle",
    "execv", "execvp", "execve", "posix_spawn", "posix_spawnp",
    "ExecShell", "CsteSystem", "doSystemCmd",
]
MEM_WRITE = ["memcpy", "memmove", "strcpy", "strcat", "sprintf"]

_SINK_GROUPS = {"command_exec": COMMAND_EXEC, "mem_write": MEM_WRITE}
_MAX_DEPTH = 15


@dataclass
class Site:
    category: str
    name: str
    line: int
    snippet: str


# --- sink detection ----------------------------------------------------------

def _scan(text: str, names: list[str]) -> list[tuple[str, int, str]]:
    pattern = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\s*\(")
    hits: list[tuple[str, int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for match in pattern.finditer(line):
            hits.append((match.group(1), lineno, line.strip()))
    return hits


def _sink_sites(text: str) -> list[Site]:
    sites: list[Site] = []
    for category, names in _SINK_GROUPS.items():
        for name, line, snippet in _scan(text, names):
            sites.append(Site(category=category, name=name, line=line, snippet=snippet))
    return sites


def _sink_functions(graph: CallGraph) -> dict[str, list[Site]]:
    out: dict[str, list[Site]] = {}
    for addr, node in graph.nodes.items():
        sites = _sink_sites(node.path.read_text(encoding="utf-8", errors="ignore"))
        if sites:
            out[addr] = sites
    return out


# --- call-graph path search --------------------------------------------------

def _paths_to_roots(graph: CallGraph, sink_addr: str, max_depth: int) -> list[list[str]]:
    paths: list[list[str]] = []

    def walk(addr: str, path: list[str]) -> None:
        live = [c for c in graph.callers(addr) if c.addr not in path]
        if not live or len(path) >= max_depth:
            paths.append(list(reversed(path)))
            return
        for caller in live:
            walk(caller.addr, path + [caller.addr])

    walk(sink_addr, [sink_addr])
    return paths


def _dedup(paths: list[list[str]]) -> list[list[str]]:
    seen: set[tuple[str, ...]] = set()
    uniq: list[list[str]] = []
    for path in sorted(paths, key=len):
        key = tuple(path)
        if key not in seen:
            seen.add(key)
            uniq.append(path)
    return uniq


# --- public API --------------------------------------------------------------

def build_flows(graph: CallGraph) -> dict:
    """Return {summary, sinks} for every sink function in the call graph."""
    sink_funcs = _sink_functions(graph)
    records: list[dict] = []

    for addr in sorted(sink_funcs):
        node = graph.nodes[addr]
        sites = sink_funcs[addr]
        severity = "high" if any(s.category == "command_exec" for s in sites) else "low"
        all_paths = _dedup(_paths_to_roots(graph, addr, _MAX_DEPTH))
        shortest = min(all_paths, key=len) if all_paths else [addr]
        status = "traced" if graph.callers(addr) else "root"
        placeholders = sorted(
            {ph for a in shortest for ph in graph.nodes[a].placeholders}
        )
        records.append({
            "sink_id": 0,
            "severity": severity,
            "status": status,
            "confidence": "inferred" if placeholders else "confirmed",
            "sink": {"addr": addr, "name": node.name, "sites": _site_dicts(sites)},
            "path": [graph.nodes[a].name for a in shortest],
            "path_count": len(all_paths),
            "placeholders_on_path": placeholders,
        })

    records.sort(
        key=lambda r: (r["severity"] != "high", r["status"] != "traced", r["sink"]["addr"])
    )
    for i, record in enumerate(records, 1):
        record["sink_id"] = i

    summary = {
        "sinks": len(records),
        "high": sum(1 for r in records if r["severity"] == "high"),
        "low": sum(1 for r in records if r["severity"] == "low"),
        "root_only": sum(1 for r in records if r["status"] == "root"),
        "inferred": sum(1 for r in records if r["confidence"] == "inferred"),
    }
    return {"summary": summary, "sinks": records}


def _site_dicts(sites: list[Site]) -> list[dict]:
    return [
        {"category": s.category, "name": s.name, "line": s.line, "snippet": s.snippet}
        for s in sites
    ]


def format_flows(flows: dict) -> str:
    """Human-readable chain list for the agent system prompt / get_flows."""
    s = flows["summary"]
    lines = [
        f"{s['sinks']} sinks reachable in the code set "
        f"({s['high']} high command-exec, {s['low']} low mem-write, {s['root_only']} root-only). "
        "These are the primary review targets — restore each chain end to end, high first.",
    ]
    for r in flows["sinks"]:
        names = "+".join(sorted({x["name"] for x in r["sink"]["sites"]}))
        path = " -> ".join(r["path"])
        extra = f" (+{r['path_count'] - 1} more routes)" if r["path_count"] > 1 else ""
        note = ""
        if r["status"] == "root":
            note += (
                " [root: no resolved caller — if not the program entry, it is reached via "
                "an unseen edge (function-pointer dispatch) or is dead; investigate]"
            )
        if r["confidence"] == "inferred":
            note += " [inferred: path still carries placeholders]"
        lines.append(
            f"#{r['sink_id']} [{r['severity']}] {names} in {r['sink']['name']}"
            f"  <=  {path}{extra}{note}"
        )
    return "\n".join(lines)


def write_flows(package_dir: Path, flows: dict) -> Path:
    path = package_dir / "reconstruction" / "flows.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(flows, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python -m pipeline.agent.flows <output_package_dir>")
        return 1
    package_dir = Path(argv[1])
    codeql_dir = package_dir / "codeql" / "src"
    if not codeql_dir.is_dir():
        print(f"error: no codeql/src in {package_dir}")
        return 1

    graph = CallGraph(codeql_dir)
    flows = build_flows(graph)
    out = write_flows(package_dir, flows)

    s = flows["summary"]
    print(f"functions  {len(graph.nodes)}")
    print(f"sinks      {s['sinks']}  (high {s['high']}, low {s['low']}, "
          f"root-only {s['root_only']}, inferred {s['inferred']})")
    print(f"written    {out}\n")
    for record in flows["sinks"]:
        names = "+".join(sorted({s["name"] for s in record["sink"]["sites"]}))
        tag = f"[{record['severity']:<4} {record['status']:<6}] #{record['sink_id']}"
        extra = f"  (+{record['path_count'] - 1} more routes)" if record["path_count"] > 1 else ""
        print(f"  {tag} {' -> '.join(record['path'])}  ::{names}{extra}")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv))
