from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.live import Live

from pipeline.agent.catalog import FunctionCatalog
from pipeline.agent.context import KICKOFF, build_system_blocks
from pipeline.agent.graph import CallGraph
from pipeline.agent.session import ReviewSession
from pipeline.agent.syntax_utils import check_file
from pipeline.agent.tools import build_tools, build_prescan_tool_set, build_specialist_tool_set
from pipeline.console import print_item, print_step
from pipeline.llm import AGENT_MAX_TOKENS, LLMClient, TokenUsage
from pipeline.paths import CODEQL_SUBDIR, REGISTRY_SUBDIR
from pipeline.registry import NamingRegistry, StructRegistry, write_types_header

_MAX_ITERATIONS = 1000
_PRESCAN_ITERATIONS = 30
_REVIEW_LOG = "agent_review.json"
_CATALOG_SUMMARY = "catalog_summary.json"

# Specialist agent configs: (name, playbook_file, iterations)
_SPECIALIST_AGENTS = [
    ("Naming-Agent",   "playbook_naming.md",   30),
    ("Types-Agent",    "playbook_types.md",    30),
    ("Dispatch-Agent", "playbook_dispatch.md", 40),
    ("Syntax-Agent",   "playbook_syntax.md",   10),
]


def _run_prescan_phase(
    *,
    package_dir: Path,
    graph: CallGraph,
    catalog: FunctionCatalog,
    registry,
    struct_registry,
    llm: LLMClient,
    console: Console,
) -> TokenUsage:
    """Phase 0: run a read-only agent that surveys the codebase and writes
    a structured catalog summary for downstream specialist agents.
    """
    print_step(console, "4.0 Pre-Scan")
    usage = TokenUsage()

    session = ReviewSession(graph=graph, catalog=catalog,
                            registry=registry, struct_registry=struct_registry)

    _PLAYBOOK_PRESCAN = (Path(__file__).parent / "playbook_prescan.md").read_text(encoding="utf-8")
    summary_path = package_dir / Path(REGISTRY_SUBDIR).parent / _CATALOG_SUMMARY

    overview = (
        f"{len(graph.nodes)} functions in catalog. "
        f"Use browse_functions to survey, then group by domain. "
        f"Call generate_catalog_summary to persist your analysis. "
        f"Output goes to {summary_path}."
    )
    system = [
        {"type": "text", "text": _PLAYBOOK_PRESCAN},
        {"type": "text", "text": overview},
    ]

    kickoff = (
        "Survey this firmware codebase and produce a catalog summary. "
        "Start with browse_functions for an overview, then group functions "
        "by semantic domain.  For each domain, identify the entry function "
        "and write a brief role description.  Inventory all FUN_/DAT_ "
        "placeholders with suggested names.  Detect dispatch tables and "
        "orphan functions.  Audit signature mismatches and struct coverage. "
        "Call scan_residual_noise (rule-based) before writing noise_report — "
        "use its priority_files as the hotspot list (do not invent counts). "
        "Build a dependency map by depth layers.  Call generate_catalog_summary "
        "incrementally or in one final call with all sections."
    )
    messages = [{"role": "user", "content": kickoff}]

    final_text = ""
    try:
        runner = llm.client.beta.messages.tool_runner(
            model=llm.model,
            max_tokens=AGENT_MAX_TOKENS,
            max_iterations=_PRESCAN_ITERATIONS,
            tools=build_prescan_tool_set(session, summary_path),
            system=system,
            messages=messages,
            **llm.thinking_kwargs(),
        )
        with console.status("[dim]pre-scanning…[/dim]", spinner="dots") as status:
            calls = 0
            for message in runner:
                usage.add_anthropic(getattr(message, "usage", None))
                for block in message.content:
                    if block.type == "tool_use":
                        calls += 1
                        status.update(f"pre-scan · calls {calls}")
                    elif block.type == "text" and block.text.strip():
                        final_text = block.text.strip()
    except Exception as exc:
        console.print(f"  [yellow]pre-scan failed:[/yellow] {exc}")
        return usage

    if summary_path.is_file():
        try:
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            sections = list(data.keys())
            print_item(console, "pre-scan summary", f"{len(sections)} sections: {', '.join(sections)}")
        except json.JSONDecodeError:
            console.print("  [yellow]pre-scan summary is not valid JSON[/yellow]")
    else:
        console.print("  [yellow]pre-scan did not produce a summary file[/yellow]")

    print_item(console, "pre-scan tokens", usage.format())
    return usage


def _run_specialist_agent(
    *,
    agent_name: str,
    playbook_file: str,
    max_iterations: int,
    session: ReviewSession,
    llm: LLMClient,
    console: Console,
) -> TokenUsage:
    """Run a single specialist agent and return its token usage."""
    usage = TokenUsage()
    session.set_agent(agent_name)

    playbook_path = Path(__file__).parent / playbook_file
    playbook_text = playbook_path.read_text(encoding="utf-8") if playbook_path.is_file() else ""
    system = [{"type": "text", "text": playbook_text}]
    kickoff = f"You are the {agent_name} specialist. Review the codebase for {agent_name}-related issues."
    messages = [{"role": "user", "content": kickoff}]

    def _label(name: str, inp: dict | None) -> str:
        """One-line summary of a tool call for the console display."""
        name_pad = name.ljust(18)
        if name in ("edit_function", "rewrite_function"):
            addr = (inp or {}).get("address", "?")
            node = session.graph.resolve(addr) if addr else None
            label = f"0x{node.addr} {node.name}" if node else (addr or "?")
            return f"  {agent_name:<15} [yellow]\u2710 {name_pad}[/yellow] {label}"
        if name == "rename_symbol":
            return f"  {agent_name:<15} [yellow]\u2710 rename[/yellow] {(inp or {}).get('old_name','?')} \u2192 {(inp or {}).get('new_name','?')}"
        if name == "batch_resolve_symbols":
            return f"  {agent_name:<15} [yellow]\u2710 resolve[/yellow] batch"
        if name == "generate_catalog_summary":
            return f"  {agent_name:<15} [cyan]\u2713 summary[/cyan]"
        if name == "check_syntax" or name == "batch_check_syntax":
            return f"  {agent_name:<15} [cyan]\u2713 syntax[/cyan]"
        return f"  {agent_name:<15} [dim]\u00b7 {name_pad}[/dim]"

    calls = 0
    try:
        runner = llm.client.beta.messages.tool_runner(
            model=llm.model,
            max_tokens=AGENT_MAX_TOKENS,
            max_iterations=max_iterations,
            tools=build_specialist_tool_set(session, agent_name),
            system=system,
            messages=messages,
            **llm.thinking_kwargs(),
        )
        for message in runner:
            usage.add_anthropic(getattr(message, "usage", None))
            for block in message.content:
                if block.type == "tool_use":
                    calls += 1
                    inp: dict | None = getattr(block, "input", None)
                    console.print(_label(block.name, inp))
    except Exception:
        logging.getLogger("pipeline").warning(
            "specialist agent %s failed silently", agent_name, exc_info=True
        )
    return usage


def _load_placeholder_inventory(package_dir: Path) -> list[dict]:
    """Load high-confidence placeholder suggestions from catalog_summary.json.

    Returns an empty list if the file is missing, malformed, or has no
    placeholder_inventory section.  The Naming-Agent kickoff embeds this
    list so it doesn't have to discover placeholders from scratch.
    """
    summary_path = package_dir / Path(REGISTRY_SUBDIR).parent / _CATALOG_SUMMARY
    if not summary_path.is_file():
        return []
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    inv = data.get("placeholder_inventory") or {}
    items = inv.get("by_priority") or []
    if not isinstance(items, list):
        return []
    return [it for it in items if isinstance(it, dict)]


def _load_noise_priority_files(package_dir: Path, *, limit: int = 5) -> list[dict]:
    """Load rule-scanned noise hotspots from catalog_summary.json."""
    summary_path = package_dir / Path(REGISTRY_SUBDIR).parent / _CATALOG_SUMMARY
    if not summary_path.is_file():
        return []
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    noise = data.get("noise_report") or {}
    items = noise.get("priority_files") or []
    if not items:
        rule = noise.get("rule_scan") or {}
        items = rule.get("priority_files") or []
    if not isinstance(items, list):
        return []
    return [it for it in items if isinstance(it, dict)][:limit]


def _format_hotspot_lines(hotspots: list[dict]) -> str:
    lines = []
    for it in hotspots:
        counts = it.get("counts") or {}
        cstr = ",".join(f"{k}={v}" for k, v in counts.items() if v)
        addr = it.get("address") or "?"
        lines.append(
            f"- {addr}  score={it.get('score', '?')}  {it.get('file', '?')}  ({cstr})"
        )
    return "\n".join(lines)


def _naming_kickoff(package_dir: Path) -> str:
    """Build Naming-Agent kickoff with embedded high-confidence placeholders."""
    items = _load_placeholder_inventory(package_dir)
    high = [it for it in items if str(it.get("confidence", "")).lower() == "high"]
    hotspots = _load_noise_priority_files(package_dir, limit=5)
    base = (
        "You are the Naming-Agent specialist. Review the codebase for "
        "naming-related issues.  Per your playbook, step 0: process the "
        "high-confidence placeholders listed below BEFORE browsing.  Use "
        "rename_symbol for each one (evidence was already cross-checked by "
        "PreScan).  Then proceed to step 1 of your playbook."
    )
    if not high:
        base += (
            "\n\n(catalog_summary.json has no high-confidence placeholders; "
            "fall through to browse_functions filter=placeholders.)"
        )
    else:
        lines = [f"\n\nHigh-confidence placeholders ({len(high)}):"]
        for it in high:
            sym = it.get("symbol") or it.get("placeholder") or "?"
            sug = it.get("suggested_name") or it.get("suggestion") or "?"
            reason = it.get("reason") or it.get("evidence") or ""
            line = f"- {sym} -> {sug}"
            if reason:
                line += f"  // {reason[:120]}"
            lines.append(line)
        base += "\n".join(lines)
    if hotspots:
        base += (
            f"\n\nNoise hotspots (resolve FUN_/iVar/local_ on these first; "
            f"{len(hotspots)}):\n{_format_hotspot_lines(hotspots)}"
        )
    return base


def _types_kickoff(package_dir: Path) -> str:
    """Build Types-Agent kickoff with embedded noise hotspots."""
    hotspots = _load_noise_priority_files(package_dir, limit=5)
    base = (
        "You are the Types-Agent specialist. Per your playbook step 0: clean "
        "residual noise on the priority_files below with a tight edit budget "
        "(≤5 edit_function per file): undefined*/hex offsets/simple goto+LAB_. "
        "Then continue with signature/struct consistency work. "
        "After typing edits, call check_field_coherence(addr); "
        "prefer bare offsets over incoherent typed fields."
    )
    if not hotspots:
        return base + (
            "\n\n(No noise_report.priority_files in catalog_summary.json; "
            "fall through to normal signature audit.)"
        )
    return (
        base
        + f"\n\nRule-scanned noise hotspots ({len(hotspots)}):\n"
        + _format_hotspot_lines(hotspots)
    )


def _run_multi_agent_phase(
    *,
    package_dir: Path,
    session: ReviewSession,
    llm: LLMClient,
    console: Console,
) -> TokenUsage:
    """Run 4 specialist agents concurrently under function-level locking."""
    print_step(console, "4.1 Specialist agents")

    _SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    status_lines: dict[str, str] = {
        name: f"  {name:<15} starting…" for name, _, _ in _SPECIALIST_AGENTS
    }
    status_lock = threading.Lock()
    agent_running: dict[str, bool] = {
        name: True for name, _, _ in _SPECIALIST_AGENTS
    }

    def _agent_with_status(agent_name, playbook_file, max_iterations):
        usage = TokenUsage()
        session.set_agent(agent_name)
        playbook_path = Path(__file__).parent / playbook_file
        playbook_text = playbook_path.read_text(encoding="utf-8") if playbook_path.is_file() else ""
        system = [{"type": "text", "text": playbook_text}]
        if agent_name == "Naming-Agent":
            kickoff = _naming_kickoff(package_dir)
        elif agent_name == "Types-Agent":
            kickoff = _types_kickoff(package_dir)
        else:
            kickoff = f"You are the {agent_name} specialist. Review the codebase for {agent_name}-related issues."
        messages = [{"role": "user", "content": kickoff}]

        def _brief(name, inp):
            name_pad = name.ljust(18)
            if name in ("edit_function", "rewrite_function"):
                addr = (inp or {}).get("address", "?")
                node = session.graph.resolve(addr) if addr else None
                label = f"0x{node.addr} {node.name}" if node else (addr or "?")
                return f"[yellow]\u2710 {name_pad}[/yellow] {label}"
            if name == "rename_symbol":
                return f"[yellow]\u2710 rename[/yellow] {(inp or {}).get('old_name','?')} \u2192 {(inp or {}).get('new_name','?')}"
            if name == "batch_resolve_symbols":
                return "[yellow]\u2710 resolve[/yellow] batch"
            if name in ("generate_catalog_summary", "check_syntax", "batch_check_syntax"):
                return f"[cyan]\u2713 {name_pad}[/cyan]"
            return f"[dim]\u00b7 {name_pad}[/dim]"

        try:
            runner = llm.client.beta.messages.tool_runner(
                model=llm.model, max_tokens=AGENT_MAX_TOKENS,
                max_iterations=max_iterations,
                tools=build_specialist_tool_set(session, agent_name),
                system=system, messages=messages,
                **llm.thinking_kwargs(),
            )
            for message in runner:
                usage.add_anthropic(getattr(message, "usage", None))
                for block in message.content:
                    if block.type == "tool_use":
                        inp = getattr(block, "input", None)
                        with status_lock:
                            status_lines[agent_name] = f"  {agent_name:<15} {_brief(block.name, inp)}"
        except Exception:
            with status_lock:
                status_lines[agent_name] = f"  {agent_name:<15} [red]failed[/red]"
            logging.getLogger("pipeline").warning("specialist %s failed", agent_name, exc_info=True)
        finally:
            agent_running[agent_name] = False
            with status_lock:
                status_lines[agent_name] = f"  {agent_name:<15} [green]done[/green]"
        return usage

    total_usage = TokenUsage()
    names_in_order = [n for n, _, _ in _SPECIALIST_AGENTS]

    def _render():
        frame = _SPINNER[int(time.monotonic() * 10) % len(_SPINNER)]
        lines = []
        for name in names_in_order:
            if agent_running[name]:
                lines.append(f"[bold cyan]{frame}[/bold cyan] {status_lines[name]}")
            else:
                lines.append(f"[green]✓[/green] {status_lines[name]}")
        return "\n".join(lines)

    class _LiveRenderable:
        __slots__ = ()
        def __rich_console__(self, _console, _options):
            yield _render()

    with Live(_LiveRenderable(), console=console, refresh_per_second=8, transient=True):
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(_agent_with_status, name, pb, iters): name
                for name, pb, iters in _SPECIALIST_AGENTS
            }
            for f in as_completed(futures):
                name = futures[f]
                try:
                    total_usage.merge(f.result())
                except Exception:
                    pass

    for name, _, _ in _SPECIALIST_AGENTS:
        changes = len(session.changes_by_agent.get(name, []))
        if changes:
            print_item(console, f"  {name}", f"{changes} changes")
    lock_count = len(session._edit_lock)
    if lock_count:
        print_item(console, "functions edited", lock_count)

    return total_usage


def _write_review_log(
    package_dir: Path,
    session: ReviewSession,
    summary: str,
    *,
    by_agent: dict[str, int] | None = None,
) -> Path:
    log_path = package_dir / Path(REGISTRY_SUBDIR).parent / _REVIEW_LOG
    log_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict = {"summary": summary, "changes": session.changes}
    if by_agent is not None:
        payload["by_agent"] = by_agent
    log_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
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
    if name == "check_syntax":
        return f"  [cyan]✓ syntax[/cyan] {fn(inp.get('address', ''))}"
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
    enable_prescan: bool = False,
    enable_multi_agent: bool = False,
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

    # ── Phase 0: Pre-Scan (optional) ─────────────────────────────────
    if enable_prescan:
        usage.merge(
            _run_prescan_phase(
                package_dir=package_dir,
                graph=graph,
                catalog=catalog,
                registry=registry,
                struct_registry=struct_registry,
                llm=llm,
                console=console,
            )
        )

    session = ReviewSession(
        graph=graph,
        catalog=catalog,
        registry=registry,
        struct_registry=struct_registry,
    )

    # ── Phase 1: Multi-Agent (optional) ──────────────────────────────
    if enable_multi_agent:
        usage.merge(_run_multi_agent_phase(package_dir=package_dir, session=session, llm=llm, console=console))

        write_types_header(codeql_dir, struct_registry.get_all())
        summary = f"multi-agent review: {len(session.changes)} changes across 4 agents"
        by_agent = {k: len(v) for k, v in session.changes_by_agent.items()}
        log_path = _write_review_log(package_dir, session, summary, by_agent=by_agent)

        print_item(console, "changes", str(len(session.changes)))
        print_item(console, "tokens", usage.format())
        print_item(console, "log", log_path)
        return usage

    system = build_system_blocks(graph, catalog, struct_registry)
    kickoff = KICKOFF + ("\n\n" + language_directive if language_directive else "")
    messages = [{"role": "user", "content": kickoff}]

    final_text = ""
    last_stop = None
    calls = 0
    try:
        runner = llm.client.beta.messages.tool_runner(
            model=llm.model,
            max_tokens=AGENT_MAX_TOKENS,
            max_iterations=_MAX_ITERATIONS,
            tools=build_tools(session),
            system=system,
            messages=messages,
            **llm.thinking_kwargs(),
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
        console.print_exception()
        return usage

    syntax_errs = sum(
        len(check_file(codeql_dir, f.name))
        for f in codeql_dir.glob("*.c")
    )
    print_item(console, "syntax errs", syntax_errs)

    write_types_header(codeql_dir, struct_registry.get_all())

    log_path = _write_review_log(package_dir, session, final_text)
    by_tool = Counter(c["tool"] for c in session.changes)
    edited = {c["address"] for c in session.changes if c.get("address")}
    print_item(
        console,
        "changes",
        f"{len(session.changes)} (rename {by_tool.get('rename_symbol', 0)}, "
        f"edit {by_tool.get('edit_function', 0)}, rewrite {by_tool.get('rewrite_function', 0)}, "
        f"struct {by_tool.get('rename_struct', 0)}, syntax {by_tool.get('check_syntax', 0)})",
    )
    print_item(console, "functions edited", len(edited))
    print_item(console, "tool calls", calls)
    print_item(console, "tokens", usage.format())
    print_item(console, "log", log_path)
    if last_stop not in ("end_turn", "stop_sequence", None):
        print_item(console, "note", f"stopped at {last_stop}; review may be incomplete (raise _MAX_ITERATIONS)")
    return usage
