"""Agent tool registry: assembles beta_tools for the review loop.

Explore tools (9, read-only) and edit tools (5, modifying) are built in their
submodules and concatenated here.  Pre-Scan and specialist agent tools are
built separately for their respective phases.
"""
from __future__ import annotations

from pathlib import Path

from pipeline.agent.session import ReviewSession
from pipeline.agent.tools._dispatch import build_dispatch_tools
from pipeline.agent.tools._edit import build_edit_tools
from pipeline.agent.tools._explore import build_explore_tools
from pipeline.agent.tools._naming import build_naming_tools
from pipeline.agent.tools._prescan import build_prescan_tools
from pipeline.agent.tools._syntax import build_syntax_tools
from pipeline.agent.tools._types import build_types_tools


def build_tools(session: ReviewSession) -> list:
    """Assemble all 14 agent tools for single-agent review.

    Returns a list of ``@beta_tool`` decorated callables ready to pass to
    ``client.beta.messages.tool_runner(tools=...)``.
    """
    graph = session.graph
    catalog = session.catalog
    codeql_dir = next(iter(graph.nodes.values())).path.parent if graph.nodes else Path(".")
    return (
        build_explore_tools(session, graph, catalog, codeql_dir)
        + build_edit_tools(session, graph, catalog, codeql_dir)
    )


def build_prescan_tool_set(session: ReviewSession, output_path: Path) -> list:
    """Build tools for the Pre-Scan phase (explore + prescan-specific)."""
    graph = session.graph
    catalog = session.catalog
    codeql_dir = next(iter(graph.nodes.values())).path.parent if graph.nodes else Path(".")
    return (
        build_explore_tools(session, graph, catalog, codeql_dir)
        + build_prescan_tools(session, output_path)
    )


def build_specialist_tool_set(session: ReviewSession, agent_name: str) -> list:
    """Build tools for a specialist agent: shared explore/edit + agent-specific.

    Each specialist gets the full shared toolset plus their specialized
    batch tool, so they can fall back to single-step operations when needed.

    Syntax-Agent is the exception: its playbook says "Do NOT fix errors —
    report them", so it must not have edit_function/rewrite_function.
    Giving it edit tools led to semantic regressions (e.g. dispatch_dhcp_message
    void→int without a return statement). Syntax-Agent now gets explore tools
    plus syntax-checking tools only.
    """
    graph = session.graph
    catalog = session.catalog
    codeql_dir = next(iter(graph.nodes.values())).path.parent if graph.nodes else Path(".")

    if agent_name == "Syntax-Agent":
        # Read-only: explore + syntax checks only. No edit_function.
        return (
            build_explore_tools(session, graph, catalog, codeql_dir)
            + build_syntax_tools(session, codeql_dir)
        )

    shared = (
        build_explore_tools(session, graph, catalog, codeql_dir)
        + build_edit_tools(session, graph, catalog, codeql_dir)
    )

    specialist = {
        "Naming-Agent":   build_naming_tools,
        "Types-Agent":    build_types_tools,
        "Dispatch-Agent": build_dispatch_tools,
        "Syntax-Agent":   lambda s: build_syntax_tools(s, codeql_dir),
    }

    extra = specialist.get(agent_name, lambda s: [])
    return shared + extra(session)
