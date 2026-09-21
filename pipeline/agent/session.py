from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from pipeline.agent.catalog import FunctionCatalog
from pipeline.agent.graph import CallGraph
from pipeline.registry import NamingRegistry, StructRegistry


@dataclass
class ReviewSession:
    graph: CallGraph
    catalog: FunctionCatalog
    registry: NamingRegistry | None = None       # None during pre-scan
    struct_registry: StructRegistry | None = None  # None during pre-scan
    changes: list[dict[str, Any]] = field(default_factory=list)
    read_addrs: set[str] = field(default_factory=set)

    # Multi-agent support
    _edit_lock: set[str] = field(default_factory=set)
    changes_by_agent: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Per-thread agent name. threading.local ensures each specialist agent
    # running in the ThreadPoolExecutor has its own _agent_name, so concurrent
    # record_change calls are attributed to the correct agent. The previous
    # shared-string implementation caused all changes to be attributed to
    # whichever agent last called set_agent (the "attribution bug").
    _agent_name: threading.local = field(
        default_factory=threading.local, repr=False, compare=False
    )

    # Serialises all mutations of the multi-agent accumulators above
    # (changes, changes_by_agent, _edit_lock). Without this, four concurrent
    # specialist agents racing on changes.append() can lose entries and two
    # agents can simultaneously pass the ``address in _edit_lock`` check and
    # both edit the same function.
    _state_lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    def set_agent(self, name: str) -> None:
        """Set the active agent name for change attribution.

        Binds the name to the calling thread via threading.local, so each
        concurrent specialist agent in the ThreadPoolExecutor has its own
        attribution context.
        """
        with self._state_lock:
            self._agent_name.name = name  # type: ignore[attr-defined]
            if name not in self.changes_by_agent:
                self.changes_by_agent[name] = []

    def _current_agent(self) -> str:
        """Return the agent name bound to the calling thread (or '')."""
        return getattr(self._agent_name, "name", "")

    def record_change(self, change: dict[str, Any]) -> None:
        """Record a change, attributed to the current agent.

        All mutations of ``changes`` and ``changes_by_agent`` must go through
        this method so they are serialised by ``_state_lock``. Direct
        ``self.changes.append(...)`` calls from tool code bypass the lock and
        reintroduce the race this method exists to prevent.
        """
        with self._state_lock:
            self.changes.append(change)
            agent = self._current_agent()
            if agent:
                self.changes_by_agent.setdefault(agent, []).append(change)

    def acquire_edit(self, address: str) -> bool:
        """Try to acquire exclusive edit rights for a function.

        Returns True if the lock was acquired, False if another agent
        already edited this function.  Agents should skip locked functions.

        The membership check and the ``add`` are performed atomically under
        ``_state_lock``; without it, two agents can both observe the address
        as unlocked and both proceed to edit.
        """
        with self._state_lock:
            if address in self._edit_lock:
                return False
            self._edit_lock.add(address)
            return True

    def node_or_error(self, address: str):
        node = self.graph.resolve(address)
        if node is None:
            known = ", ".join(f"0x{a}" for a in sorted(self.graph.nodes)[:12])
            return None, f"No function at {address!r}. Examples: {known} ..."
        return node, ""
