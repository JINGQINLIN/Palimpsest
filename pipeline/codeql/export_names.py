from __future__ import annotations

from collections import Counter
from pathlib import Path

from pipeline.addresses import fun_symbol_addr
from pipeline.c_source import first_function_name, rename_function_definition
from pipeline.registry import PLACEHOLDER_RE, NamingRegistry


def duplicate_base_names(bases_by_addr: dict[str, str | None]) -> set[str]:
    counts = Counter(name for name in bases_by_addr.values() if name)
    return {name for name, total in counts.items() if total > 1}


def codeql_name(base: str | None, addr_hex: str, duplicate_bases: set[str]) -> str:
    name = base or f"FUN_{addr_hex}"
    if name in duplicate_bases:
        return f"{name}_0x{addr_hex}"
    return name


def lookup_base_name(registry: NamingRegistry, ghidra_name: str, code: str) -> str | None:
    if entry := registry.lookup(ghidra_name):
        return entry["canonical_name"]
    return first_function_name(code)


def collect_base_names(
    functions_dir: Path,
    registry: NamingRegistry,
    contexts: dict,
) -> dict[str, str | None]:
    bases: dict[str, str | None] = {}
    for func_dir in sorted(functions_dir.glob("0x*")):
        named_path = func_dir / "named.c"
        if not named_path.is_file():
            continue
        addr_hex = func_dir.name[2:]
        ctx = contexts.get(addr_hex)
        ghidra_name = ctx.ghidra_name if ctx else f"FUN_{addr_hex}"
        bases[addr_hex] = lookup_base_name(
            registry, ghidra_name, named_path.read_text(encoding="utf-8")
        )
    return bases


def build_export_map(
    registry_entries: dict[str, dict],
    codeql_names: dict[str, str],
) -> dict[str, str]:
    export: dict[str, str] = {}
    for symbol, entry in registry_entries.items():
        if not PLACEHOLDER_RE.fullmatch(symbol):
            continue
        if entry["kind"] == "function":
            addr = fun_symbol_addr(symbol)
            export[symbol] = codeql_names[addr] if addr in codeql_names else entry["canonical_name"]
        else:
            export[symbol] = entry["canonical_name"]
    return export


def plan_codeql_names(
    functions_dir: Path,
    registry: NamingRegistry,
    contexts: dict,
) -> tuple[dict[str, str | None], dict[str, str], set[str]]:
    base_names = collect_base_names(functions_dir, registry, contexts)
    duplicate_bases = duplicate_base_names(base_names)
    codeql_names = {
        addr: codeql_name(base, addr, duplicate_bases)
        for addr, base in base_names.items()
    }
    return base_names, codeql_names, duplicate_bases


def apply_codeql_name(code: str, base_name: str | None, codeql_name_value: str) -> str:
    if base_name:
        return rename_function_definition(code, base_name, codeql_name_value)
    return code
