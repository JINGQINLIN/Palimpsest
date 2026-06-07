from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

from pipeline.codeql.stubs import write_stub_header
from pipeline.console import print_item, print_step
from pipeline.outputs import copy_to_codeql_src
from pipeline.paths import (
    CODEQL_DB_SUBDIR,
    CODEQL_SUBDIR,
    FUNCTIONS_SUBDIR,
    REGISTRY_SUBDIR,
)
from pipeline.registry import (
    PLACEHOLDER_RE,
    NamingRegistry,
    StructRegistry,
    write_globals_header,
    write_macros_header,
    write_types_header,
)

_FUNC_DEF_RE = re.compile(
    r"(?m)^\s*[A-Za-z_][\w\s\*]*\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
)


def _write_unresolved_symbols(package_dir: Path, unresolved: dict[str, list[str]]) -> None:
    report_path = package_dir / REGISTRY_SUBDIR / "unresolved_symbols.txt"
    if not unresolved:
        report_path.write_text("(none)\n", encoding="utf-8")
        return

    lines = []
    for func_dir, symbols in sorted(unresolved.items()):
        lines.append(func_dir)
        lines.extend(f"  {symbol}" for symbol in symbols)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _lookup_function_name(registry: NamingRegistry, ghidra_name: str, code: str) -> str | None:
    if entry := registry.lookup(ghidra_name):
        return entry["canonical_name"]
    if match := _FUNC_DEF_RE.search(code):
        return match.group(1)
    return None


def apply_registry_and_export_sources(
    *,
    package_dir: Path,
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    contexts: dict,
    console: Console,
) -> int:
    print_step(console, "3. CodeQL source")

    registry_entries = registry.get_all()
    symbol_map = {
        sym: entry["canonical_name"]
        for sym, entry in registry_entries.items()
        if PLACEHOLDER_RE.fullmatch(sym)
    }
    if not symbol_map:
        print_item(console, "registry", "empty; no placeholders replaced")

    codeql_dir = package_dir / CODEQL_SUBDIR
    if codeql_dir.exists():
        shutil.rmtree(codeql_dir)
    codeql_dir.mkdir(parents=True)
    write_stub_header(codeql_dir)
    write_macros_header(codeql_dir, registry_entries)
    write_globals_header(codeql_dir, registry_entries)
    structs = struct_registry.get_all()
    write_types_header(codeql_dir, structs)

    macros_count = sum(
        1 for e in registry_entries.values() if e["kind"] == "constant" and e.get("value")
    )
    globals_count = sum(1 for e in registry_entries.values() if e["kind"] == "global_var")
    print_item(console, "structs", len(structs))
    print_item(console, "macros", macros_count)
    print_item(console, "globals", globals_count)

    count = 0
    unresolved: dict[str, list[str]] = {}
    functions_dir = package_dir / FUNCTIONS_SUBDIR
    for func_dir in sorted(functions_dir.glob("0x*")):
        named_path = func_dir / "named.c"
        if not named_path.is_file():
            continue

        named = named_path.read_text(encoding="utf-8")
        for placeholder, canonical_name in symbol_map.items():
            pattern = rf"\b{re.escape(placeholder)}\b"
            named = re.sub(pattern, canonical_name, named)
        named_path.write_text(named, encoding="utf-8")
        remaining = sorted(set(PLACEHOLDER_RE.findall(named)))
        if remaining:
            unresolved[func_dir.name] = remaining

        addr_hex = func_dir.name[2:]
        ctx = contexts.get(addr_hex)
        ghidra_name = ctx.ghidra_name if ctx else f"FUN_{addr_hex}"
        function_name = _lookup_function_name(registry, ghidra_name, named)
        copy_to_codeql_src(codeql_dir, addr_hex, named, function_name)
        count += 1

    print_item(console, "files", f"{count} C files")
    print_item(console, "output", codeql_dir)
    print_item(console, "symbols", len(symbol_map))
    print_item(console, "unresolved", sum(len(items) for items in unresolved.values()))
    _write_unresolved_symbols(package_dir, unresolved)
    return count


def create_codeql_database(*, package_dir: Path, codeql_exe: str, console: Console) -> bool:
    print_step(console, "5. CodeQL database")

    codeql_dir = package_dir / CODEQL_SUBDIR
    db_dir = package_dir / CODEQL_DB_SUBDIR
    if not codeql_dir.is_dir():
        console.print(f"  [red]error:[/red] CodeQL source not found: {codeql_dir}")
        return False
    if not any(codeql_dir.glob("*.c")):
        console.print(f"  [red]error:[/red] no .c files in {codeql_dir}")
        return False

    cmd = [
        codeql_exe,
        "database",
        "create",
        "--quiet",
        str(db_dir),
        "--language=cpp",
        "--source-root",
        str(codeql_dir),
        "--build-mode=none",
        "--overwrite",
    ]
    print_item(console, "command", codeql_exe)
    print_item(console, "source", codeql_dir)
    print_item(console, "db", db_dir)
    try:
        result = subprocess.run(cmd, text=True, capture_output=True)
    except FileNotFoundError:
        console.print(f"  [red]error:[/red] CODEQL_EXE not found: {codeql_exe}")
        return False
    if result.returncode != 0:
        if result.stdout.strip():
            console.print(result.stdout.rstrip())
        if result.stderr.strip():
            console.print(result.stderr.rstrip())
        console.print(f"  [red]error:[/red] codeql database create failed ({result.returncode})")
        return False

    print_item(console, "status", f"[green]created[/green] {db_dir}")
    return True
