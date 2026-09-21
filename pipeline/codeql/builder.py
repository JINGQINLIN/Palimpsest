"""CodeQL database builder.

Applies the naming & struct registries to the reconstructed C sources, writes
the generated headers (stubs/macros/globals/types), and builds a CodeQL C++
database with --build-mode=none.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

from pipeline.c_source import first_function_name, parse_function_definition
from pipeline.codeql.export_names import (
    apply_codeql_name,
    build_export_map,
    plan_codeql_names,
)
from pipeline.codeql.stubs import write_stub_header
from pipeline.console import print_item, print_step
from pipeline.outputs import copy_to_codeql_src
from pipeline.paths import (
    CODEQL_DB_SUBDIR,
    CODEQL_SUBDIR,
    DECLS_HEADER_FILENAME,
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
from pipeline.registry.coherence import check_field_coherence


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


def sync_codeql_filenames(codeql_dir: Path, console: Console) -> list[tuple[str, str]]:
    """Sync CodeQL source filenames to match the actual function name in file content.

    After agent review may rename symbols (FUN_xxxx → meaningful_name) in file
    content via rename_symbol, the filename tokens (derived from base_names at
    export time) become stale. This ensures filename == content for every .c file.

    Returns a list of (old_name, new_name) for each renamed file.
    """
    renamed: list[tuple[str, str]] = []
    for src_file in sorted(codeql_dir.glob("0x*.c")):
        text = src_file.read_text(encoding="utf-8")
        name = first_function_name(text)
        if name is None:
            continue

        stem = src_file.stem
        parts = stem.split("_", 1)
        if len(parts) != 2:
            continue
        addr_hex = parts[0]
        old_token = parts[1]

        if old_token == name:
            continue

        token = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_")
        new_path = src_file.parent / f"{addr_hex}_{token}.c"

        if new_path.exists() and new_path != src_file:
            new_path = src_file.parent / f"{addr_hex}_{token}_0x{addr_hex}.c"

        src_file.rename(new_path)
        renamed.append((src_file.name, new_path.name))

    if renamed:
        print_item(console, "sync filenames", f"{len(renamed)} files renamed after agent review")
    return renamed


def _write_decls_header(codeql_dir: Path) -> int:
    """Extract function signatures from all .c files and write forward declarations.

    CodeQL --build-mode=none treats each .c as an independent translation unit.
    Without forward declarations for cross-file calls, CodeQL may silently drop
    call edges that are essential for data-flow tracking.

    Must be called AFTER agent review completes, so that all FUN_ placeholders
    have been resolved to semantic names.
    """
    signatures: list[str] = []
    seen: set[str] = set()
    for src_path in sorted(codeql_dir.glob("0x*.c")):
        text = src_path.read_text(encoding="utf-8", errors="ignore")
        parsed = parse_function_definition(text)
        if parsed is None:
            continue
        sig = f"{parsed['return_type']} {parsed['name']}({', '.join(parsed['params'])})"
        if sig not in seen:
            seen.add(sig)
            signatures.append(sig)

    if not signatures:
        # Still write an empty marker so #include "recopilot_decls.h" resolves.
        (codeql_dir / DECLS_HEADER_FILENAME).write_text(
            "/* Auto-generated forward declarations (none parsed). */\n",
            encoding="utf-8",
        )
        return 0

    header = (
        "/* Auto-generated forward declarations for cross-file CodeQL data-flow tracking. */\n"
        + "\n".join(f"{sig};" for sig in sorted(signatures))
        + "\n"
    )
    (codeql_dir / DECLS_HEADER_FILENAME).write_text(header, encoding="utf-8")
    return len(signatures)


def verify_decls_match_sources(codeql_dir: Path) -> list[str]:
    """Return mismatch messages if decls disagree with per-file parsed signatures."""
    decls_path = codeql_dir / DECLS_HEADER_FILENAME
    if not decls_path.is_file():
        return [f"missing {DECLS_HEADER_FILENAME}"]
    decl_text = decls_path.read_text(encoding="utf-8", errors="replace")
    mismatches: list[str] = []
    for src_path in sorted(codeql_dir.glob("0x*.c")):
        parsed = parse_function_definition(src_path.read_text(encoding="utf-8", errors="ignore"))
        if parsed is None:
            continue
        expected = f"{parsed['return_type']} {parsed['name']}("
        # Pointer-drop regression: decl has same name but wrong return type (e.g. char vs char *).
        name = parsed["name"]
        needle = f" {name}("
        hits = [line.strip() for line in decl_text.splitlines() if needle in line and line.strip().endswith(";")]
        if not hits:
            mismatches.append(f"{src_path.name}: no decl for {name}")
            continue
        ok = any(line.startswith(parsed["return_type"] + " " + name + "(") or line.startswith(expected) for line in hits)
        if not ok:
            mismatches.append(f"{src_path.name}: want `{parsed['return_type']} {name}(...)` got {hits[0]}")
    return mismatches


def finalize_codeql_sources(codeql_dir: Path, console: Console) -> int:
    """Sync filenames and (re)write decls — required even when package DB build is skipped."""
    if not codeql_dir.is_dir():
        return 0
    sync_codeql_filenames(codeql_dir, console)
    decls_count = _write_decls_header(codeql_dir)
    print_item(console, "forward decls", decls_count)
    mismatches = verify_decls_match_sources(codeql_dir)
    if mismatches:
        print_item(console, "decls audit", f"[red]{len(mismatches)} mismatch(es)[/red]")
        for item in mismatches[:12]:
            console.print(f"  [red]-[/red] {item}")
        raise RuntimeError(
            "recopilot_decls.h does not match codeql/src signatures "
            f"({len(mismatches)} mismatches); refusing to continue"
        )
    return decls_count


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
    functions_dir = package_dir / FUNCTIONS_SUBDIR
    base_names, codeql_names, duplicate_bases = plan_codeql_names(
        functions_dir, registry, contexts
    )
    export_map = build_export_map(registry_entries, codeql_names)
    if not export_map:
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
    coherence_fallbacks: list[str] = []

    def _apply_export(text: str, addr_hex: str) -> str:
        for placeholder, replacement in export_map.items():
            text = re.sub(rf"\b{re.escape(placeholder)}\b", replacement, text)
        return apply_codeql_name(
            text, base_names.get(addr_hex), codeql_names[addr_hex]
        )

    for func_dir in sorted(functions_dir.glob("0x*")):
        named_path = func_dir / "named.c"
        if not named_path.is_file():
            continue

        addr_hex = func_dir.name[2:]
        named = _apply_export(named_path.read_text(encoding="utf-8"), addr_hex)

        # Safety net: typed field access must exist on the declared struct.
        # Prefer structured, then raw, over incoherent named output.
        report = check_field_coherence(named, structs)
        if not report.ok:
            chosen = None
            chosen_label = ""
            for label, fname in (("structured", "structured.c"), ("raw", "raw.c")):
                alt_path = func_dir / fname
                if not alt_path.is_file():
                    continue
                alt = _apply_export(alt_path.read_text(encoding="utf-8"), addr_hex)
                if check_field_coherence(alt, structs).ok or label == "raw":
                    chosen, chosen_label = alt, label
                    break
            if chosen is not None:
                coherence_fallbacks.append(
                    f"0x{addr_hex}: named→{chosen_label} ({report.summary()})"
                )
                named = chosen

        named_path.write_text(named, encoding="utf-8")
        remaining = sorted(set(PLACEHOLDER_RE.findall(named)))
        if remaining:
            unresolved[func_dir.name] = remaining

        copy_to_codeql_src(codeql_dir, addr_hex, named, codeql_names[addr_hex])
        count += 1

    print_item(console, "files", f"{count} C files")
    print_item(console, "output", codeql_dir)
    print_item(console, "symbols", len(export_map))
    if duplicate_bases:
        print_item(console, "collisions", ", ".join(sorted(duplicate_bases)))
    print_item(console, "unresolved", sum(len(items) for items in unresolved.values()))
    if coherence_fallbacks:
        print_item(console, "coherence fallbacks", len(coherence_fallbacks))
        fallback_path = package_dir / REGISTRY_SUBDIR / "coherence_fallbacks.txt"
        fallback_path.write_text(
            "\n".join(coherence_fallbacks) + "\n", encoding="utf-8"
        )
    _write_unresolved_symbols(package_dir, unresolved)
    # Always emit decls here so --skip-codeql-build packages remain CodeQL-ready.
    finalize_codeql_sources(codeql_dir, console)
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

    finalize_codeql_sources(codeql_dir, console)

    cmd = [
        codeql_exe,
        "database",
        "create",
        "--quiet",
        str(db_dir),
        "--language=cpp",
        "--source-root",
        str(codeql_dir),
        # --build-mode=none creates a DB from source without compilation.
        # No compiler syntax validation; parse failures silently dropped.
        # TODO(P1): collect compiler syntax-check feedback to evaluate IR accuracy.
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
