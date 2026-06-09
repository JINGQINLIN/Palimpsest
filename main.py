from __future__ import annotations

import argparse
import asyncio
import shutil
from pathlib import Path

from rich.console import Console

from config import load_config
from pipeline.agent import run_agent_review
from pipeline.codeql import apply_registry_and_export_sources, create_codeql_database
from pipeline.console import print_item, print_step
from pipeline.llm import TokenUsage, client_from_config
from pipeline.outputs import (
    prepare_package_dirs,
    reset_core_outputs,
    reset_registry_files,
    write_registry_exports,
    write_skipped_log,
)
from pipeline.paths import (
    CODEQL_DB_SUBDIR,
    CODEQL_SUBDIR,
    FUNCTIONS_SUBDIR,
    OUTPUT_DIR,
    RAW_PACKAGE_SUBDIR,
    REGISTRY_SUBDIR,
    safe_dir_name,
)
from pipeline.prompts import load_layer_context
from pipeline.registry import NamingRegistry, StructRegistry
from pipeline.stages.ghidra import (
    fetch as fetch_raw_package,
    filter_runtime_contexts,
    load_ghidra_config,
    load_raw_package,
)
from pipeline.stages.reconstruct import run_reconstruction

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Firmware semantic reconstruction pipeline")
    parser.add_argument("binary", type=Path, help="Firmware binary path")
    return parser.parse_args()


def package_dir_for(binary: Path) -> Path:
    return OUTPUT_DIR / safe_dir_name(binary.name)


def ensure_raw_package(binary: Path, raw_dir: Path) -> bool:
    print_step(console, "1. Raw package")
    print_item(console, "binary", binary)
    print_item(console, "raw", raw_dir)
    if raw_dir.is_dir():
        shutil.rmtree(raw_dir)

    try:
        ghidra_dir, mcp_exe = load_ghidra_config()
    except RuntimeError as exc:
        console.print(f"[red]error:[/red] {exc}")
        print_item(console, "hint", "set GHIDRA_INSTALL_DIR in local_config.yaml")
        return False

    rc = asyncio.run(
        fetch_raw_package(
            binary_path=binary,
            output_dir=raw_dir,
            ghidra_dir=ghidra_dir,
            mcp_exe=mcp_exe,
        )
    )
    return rc == 0


def main() -> int:
    args = parse_args()
    try:
        config = load_config()
    except RuntimeError as exc:
        console.print(f"[red]error:[/red] {exc}")
        print_item(console, "hint", "copy local_config.example.yaml to local_config.yaml")
        return 1

    package_dir = package_dir_for(args.binary)
    raw_dir = package_dir / RAW_PACKAGE_SUBDIR
    if not ensure_raw_package(args.binary, raw_dir):
        return 1

    try:
        raw_contexts = load_raw_package(raw_dir)
    except Exception as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 1
    contexts = filter_runtime_contexts(raw_contexts)
    runtime_filtered = len(raw_contexts) - len(contexts)
    if not contexts:
        console.print("[red]error:[/red] no analyzable functions after filtering")
        print_item(console, "raw funcs", len(raw_contexts))
        print_item(console, "runtime", runtime_filtered)
        return 1

    reset_core_outputs(package_dir)
    prepare_package_dirs(package_dir)
    registry_path = package_dir / REGISTRY_SUBDIR / "symbol_registry.sqlite3"
    struct_registry_path = package_dir / REGISTRY_SUBDIR / "struct_registry.sqlite3"
    reset_registry_files(registry_path)
    reset_registry_files(struct_registry_path)

    llm = client_from_config(config)
    registry = NamingRegistry(registry_path)
    struct_registry = StructRegistry(struct_registry_path)

    try:
        total_usage, failed, skipped = run_reconstruction(
            binary_name=safe_dir_name(args.binary.name),
            package_dir=package_dir,
            contexts=contexts,
            registry=registry,
            struct_registry=struct_registry,
            llm=llm,
            structure_context=load_layer_context(config.context, "structure"),
            naming_context=load_layer_context(config.context, "naming"),
            console=console,
        )
        write_registry_exports(package_dir, registry)
        write_skipped_log(package_dir, skipped)
        apply_registry_and_export_sources(
            package_dir=package_dir,
            registry=registry,
            struct_registry=struct_registry,
            contexts=contexts,
            console=console,
        )
        total_usage.merge(
            run_agent_review(
                package_dir=package_dir,
                registry=registry,
                struct_registry=struct_registry,
                llm=llm,
                console=console,
            )
        )
    finally:
        registry.close()
        struct_registry.close()

    codeql_ok = create_codeql_database(package_dir=package_dir, codeql_exe=config.codeql_exe, console=console)

    ok = len(contexts) - len(failed) - len(skipped)
    print_step(console, "[green]Done[/green]")
    print_item(console, "raw funcs", len(raw_contexts))
    print_item(console, "runtime", runtime_filtered)
    print_item(console, "trivial", len(skipped))
    print_item(console, "functions", f"{ok} ok, {len(failed)} failed")
    print_item(console, "tokens", total_usage.format())
    print_item(console, "recon", package_dir / FUNCTIONS_SUBDIR)
    print_item(console, "registry", package_dir / REGISTRY_SUBDIR)
    print_item(console, "codeql src", package_dir / CODEQL_SUBDIR)
    print_item(console, "codeql db", package_dir / CODEQL_DB_SUBDIR)
    if failed:
        return 2
    return 0 if codeql_ok else 3


if __name__ == "__main__":
    raise SystemExit(main())
