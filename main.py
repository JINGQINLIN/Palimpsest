from __future__ import annotations

import argparse
import asyncio
import shutil
from pathlib import Path

import yaml
from rich.console import Console

from config import load_config
from pipeline.agent import run_agent_review
from pipeline.codeql import apply_registry_and_export_sources, create_codeql_database
from pipeline.console import make_progress, print_item, print_step
from pipeline.llm import LLMClient, TokenUsage
from pipeline.outputs import (
    prepare_package_dirs,
    reset_core_outputs,
    reset_registry_files,
    write_function_outputs,
    write_registry_exports,
)
from pipeline.paths import (
    CODEQL_DB_SUBDIR,
    CODEQL_SUBDIR,
    CONTEXTS_DIR,
    FUNCTIONS_SUBDIR,
    OUTPUT_DIR,
    RAW_PACKAGE_SUBDIR,
    REGISTRY_SUBDIR,
    safe_dir_name,
)
from pipeline.registry import NamingRegistry, StructRegistry
from pipeline.stages.ghidra import (
    FunctionContext,
    fetch as fetch_raw_package,
    load_ghidra_config,
    load_raw_package,
)
from pipeline.stages.reconstruct import prefetch, process_function

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Firmware semantic reconstruction pipeline")
    parser.add_argument("binary", type=Path, help="Firmware binary path")
    return parser.parse_args()


def package_dir_for(binary: Path) -> Path:
    return OUTPUT_DIR / safe_dir_name(binary.name)


def load_domain_context(name: str) -> str:
    path = CONTEXTS_DIR / f"{name}.yaml"
    if not path.exists():
        return ""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sections: list[str] = []
    if value := data.get("domain"):
        sections.append(f"## Domain\n{value}")
    if value := data.get("protocol"):
        sections.append(f"## Protocol Background\n{value.strip()}")
    if value := data.get("platform"):
        sections.append(f"## Platform Background\n{value.strip()}")
    return "\n\n".join(sections)


def filter_contexts(contexts: dict) -> dict:
    def is_runtime_stub(name: str) -> bool:
        return name == "_start" or name.startswith(("_INIT", "_FINI", "_DT_INIT", "_DT_FINI"))

    return {
        addr: ctx
        for addr, ctx in contexts.items()
        if not is_runtime_stub(ctx.ghidra_name)
    }


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


def reconstruct_function(
    *,
    binary_name: str,
    package_dir: Path,
    ctx: FunctionContext,
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm: LLMClient,
    domain_context: str,
) -> TokenUsage:
    known_symbols, unknown_symbols = prefetch(ctx.code, registry)
    artifacts = process_function(
        binary_name=binary_name,
        address=int(ctx.address, 16),
        ghidra_name=ctx.ghidra_name,
        raw_decompile=ctx.code,
        known_symbols=known_symbols,
        unknown_symbols=unknown_symbols,
        registry=registry,
        struct_registry=struct_registry,
        llm=llm,
        domain_context=domain_context,
    )
    func_dir = package_dir / FUNCTIONS_SUBDIR / f"0x{ctx.address}"
    write_function_outputs(func_dir, artifacts)
    return artifacts.get("usage") or TokenUsage()


def run_reconstruction(
    *,
    binary_name: str,
    package_dir: Path,
    contexts: dict,
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm: LLMClient,
    domain_context: str,
) -> tuple[TokenUsage, list[tuple[str, str]]]:
    print_step(console, "2. Semantic reconstruction")
    print_item(console, "functions", len(contexts))
    print_item(console, "model", llm.model)
    print_item(console, "output", package_dir)
    console.print()

    total_usage = TokenUsage()
    failed: list[tuple[str, str]] = []

    with make_progress(console) as progress:
        task = progress.add_task("reconstructing", total=len(contexts))
        for addr_hex, ctx in sorted(contexts.items()):
            progress.update(task, description=f"0x{addr_hex}  {ctx.ghidra_name}")
            try:
                usage = reconstruct_function(
                    binary_name=binary_name,
                    package_dir=package_dir,
                    ctx=ctx,
                    registry=registry,
                    struct_registry=struct_registry,
                    llm=llm,
                    domain_context=domain_context,
                )
                total_usage.merge(usage)
            except Exception as exc:
                failed.append((addr_hex, str(exc)))
                console.print(f"  [red]failed[/red] 0x{addr_hex}: {exc}")
            progress.advance(task)

    return total_usage, failed


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
    contexts = filter_contexts(raw_contexts)
    skipped = len(raw_contexts) - len(contexts)
    if not contexts:
        console.print("[red]error:[/red] no analyzable functions after filtering")
        print_item(console, "raw funcs", len(raw_contexts))
        print_item(console, "skipped", skipped)
        return 1

    reset_core_outputs(package_dir)
    prepare_package_dirs(package_dir)
    registry_path = package_dir / REGISTRY_SUBDIR / "symbol_registry.sqlite3"
    struct_registry_path = package_dir / REGISTRY_SUBDIR / "struct_registry.sqlite3"
    reset_registry_files(registry_path)
    reset_registry_files(struct_registry_path)

    llm = LLMClient(
        api_key=config.anthropic_api_key,
        base_url=config.anthropic_base_url,
        model=config.reconstruction_model,
        timeout=config.llm_timeout_seconds,
    )
    registry = NamingRegistry(registry_path)
    struct_registry = StructRegistry(struct_registry_path)

    try:
        total_usage, failed = run_reconstruction(
            binary_name=safe_dir_name(args.binary.name),
            package_dir=package_dir,
            contexts=contexts,
            registry=registry,
            struct_registry=struct_registry,
            llm=llm,
            domain_context=load_domain_context(config.context),
        )
        write_registry_exports(package_dir, registry)
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

    ok = len(contexts) - len(failed)
    print_step(console, "[green]Done[/green]")
    print_item(console, "raw funcs", len(raw_contexts))
    print_item(console, "skipped", skipped)
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
