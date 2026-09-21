from __future__ import annotations

import argparse
import asyncio
import os
import json
import shutil
from dataclasses import replace
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
from pipeline.prompts import language_directive, load_layer_context
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
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Override output directory (default: output/<binary-name>)")
    parser.add_argument("--config", type=Path, default=None,
                        help="Override config file (default: local_config.yaml)")
    parser.add_argument(
        "--skip-codeql-build",
        action="store_true",
        help="Skip package-side CodeQL database creation (Claris builds the DB from codeql/src).",
    )
    parser.add_argument(
        "--pin-raw-from",
        type=Path,
        default=None,
        help="Copy this raw package instead of re-exporting via Ghidra (experiment parity pin).",
    )
    parser.add_argument(
        "--reconstruction-workers",
        type=int,
        default=None,
        help="Override ABLATION.reconstruction_workers for this run.",
    )
    return parser.parse_args()


def package_dir_for(binary: Path, override: Path | None = None) -> Path:
    if override is not None:
        return override
    return OUTPUT_DIR / safe_dir_name(binary.name)


def ensure_raw_package(
    binary: Path,
    raw_dir: Path,
    config,
    *,
    pin_raw_from: Path | None = None,
) -> bool:
    print_step(console, "1. Raw package")
    print_item(console, "binary", binary)
    print_item(console, "raw", raw_dir)
    if raw_dir.is_dir():
        shutil.rmtree(raw_dir)

    if pin_raw_from is not None:
        pin = pin_raw_from.resolve()
        if not pin.is_dir():
            console.print(f"[red]error:[/red] --pin-raw-from is not a directory: {pin}")
            return False
        print_item(console, "pin-raw-from", pin)
        shutil.copytree(pin, raw_dir)
        return True

    try:
        ghidra_dir, mcp_exe = load_ghidra_config(config)
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
            console=console,
        )
    )
    return rc == 0


def _load_and_filter_contexts(raw_dir: Path) -> tuple[dict, int, int]:
    raw_contexts = load_raw_package(raw_dir)
    contexts = filter_runtime_contexts(raw_contexts)
    raw_count = len(raw_contexts)
    runtime_filtered = raw_count - len(contexts)
    return contexts, raw_count, runtime_filtered


def _setup_outputs_and_registries(
    package_dir: Path,
) -> tuple[Path, Path]:
    reset_core_outputs(package_dir)
    prepare_package_dirs(package_dir)
    registry_path = package_dir / REGISTRY_SUBDIR / "symbol_registry.sqlite3"
    struct_registry_path = package_dir / REGISTRY_SUBDIR / "struct_registry.sqlite3"
    reset_registry_files(registry_path)
    reset_registry_files(struct_registry_path)
    return registry_path, struct_registry_path


def _print_ablation_toggles(ablation) -> None:
    if not ablation.active:
        return
    print_step(console, "[yellow]Ablation[/yellow]")
    for key, value in ablation.__dict__.items():
        if value:
            print_item(console, key, "ON")


def _copy_raw_code_as_is(contexts: dict, package_dir: Path) -> None:
    print_item(console, "reconstruction",
               "[yellow]skipped (both structure and naming disabled)[/yellow]")
    for addr_hex, ctx in contexts.items():
        func_dir = package_dir / FUNCTIONS_SUBDIR / f"0x{addr_hex}"
        func_dir.mkdir(parents=True, exist_ok=True)
        (func_dir / "raw.c").write_text(ctx.code, encoding="utf-8")
        (func_dir / "structured.c").write_text(ctx.code, encoding="utf-8")
        (func_dir / "named.c").write_text(ctx.code, encoding="utf-8")


def _run_pipeline_body(
    *,
    binary_name: str,
    package_dir: Path,
    contexts: dict,
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm,
    structure_ctx: str,
    naming_ctx: str,
    lang_directive: str,
    ablation,
    console: Console,
) -> tuple[TokenUsage, list, list]:
    total_usage = TokenUsage()
    failed: list[tuple[str, str]] = []
    skipped: list[tuple[str, str, str]] = []

    if ablation.skip_structure and ablation.skip_naming:
        _copy_raw_code_as_is(contexts, package_dir)
    else:
        total_usage, failed, skipped = run_reconstruction(
            binary_name=binary_name,
            package_dir=package_dir,
            contexts=contexts,
            registry=registry,
            struct_registry=struct_registry,
            llm=llm,
            structure_context=structure_ctx,
            naming_context=naming_ctx,
            language_directive=lang_directive,
            console=console,
            ablation=ablation,
        )

    # Strict experiment invariant: every selected binary function must have a
    # real Palimpsest result.  Do not build a mixed or partial repository.
    produced = sum(
        1
        for path in (package_dir / FUNCTIONS_SUBDIR).glob("0x*/named.c")
        if path.is_file()
    )
    if failed or skipped or produced != len(contexts):
        write_registry_exports(package_dir, registry)
        write_skipped_log(package_dir, skipped)
        return total_usage, failed, skipped

    write_registry_exports(package_dir, registry)
    write_skipped_log(package_dir, skipped)
    apply_registry_and_export_sources(
        package_dir=package_dir,
        registry=registry,
        struct_registry=struct_registry,
        contexts=contexts,
        console=console,
    )

    if not ablation.skip_agent_review:
        total_usage.merge(
            run_agent_review(
                package_dir=package_dir,
                registry=registry,
                struct_registry=struct_registry,
                llm=llm,
                language_directive=lang_directive,
                console=console,
                enable_prescan=getattr(ablation, "enable_prescan", False),
                enable_multi_agent=getattr(ablation, "enable_multi_agent", False),
            )
        )
    else:
        print_item(console, "agent review", "[yellow]skipped[/yellow]")

    return total_usage, failed, skipped


def _print_final_summary(
    console: Console,
    raw_count: int,
    runtime_filtered: int,
    contexts: dict,
    skipped: list,
    failed: list,
    total_usage: TokenUsage,
    package_dir: Path,
    ablation,
) -> None:
    produced = sum(
        1
        for path in (package_dir / FUNCTIONS_SUBDIR).glob("0x*/named.c")
        if path.is_file()
    )
    failed_functions = sum(1 for address, _ in failed if address != "package")
    not_run = max(0, len(contexts) - produced - failed_functions - len(skipped))
    print_step(console, "[green]Done[/green]")
    print_item(console, "raw funcs", raw_count)
    print_item(console, "runtime", runtime_filtered)
    print_item(console, "trivial", len(skipped))
    print_item(
        console,
        "functions",
        f"{produced}/{len(contexts)} produced, {failed_functions} failed, {not_run} not run",
    )
    print_item(console, "tokens", total_usage.format())
    print_item(console, "recon", package_dir / FUNCTIONS_SUBDIR)
    print_item(console, "registry", package_dir / REGISTRY_SUBDIR)
    print_item(console, "codeql src", package_dir / CODEQL_SUBDIR)
    if not ablation.skip_codeql_build:
        print_item(console, "codeql db", package_dir / CODEQL_DB_SUBDIR)


def _write_completeness_manifest(
    package_dir: Path,
    *,
    selected: int,
    failed: list,
    skipped: list,
    codeql_ok: bool,
    codeql_database_created: bool | None = None,
) -> None:
    produced = sum(
        1
        for path in (package_dir / FUNCTIONS_SUBDIR).glob("0x*/named.c")
        if path.is_file()
    )
    created = codeql_ok if codeql_database_created is None else codeql_database_created
    payload = {
        "selected_functions": selected,
        "produced_functions": produced,
        "failed_count": len(failed),
        "skip_count": len(skipped),
        "failed": [{"address": addr, "error": error} for addr, error in failed],
        "skipped": [
            {"address": addr, "name": name, "reason": reason}
            for addr, name, reason in skipped
        ],
        "codeql_database_created": created,
        "full_success": produced == selected and not failed and not skipped and codeql_ok,
    }
    path = package_dir / "reconstruction" / "completeness_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()

    try:
        config = load_config(args.config) if args.config else load_config()
    except RuntimeError as exc:
        console.print(f"[red]error:[/red] {exc}")
        print_item(console, "hint", "copy local_config.example.yaml to local_config.yaml")
        return 1

    if args.skip_codeql_build and not config.ablation.skip_codeql_build:
        config = replace(
            config,
            ablation=replace(config.ablation, skip_codeql_build=True),
        )
    if args.reconstruction_workers is not None:
        if args.reconstruction_workers < 1:
            console.print("[red]error:[/red] --reconstruction-workers must be >= 1")
            return 1
        config = replace(
            config,
            ablation=replace(
                config.ablation,
                reconstruction_workers=args.reconstruction_workers,
            ),
        )

    package_dir = package_dir_for(args.binary, args.output_dir)
    raw_dir = package_dir / RAW_PACKAGE_SUBDIR
    if not ensure_raw_package(args.binary, raw_dir, config, pin_raw_from=args.pin_raw_from):
        return 1

    try:
        contexts, raw_count, runtime_filtered = _load_and_filter_contexts(raw_dir)
    except Exception as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 1

    if not contexts:
        console.print("[red]error:[/red] no analyzable functions after filtering")
        print_item(console, "raw funcs", raw_count)
        print_item(console, "runtime", runtime_filtered)
        return 1

    binary_name = safe_dir_name(args.binary.name)
    registry_path, struct_registry_path = _setup_outputs_and_registries(package_dir)

    llm = client_from_config(config)
    registry = NamingRegistry(registry_path)
    struct_registry = StructRegistry(struct_registry_path)
    lang_directive = language_directive(config.language)
    ablation = config.ablation

    structure_ctx = "" if ablation.disable_domain_context else load_layer_context(config.context, "structure")
    naming_ctx = "" if ablation.disable_domain_context else load_layer_context(config.context, "naming")

    _print_ablation_toggles(ablation)

    try:
        total_usage, failed, skipped = _run_pipeline_body(
            binary_name=binary_name,
            package_dir=package_dir,
            contexts=contexts,
            registry=registry,
            struct_registry=struct_registry,
            llm=llm,
            structure_ctx=structure_ctx,
            naming_ctx=naming_ctx,
            lang_directive=lang_directive,
            ablation=ablation,
            console=console,
        )
    finally:
        registry.close()
        struct_registry.close()

    if failed or skipped:
        _write_completeness_manifest(
            package_dir,
            selected=len(contexts),
            failed=failed,
            skipped=skipped,
            codeql_ok=False,
        )
        _print_final_summary(
            console, raw_count, runtime_filtered, contexts,
            skipped, failed, total_usage, package_dir, ablation,
        )
        console.print("[red]STRICT INPUT FAILURE:[/red] partial Palimpsest output rejected")
        return 2

    if not ablation.skip_codeql_build:
        codeql_created = create_codeql_database(
            package_dir=package_dir, codeql_exe=config.codeql_exe, console=console
        )
        codeql_ok = codeql_created
    else:
        print_item(console, "codeql build", "[yellow]skipped[/yellow] (Claris builds DB)")
        codeql_created = False
        codeql_ok = True

    _write_completeness_manifest(
        package_dir,
        selected=len(contexts),
        failed=failed,
        skipped=skipped,
        codeql_ok=codeql_ok,
        codeql_database_created=codeql_created,
    )

    _print_final_summary(
        console, raw_count, runtime_filtered, contexts,
        skipped, failed, total_usage, package_dir, ablation,
    )

    if failed:
        return 2
    return 0 if codeql_ok else 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        # Worker threads may be blocked in HTTP calls. A hard exit is safe for
        # experiment integrity because partial packages are always rejected and
        # fully reset on the next run.
        console.print("\n[yellow]Interrupted; partial package rejected.[/yellow]")
        os._exit(130)
