"""Ghidra export stage / Ghidra 导出阶段。

Drives pyghidra-mcp (Ghidra Headless) to decompile every function and dumps the
raw pseudo-C as per-function JSON. By design it exports ONLY decompiled code,
not the Data Type Manager: struct layouts are re-inferred later by the LLM
(structure phase) instead of trusting Ghidra's often-incomplete type database.

驱动 pyghidra-mcp 反编译全部函数并按函数导出原始伪 C（JSON）。设计上仅导出
反编译代码、不导出 Data Type Manager——结构体布局改由 LLM structure 阶段推断，
而非依赖 Ghidra 往往不完整的类型库。
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from config import ghidra_settings, load_config
from pipeline.addresses import normalize_address
from pipeline.console import make_progress, print_item, print_step

console = Console()


@dataclass
class FunctionContext:
    address: str
    ghidra_name: str
    code: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {"address": self.address, "ghidra_name": self.ghidra_name, "code": self.code},
            ensure_ascii=False,
            indent=2,
        )

    @classmethod
    def from_json(cls, text: str) -> "FunctionContext":
        data = json.loads(text)
        return cls(
            address=normalize_address(data.get("address")),
            ghidra_name=str(data.get("ghidra_name") or ""),
            code=str(data.get("code") or ""),
        )


def load_raw_package(raw_dir: Path) -> dict[str, FunctionContext]:
    if not raw_dir.is_dir():
        raise FileNotFoundError(f"raw package not found: {raw_dir}")

    contexts: dict[str, FunctionContext] = {}
    for path in sorted(raw_dir.glob("*.json")):
        ctx = FunctionContext.from_json(path.read_text(encoding="utf-8"))
        if ctx.address:
            contexts[ctx.address] = ctx

    if not contexts:
        raise RuntimeError(f"no *.json files found in raw package: {raw_dir}")
    return contexts


def filter_runtime_contexts(contexts: dict[str, FunctionContext]) -> dict[str, FunctionContext]:
    def is_runtime_stub(name: str) -> bool:
        return name == "_start" or name.startswith(("_INIT", "_FINI", "_DT_INIT", "_DT_FINI"))

    return {
        addr: ctx
        for addr, ctx in contexts.items()
        if not is_runtime_stub(ctx.ghidra_name)
    }


def load_ghidra_config() -> tuple[str, str]:
    return ghidra_settings(load_config())


def _normalize_code(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


async def _call(session, tool: str, **args) -> dict:
    result = await session.call_tool(tool, args)
    text = "".join(item.text for item in result.content if hasattr(item, "text") and item.text)
    if getattr(result, "isError", False):
        raise RuntimeError(f"{tool} error: {text[:300] or '(empty)'}")
    if not text.strip():
        raise RuntimeError(f"{tool} returned empty content")
    return json.loads(text)


async def _wait_until_ready(session, binary: str, timeout: float = 300.0) -> None:
    waited = 0.0
    while waited < timeout:
        programs = (await _call(session, "list_project_binaries")).get("programs") or []
        ready = any(
            item.get("name", "").lstrip("/") == binary and item.get("analysis_complete")
            for item in programs
        )
        if ready:
            return
        await asyncio.sleep(3.0)
        waited += 3.0
    raise TimeoutError(f"Ghidra analysis not complete within {timeout}s")


async def _list_functions(session, binary: str) -> list[dict]:
    functions: list[dict] = []
    seen: set[str] = set()
    offset = 0
    page_size = 500

    while True:
        data = await _call(
            session,
            "search_symbols_by_name",
            binary_name=binary,
            query=".",
            functions_only=True,
            offset=offset,
            limit=page_size,
        )
        symbols = data.get("symbols") or []
        if not symbols:
            break

        for item in symbols:
            if item.get("external") or item.get("is_thunk"):
                continue
            addr = normalize_address(item.get("address"))
            if not addr or addr in seen:
                continue
            seen.add(addr)
            functions.append({"address": addr, "name": item.get("name") or f"FUN_{addr}"})

        if len(symbols) < page_size:
            break
        offset += page_size

    return functions


async def fetch(binary_path: Path, output_dir: Path, ghidra_dir: str, mcp_exe: str) -> int:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    print_step(console, "Ghidra fetch")
    print_item(console, "binary", binary_path)
    print_item(console, "output", output_dir)

    params = StdioServerParameters(
        command=mcp_exe,
        args=["--wait-for-analysis", str(binary_path)],
        env={"GHIDRA_INSTALL_DIR": ghidra_dir},
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            programs = (await _call(session, "list_project_binaries")).get("programs") or []
            if not programs:
                raise RuntimeError("pyghidra-mcp has no loaded binaries")

            binary = programs[0]["name"].lstrip("/")
            print_item(console, "program", binary)
            print_item(console, "status", "waiting for analysis")
            await _wait_until_ready(session, binary)

            functions = await _list_functions(session, binary)
            print_item(console, "functions", len(functions))

            output_dir.mkdir(parents=True, exist_ok=True)
            ok = 0
            failed = []

            with make_progress(console) as progress:
                task = progress.add_task("fetching...", total=len(functions))
                for func in functions:
                    addr = func["address"]
                    progress.update(task, description=f"0x{addr}  {func['name']}")
                    try:
                        ghidra_addr = "0x" + (addr.lstrip("0") or "0")
                        data = await _call(
                            session,
                            "decompile_function",
                            binary_name=binary,
                            name_or_address=ghidra_addr,
                        )
                        code = _normalize_code(data.get("code") or "")
                        if code:
                            ctx = FunctionContext(address=addr, ghidra_name=func["name"], code=code)
                            (output_dir / f"{addr}.json").write_text(ctx.to_json(), encoding="utf-8")
                            ok += 1
                    except Exception as exc:
                        failed.append((addr, str(exc)))
                        console.print(f"  [red]failed[/red] 0x{addr}: {exc}")
                    progress.advance(task)

    print_step(console, "[green]Ghidra fetch done[/green]")
    print_item(console, "functions", f"{ok} ok, {len(failed)} failed")
    print_item(console, "output", output_dir)
    return 0 if not failed else 2
