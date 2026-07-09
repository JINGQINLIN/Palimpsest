from __future__ import annotations

import re
from pathlib import Path

from pipeline.paths import (
    GLOBALS_HEADER_FILENAME,
    MACROS_HEADER_FILENAME,
    STUB_HEADER_FILENAME,
    TYPES_HEADER_FILENAME,
)

_TYPE_SIZE = {
    "char": 1, "uchar": 1, "byte": 1, "bool": 1, "_BYTE": 1,
    "undefined": 1, "undefined1": 1, "int8_t": 1, "uint8_t": 1,
    "short": 2, "ushort": 2, "word": 2, "_WORD": 2,
    "undefined2": 2, "int16_t": 2, "uint16_t": 2,
    "int": 4, "uint": 4, "long": 4, "ulong": 4, "float": 4, "dword": 4, "_DWORD": 4,
    "undefined4": 4, "int32_t": 4, "uint32_t": 4, "code": 4,
    "longlong": 8, "ulonglong": 8, "double": 8, "qword": 8, "_QWORD": 8,
    "undefined8": 8, "int64_t": 8, "uint64_t": 8,
}

_ARRAY_RE = re.compile(r"^(.*?)\s*\[\s*(\d+)\s*\]$")


def _sizeof(type_str: str) -> int | None:
    type_str = type_str.strip()
    array = _ARRAY_RE.match(type_str)
    if array:
        elem = _sizeof(array.group(1))
        return elem * int(array.group(2)) if elem is not None else None
    if "(*)" in type_str or type_str.endswith("*"):
        return 4
    return _TYPE_SIZE.get(type_str.rstrip())


def _field_decl(type_str: str, name: str) -> str:
    type_str = type_str.strip()
    if "(*)" in type_str:
        return type_str.replace("(*)", f"(*{name})", 1)
    array = _ARRAY_RE.match(type_str)
    if array:
        return f"{array.group(1).strip()} {name}[{array.group(2)}]"
    if type_str.endswith("[]"):
        return f"{type_str[:-2].strip()} {name}[1]"
    return f"{type_str} {name}"


def _value_struct_deps(entry: dict) -> set[str]:
    deps: set[str] = set()
    for field in entry.get("fields", []):
        type_str = field["type"].strip()
        array = _ARRAY_RE.match(type_str)
        if array:
            type_str = array.group(1).strip()
        if type_str.endswith("*"):
            continue
        match = re.fullmatch(r"struct\s+(\w+)", type_str)
        if match:
            deps.add(match.group(1))
    return deps


def _topo_order(structs: dict[str, dict]) -> list[str]:
    order: list[str] = []
    seen: set[str] = set()

    def visit(name: str, stack: set[str]) -> None:
        if name in seen or name not in structs or name in stack:
            return
        stack.add(name)
        for dep in sorted(_value_struct_deps(structs[name])):
            visit(dep, stack)
        stack.discard(name)
        seen.add(name)
        order.append(name)

    for name in sorted(structs):
        visit(name, set())
    return order


def _render_struct(name: str, entry: dict) -> str:
    # Offset-anchored 渲染：按字段偏移逐个放置，字段间空隙用 _padN 填充以精确复现
    # 内存布局；若偏移回退（字段重叠）则插入 WARNING 注释而非静默丢弃。
    fields = entry.get("fields") or []
    lines = [f"struct {name} {{"]
    cursor = 0
    pad = 0
    for field in fields:
        offset = field["offset"]
        if offset > cursor:
            lines.append(f"    unsigned char _pad{pad}[{offset - cursor}];")
            pad += 1
            cursor = offset
        elif offset < cursor:
            lines.append(f"    /* WARNING: field {field['name']} at offset 0x{offset:x} overlaps the previous field (cursor 0x{cursor:x}); review manually */")
            cursor = offset
        lines.append(f"    {_field_decl(field['type'], field['name'])};  /* +0x{offset:x} */")
        size = field.get("size") or _sizeof(field["type"]) or 0
        cursor = offset + size
    total = entry.get("size") or 0
    if total > cursor:
        lines.append(f"    unsigned char _pad_end[{total - cursor}];")
    lines.append("};")
    return "\n".join(lines)


def render_types_header(structs: dict[str, dict]) -> str:
    body = [
        "#ifndef RECOPILOT_TYPES_H",
        "#define RECOPILOT_TYPES_H",
        "",
        f'#include "{STUB_HEADER_FILENAME}"',
        f'#include "{MACROS_HEADER_FILENAME}"',
        "",
        "/* Auto-generated from StructRegistry; offset-anchored, padding reproduces the layout. */",
        "",
    ]
    if not structs:
        body.append("/* (no reconstructed structs yet) */")
    else:
        for name in sorted(structs):
            body.append(f"struct {name};")
        body.append("")
        for name in _topo_order(structs):
            body.append(_render_struct(name, structs[name]))
            body.append("")
    body += [f'#include "{GLOBALS_HEADER_FILENAME}"', "", "#endif /* RECOPILOT_TYPES_H */", ""]
    return "\n".join(body)


def _write_header(codeql_dir: Path, filename: str, content: str) -> Path:
    codeql_dir.mkdir(parents=True, exist_ok=True)
    path = codeql_dir / filename
    path.write_text(content, encoding="utf-8")
    return path


def write_types_header(codeql_dir: Path, structs: dict[str, dict]) -> Path:
    return _write_header(codeql_dir, TYPES_HEADER_FILENAME, render_types_header(structs))


def render_macros_header(entries: dict[str, dict]) -> str:
    body = ["#ifndef RECOPILOT_MACROS_H", "#define RECOPILOT_MACROS_H", ""]
    constants = sorted(
        (e for e in entries.values() if e["kind"] == "constant" and e.get("value")),
        key=lambda e: e["canonical_name"],
    )
    if not constants:
        body.append("/* No constants reconstructed yet. */")
    else:
        body.append("/* Auto-generated from NamingRegistry (kind=constant). */")
        body.append("")
        seen: set[str] = set()
        for entry in constants:
            name = entry["canonical_name"]
            if name in seen:
                continue
            seen.add(name)
            body.append(f"#define {name} {entry['value']}")
    body += ["", "#endif /* RECOPILOT_MACROS_H */", ""]
    return "\n".join(body)


def write_macros_header(codeql_dir: Path, entries: dict[str, dict]) -> Path:
    return _write_header(codeql_dir, MACROS_HEADER_FILENAME, render_macros_header(entries))


def render_globals_header(entries: dict[str, dict]) -> str:
    body = ["#ifndef RECOPILOT_GLOBALS_H", "#define RECOPILOT_GLOBALS_H", ""]
    globals_ = sorted(
        (e for e in entries.values() if e["kind"] == "global_var"),
        key=lambda e: e["canonical_name"],
    )
    if not globals_:
        body.append("/* No globals reconstructed yet. */")
    else:
        body.append("/* Auto-generated from NamingRegistry (kind=global_var). */")
        body.append("")
        for entry in globals_:
            type_str = entry.get("inferred_type") or "uint32_t"
            trailer = "" if entry.get("inferred_type") else "  /* type unknown */"
            body.append(f"extern {type_str} {entry['canonical_name']};{trailer}")
    body += ["", "#endif /* RECOPILOT_GLOBALS_H */", ""]
    return "\n".join(body)


def write_globals_header(codeql_dir: Path, entries: dict[str, dict]) -> Path:
    return _write_header(codeql_dir, GLOBALS_HEADER_FILENAME, render_globals_header(entries))
