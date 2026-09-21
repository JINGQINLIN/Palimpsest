from __future__ import annotations

from pathlib import Path

import yaml

from pipeline.paths import CONTEXTS_DIR


def _format_layouts(layouts: dict) -> str:
    if not layouts:
        return ""
    lines = [
        "## Known Layouts",
        "When offsets match, use these field names in struct_updates and field access — not opaque padding.",
    ]
    for name, entry in layouts.items():
        if not isinstance(entry, dict):
            continue
        struct_name = entry.get("struct") or name
        size = entry.get("size")
        header = f"### {name} (struct {struct_name}"
        if size is not None:
            header += f", size {size}"
        header += ")"
        lines.append(header)
        for field in entry.get("fields") or []:
            if not isinstance(field, dict):
                continue
            offset = field.get("offset")
            fname = field.get("name", "")
            ftype = field.get("type", "")
            try:
                off_text = f"+0x{int(offset):x}"
            except (TypeError, ValueError):
                off_text = str(offset)
            lines.append(f"  {off_text} {fname} {ftype}".rstrip())
    return "\n".join(lines)


def _format_distortions(items: list, layer: str) -> str:
    if not items:
        return ""
    picked = [
        item
        for item in items
        if isinstance(item, dict) and (item.get("layer") or "structure") == layer
    ]
    if not picked:
        return ""

    lines = ["## Firmware Decompilation Distortions", f"Apply fixes for {layer} pass:"]
    for item in picked:
        item_id = item.get("id", "")
        pattern = (item.get("pattern") or "").strip()
        fix = (item.get("fix") or "").strip()
        example = (item.get("example") or "").strip()
        title = f"### {item_id}" if item_id else "### Distortion"
        lines.append(title)
        if pattern:
            lines.append(f"Pattern: {pattern}")
        if fix:
            lines.append(f"Fix: {fix}")
        if example:
            lines.append(example)
    return "\n".join(lines)


def load_layer_context(name: str, layer: str) -> str:
    path = CONTEXTS_DIR / f"{name}.yaml"
    if not path.is_file():
        return ""

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sections: list[str] = []

    if value := data.get("domain"):
        sections.append(f"## Domain\n{value}")
    if value := data.get("protocol"):
        sections.append(f"## Protocol Background\n{value.strip()}")
    if value := data.get("platform"):
        sections.append(f"## Platform Background\n{value.strip()}")

    if layer == "structure":
        if block := _format_layouts(data.get("layouts") or {}):
            sections.append(block)
    if block := _format_distortions(data.get("distortions") or [], layer):
        sections.append(block)

    return "\n\n".join(sections)


_LANGUAGE_NAMES = {"en": "English", "zh": "Chinese (中文)"}


def language_directive(language: str) -> str:
    name = _LANGUAGE_NAMES.get(language.lower(), language)
    return (
        f"Write all explanatory prose — evidence text, naming-map notes, and summaries — in {name}. "
        "Code, identifiers, canonical names, struct and field names, and JSON keys must stay in "
        "English ASCII regardless."
    )
