from pipeline.registry.header import (
    write_globals_header,
    write_macros_header,
    write_types_header,
)
from pipeline.registry.naming import (
    PLACEHOLDER_RE,
    VALID_KINDS,
    NamingRegistry,
)
from pipeline.registry.structs import (
    StructRegistry,
    normalize_offset_field_name,
    normalize_offset_field_names,
    normalize_fields,
)
from pipeline.registry.coherence import (
    FieldCoherenceReport,
    check_field_coherence,
    format_coherence_violations,
)

__all__ = [
    "PLACEHOLDER_RE",
    "VALID_KINDS",
    "NamingRegistry",
    "StructRegistry",
    "FieldCoherenceReport",
    "check_field_coherence",
    "format_coherence_violations",
    "format_struct_field",
    "format_struct_summary",
    "normalize_offset_field_name",
    "normalize_offset_field_names",
    "normalize_fields",
    "write_globals_header",
    "write_macros_header",
    "write_types_header",
]


def format_struct_field(field: dict) -> str:
    """Format a struct field as a one-line summary.

    Example: ``{"offset": 8, "name": "size", "type": "uint32_t"}`` -> ``"+0x8 size uint32_t"``
    """
    return f"+0x{field['offset']:x} {field['name']} {field['type']}"


def format_struct_summary(name: str, entry: dict) -> str:
    """Format a struct as a one-line summary.

    Example: ``struct point (size 0x8): +0x0 x int; +0x4 y int``
    """
    fields = "; ".join(format_struct_field(f) for f in entry.get("fields", []))
    return f"struct {name} (size 0x{entry.get('size', 0):x}): {fields}"
