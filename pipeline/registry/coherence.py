"""Struct field coherence: typed `->` / `.` accesses must exist on the declared type.

Generic quality gate for structure recovery — not tied to any downstream analyzer
or vulnerability class. Prefer raw / less-typed code over incoherent field access.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from pipeline.registry.structs import normalize_fields

_IDENT = r"[A-Za-z_]\w*"
_STRUCT_PTR_DECL_RE = re.compile(
    rf"\bstruct\s+({_IDENT})\s*\*+\s*({_IDENT})\b"
)
_STRUCT_VAL_DECL_RE = re.compile(
    rf"\bstruct\s+({_IDENT})\s+({_IDENT})\b(?!\s*\*)"
)
_ARROW_RE = re.compile(rf"\b({_IDENT})\s*->\s*({_IDENT})\b")
_DOT_RE = re.compile(rf"\b({_IDENT})\s*\.\s*({_IDENT})\b")
_ASSIGN_RE = re.compile(rf"\b({_IDENT})\s*=\s*({_IDENT})\s*;")
_CAST_ASSIGN_RE = re.compile(
    rf"\b({_IDENT})\s*=\s*\(\s*struct\s+({_IDENT})\s*\*+\s*\)"
)
_STRUCT_IN_TYPE_RE = re.compile(rf"\bstruct\s+({_IDENT})\b")
_PARAM_SPLIT_RE = re.compile(r",(?![^()]*\))")


@dataclass
class FieldViolation:
    base: str
    field: str
    struct_name: str
    line: int
    snippet: str


@dataclass
class FieldCoherenceReport:
    violations: list[FieldViolation] = field(default_factory=list)
    checked_accesses: int = 0
    unbound_accesses: int = 0

    @property
    def ok(self) -> bool:
        return not self.violations

    def summary(self) -> str:
        if self.ok:
            return (
                f"ok: checked={self.checked_accesses} "
                f"unbound={self.unbound_accesses}"
            )
        parts = [
            f"{v.struct_name}.{v.field} via {v.base} (L{v.line})"
            for v in self.violations[:8]
        ]
        more = "" if len(self.violations) <= 8 else f" (+{len(self.violations) - 8})"
        return f"FAIL {len(self.violations)}: " + "; ".join(parts) + more


def _field_names(entry: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for item in entry.get("fields") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name and not name.startswith("_pad"):
            names.add(name)
    return names


def _struct_maps(
    structs: dict[str, dict[str, Any]],
) -> tuple[dict[str, set[str]], dict[str, str | None]]:
    """Return (struct -> fields, struct -> field -> pointee struct name)."""
    fields_by_struct: dict[str, set[str]] = {}
    pointee_by_struct_field: dict[str, str | None] = {}
    for name, entry in structs.items():
        fields_by_struct[name] = _field_names(entry)
        for item in entry.get("fields") or []:
            if not isinstance(item, dict):
                continue
            fname = str(item.get("name") or "").strip()
            if not fname:
                continue
            type_text = str(item.get("type") or "")
            m = _STRUCT_IN_TYPE_RE.search(type_text)
            pointee_by_struct_field[f"{name}.{fname}"] = m.group(1) if m else None
    return fields_by_struct, pointee_by_struct_field


def _strip_comments_and_strings(text: str) -> str:
    """Rough scrub so string literals / comments do not fake field accesses."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//.*?$", " ", text, flags=re.M)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    return text


def _parse_signature_bindings(code: str) -> dict[str, str]:
    """Map parameter names to struct type names from the function signature."""
    bindings: dict[str, str] = {}
    # First '{' starts the body; signature is before it.
    brace = code.find("{")
    head = code[: brace if brace >= 0 else len(code)]
    paren_l = head.find("(")
    paren_r = head.rfind(")")
    if paren_l < 0 or paren_r <= paren_l:
        return bindings
    params = head[paren_l + 1 : paren_r]
    for chunk in _PARAM_SPLIT_RE.split(params):
        chunk = chunk.strip()
        if not chunk or chunk == "void":
            continue
        m = re.search(rf"\bstruct\s+({_IDENT})\s*\*+\s*({_IDENT})\s*$", chunk)
        if m:
            bindings[m.group(2)] = m.group(1)
            continue
        m = re.search(rf"\bstruct\s+({_IDENT})\s+({_IDENT})\s*$", chunk)
        if m:
            bindings[m.group(2)] = m.group(1)
    return bindings


def _parse_local_bindings(body: str) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for m in _STRUCT_PTR_DECL_RE.finditer(body):
        bindings[m.group(2)] = m.group(1)
    for m in _STRUCT_VAL_DECL_RE.finditer(body):
        # Avoid matching `struct Foo *` already handled; VAL decl excludes *
        bindings[m.group(2)] = m.group(1)
    for m in _CAST_ASSIGN_RE.finditer(body):
        bindings[m.group(1)] = m.group(2)
    return bindings


def _propagate_assignments(body: str, bindings: dict[str, str]) -> dict[str, str]:
    """Copy struct types across simple `a = b;` when b is bound."""
    changed = True
    while changed:
        changed = False
        for m in _ASSIGN_RE.finditer(body):
            lhs, rhs = m.group(1), m.group(2)
            if rhs in bindings and lhs not in bindings:
                bindings[lhs] = bindings[rhs]
                changed = True
            elif rhs in bindings and lhs in bindings and bindings[lhs] != bindings[rhs]:
                # Prefer RHS after assignment (rebind)
                bindings[lhs] = bindings[rhs]
    return bindings


def check_field_coherence(
    code: str,
    structs: dict[str, dict[str, Any]] | None,
    *,
    extra_structs: Iterable[dict[str, Any]] | None = None,
) -> FieldCoherenceReport:
    """Check that every bound `base->field` / `base.field` exists on that struct.

    Unbound bases (no declared struct type) are counted but do not fail — raw
    or incompletely typed code is allowed. Clear mismatches fail.
    """
    report = FieldCoherenceReport()
    if not code or not code.strip():
        return report

    merged: dict[str, dict[str, Any]] = dict(structs or {})
    for item in extra_structs or ():
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        existing = merged.get(name)
        if existing:
            fields_by_offset = {
                field["offset"]: dict(field)
                for field in normalize_fields(existing.get("fields"))
            }
            for field in normalize_fields(item.get("fields")):
                fields_by_offset[field["offset"]] = field
            combined = dict(existing)
            combined["fields"] = [fields_by_offset[off] for off in sorted(fields_by_offset)]
            merged[name] = combined
        else:
            combined = dict(item)
            combined["fields"] = normalize_fields(item.get("fields"))
            merged[name] = combined

    fields_by_struct, pointee = _struct_maps(merged)
    if not fields_by_struct:
        return report

    cleaned = _strip_comments_and_strings(code)
    bindings = _parse_signature_bindings(cleaned)
    brace = cleaned.find("{")
    body = cleaned[brace:] if brace >= 0 else cleaned
    bindings.update(_parse_local_bindings(body))
    bindings = _propagate_assignments(body, bindings)

    lines = cleaned.splitlines()

    def line_no_at(pos: int) -> int:
        return cleaned.count("\n", 0, pos) + 1

    def snippet_at(lineno: int) -> str:
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()[:120]
        return ""

    def check_access(base: str, field_name: str, pos: int) -> None:
        struct_name = bindings.get(base)
        if not struct_name:
            report.unbound_accesses += 1
            return
        report.checked_accesses += 1
        known = fields_by_struct.get(struct_name)
        if known is None:
            report.unbound_accesses += 1
            return
        if field_name in known or field_name.startswith("_pad"):
            # Optional: rebind base through pointee for chains handled pairwise
            return
        lineno = line_no_at(pos)
        report.violations.append(
            FieldViolation(
                base=base,
                field=field_name,
                struct_name=struct_name,
                line=lineno,
                snippet=snippet_at(lineno),
            )
        )

    for m in _ARROW_RE.finditer(cleaned):
        check_access(m.group(1), m.group(2), m.start())
        # Chain support: if a->b is valid and b points to struct T, bind synthetic?
        # Pairwise a->b and b->c needs b as identifier. For a->b->c the regex
        # only sees (a,b) and then fails on `b->c` unless b is an ident — in
        # `a->b->c` the second match is wrong. Handle `ident->field` only;
        # chained `a->b->c` appears as one token stream: second arrow has base
        # that isn't a plain ident after first field. Python regex on
        # `req->dispatch->auth` yields (req, dispatch) only — good enough for
        # catching wrong leaf fields on the first base; also scan
        # `) -> field` after casts separately if needed.
        base, fld = m.group(1), m.group(2)
        struct_name = bindings.get(base)
        if struct_name and f"{struct_name}.{fld}" in pointee:
            child = pointee[f"{struct_name}.{fld}"]
            # Look ahead for `->nextfield` immediately after this match
            rest = cleaned[m.end() :]
            m2 = re.match(rf"\s*->\s*({_IDENT})\b", rest)
            if m2 and child:
                report.checked_accesses += 1
                child_fields = fields_by_struct.get(child)
                if child_fields is not None and m2.group(1) not in child_fields:
                    lineno = line_no_at(m.end() + m2.start())
                    report.violations.append(
                        FieldViolation(
                            base=f"{base}->{fld}",
                            field=m2.group(1),
                            struct_name=child,
                            line=lineno,
                            snippet=snippet_at(lineno),
                        )
                    )

    for m in _DOT_RE.finditer(cleaned):
        check_access(m.group(1), m.group(2), m.start())

    return report


def format_coherence_violations(report: FieldCoherenceReport) -> str:
    if report.ok:
        return report.summary()
    lines = [report.summary()]
    for v in report.violations[:20]:
        lines.append(
            f"  L{v.line}: `{v.base}->{v.field}` but struct {v.struct_name} "
            f"has no field `{v.field}` — {v.snippet}"
        )
    return "\n".join(lines)
