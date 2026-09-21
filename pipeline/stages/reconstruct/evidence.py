"""Deterministic evidence bundles for offset-based structure recovery."""
from __future__ import annotations

import json
import re
from bisect import bisect_right
from dataclasses import asdict, dataclass, field
from pathlib import Path

from pipeline.stages.ghidra import FunctionContext

_ACCESS_RE = re.compile(
    r"\*\s*\(\s*(?P<ctype>[A-Za-z_][\w\s]*\d*\s*\*?)\s*\*\s*\)\s*"
    r"\(\s*(?:(?:\([^()]*\))\s*)*(?P<base>[A-Za-z_]\w*)\s*\+\s*"
    r"(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\)"
)
_INDEX_RE = re.compile(
    r"\b(?P<base>[A-Za-z_]\w*)\s*\[\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\]"
)
# Only explicit Ghidra scalar declarations establish an element width here.
# Unknown pointees, structs and pointer-to-pointer bases remain unscaled.
_INDEX_BASE_RE = re.compile(
    r"\b(?P<ctype>int|uint|short|ushort|char|uchar|byte|undefined[1248]|[u]?int(?:8|16|32|64)_t)\s+"
    r"(?:\*\s*(?P<pointer>[A-Za-z_]\w*)\b|(?P<array>[A-Za-z_]\w*)\s*\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*\])"
)
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "case",
}
# Keep the bundle bounded, but give the model enough surrounding code to see
# how a field is produced, transformed, and consumed.  The complete evidence
# remains in access_evidence.json; this is only the prompt-facing digest.
_MAX_BUNDLE_CHARS = 12_000


@dataclass(frozen=True)
class AccessFact:
    address: str
    function: str
    line_no: int
    base: str
    offset: int
    ctype: str
    size: int
    snippet: str
    callee: str = ""
    arg_index: int = -1
    arg_count: int = 0
    roles: tuple[str, ...] = field(default_factory=tuple)
    access_kind: str = "displacement"
    byte_offset: int | None = None
    access_mode: str = "read"


@dataclass
class ObjectEvidence:
    address: str
    function: str
    base: str
    facts: list[AccessFact] = field(default_factory=list)

    @property
    def offsets(self) -> set[int]:
        # Unscaled indices must not match byte displacements by numeric accident.
        return {
            fact.byte_offset if fact.byte_offset is not None else fact.offset
            for fact in self.facts
            if fact.access_kind != "index" or fact.byte_offset is not None
        }


@dataclass
class AccessEvidenceIndex:
    by_address: dict[str, list[ObjectEvidence]]
    by_function: dict[str, str]

    def to_json(self) -> str:
        objects = []
        for address in sorted(self.by_address):
            for obj in sorted(self.by_address[address], key=lambda item: item.base):
                objects.append(
                    {
                        "address": obj.address,
                        "function": obj.function,
                        "base": obj.base,
                        "offsets": [f"0x{o:x}" for o in sorted(obj.offsets)],
                        "facts": [asdict(fact) for fact in obj.facts],
                    }
                )
        return json.dumps({"objects": objects}, ensure_ascii=False, indent=2)


def build_access_evidence_index(
    contexts: dict[str, FunctionContext],
) -> AccessEvidenceIndex:
    """Scan raw decompiler C and group unresolved base+offset accesses."""
    by_address: dict[str, list[ObjectEvidence]] = {}
    by_function: dict[str, str] = {}

    for address, ctx in sorted(contexts.items()):
        function = ctx.ghidra_name or f"FUN_{address}"
        by_function.setdefault(function, address)
        grouped: dict[str, ObjectEvidence] = {}
        line_starts = _line_starts(ctx.code)
        declarations = list(_INDEX_BASE_RE.finditer(ctx.code))
        element_sizes = {
            m.group("pointer") or m.group("array"): _ctype_size(m.group("ctype"))
            for m in declarations
        }
        for match in _ACCESS_RE.finditer(ctx.code):
            line_no = _line_no(line_starts, match.start())
            line = _line_text(ctx.code, line_starts, line_no)
            fact = _build_access_fact(ctx, line_no, line, match, ctx.code)
            grouped.setdefault(
                fact.base,
                ObjectEvidence(address=address, function=function, base=fact.base),
            ).facts.append(fact)
        for match in _INDEX_RE.finditer(ctx.code):
            if any(m.start() <= match.start() < m.end() for m in declarations):
                continue  # An array declaration is not a memory access.
            line_no = _line_no(line_starts, match.start())
            line = _line_text(ctx.code, line_starts, line_no)
            fact = _build_index_fact(
                ctx, line_no, line, match, ctx.code,
                element_size=element_sizes.get(match.group("base"), 0),
            )
            grouped.setdefault(
                fact.base,
                ObjectEvidence(address=address, function=function, base=fact.base),
            ).facts.append(fact)
        if grouped:
            by_address[address] = list(grouped.values())

    return AccessEvidenceIndex(by_address=by_address, by_function=by_function)


def format_evidence_bundle(
    index: AccessEvidenceIndex,
    contexts: dict[str, FunctionContext],
    address: str,
    *,
    max_related: int = 3,
) -> str:
    """Format the current function's object evidence for the structure prompt."""
    current = index.by_address.get(address) or []

    lines: list[str] = [
        "Evidence retrieved for this function (supporting evidence only).",
        "Preserve raw offsets when the evidence is weak; similar accesses are candidates, not proof of shared identity or layout.",
    ]
    if current:
        lines.extend([
            "Unrecovered memory-access evidence:",
            "Indices with explicit scalar element widths include a derived byte offset; other displacements require checking base type and pointer scaling.",
        ])
    for obj in sorted(current, key=lambda item: item.base):
        current_ctx = contexts.get(address)
        lines.extend(_format_object_block(
            obj,
            heading=f"Current object `{obj.base}`",
            context_code=current_ctx.code if current_ctx else "",
            context_before=5,
            context_after=5,
            context_limit=2,
        ))
        consensus = _format_consensus_contract(index, obj, max_sites=max_related + 1)
        if consensus:
            lines.extend(consensus)
        related = _related_objects(index, obj, limit=max_related)
        if related:
            lines.append("  candidate use sites with overlapping displacements (identity unproven):")
            for other, score in related:
                overlap = sorted(obj.offsets & other.offsets)
                off_text = ", ".join(f"+0x{o:x}" for o in overlap)
                lines.append(
                    f"    - 0x{other.address} {other.function} base `{other.base}` "
                    f"overlap {off_text} score={score:.2f}"
                )
                relevant = [f for f in other.facts if (f.byte_offset if f.byte_offset is not None else f.offset) in overlap]
                selected = _select_facts(relevant, limit=2)
                for fact in selected:
                    call = _format_call(fact)
                    offset_note = f" [index {fact.offset} -> byte +0x{fact.byte_offset:x}]" if fact.byte_offset is not None else ""
                    lines.append(
                        f"      {fact.access_mode} line {fact.line_no}: {fact.snippet}{call}{offset_note}"
                    )
                other_ctx = contexts.get(other.address)
                if other_ctx and selected:
                    lines.append("      raw use context (5 lines before/after):")
                    for fact in selected[:2]:
                        lines.extend(
                            "      " + line
                            for line in _context_window(
                                other_ctx.code,
                                fact.line_no,
                                before=5,
                                after=5,
                                max_chars=1400,
                            )
                        )

        callees = _known_callees(index, contexts, obj)
        if callees:
            lines.append("  raw callee context referenced by these accesses (may be truncated):")
            for name, callee_ctx in callees[:4]:
                excerpt = callee_ctx.code.strip()[:900]
                if excerpt:
                    lines.append(f"    - {name}:\n{excerpt}")

    # Control-flow snippets are evidence for the LLM, not a rewrite pass.  In
    # particular, show the destination body of a goto so the model can decide
    # whether a label is merely a cleanup tail or part of a real loop/merge.
    control_flow = _format_control_flow_evidence(contexts.get(address).code if contexts.get(address) else "")
    if control_flow:
        lines.append("Control-flow destination evidence (inspect before simplifying labels/gotos):")
        lines.extend(control_flow)

    if not current and not control_flow:
        return ""

    text = "\n".join(lines)
    if len(text) > _MAX_BUNDLE_CHARS:
        text = text[:_MAX_BUNDLE_CHARS].rstrip() + "\n...(access evidence truncated)"
    return text


def _format_control_flow_evidence(code: str, *, max_blocks: int = 8, max_lines: int = 10) -> list[str]:
    """Return bounded goto/label context for the structure LLM.

    This only reports source evidence.  It intentionally does not classify a
    jump as safe or alter the generated C; the reconstruction model makes that
    semantic decision with the full function in view.
    """
    if not code:
        return []
    lines = code.splitlines()
    label_re = re.compile(r"^\s*(LAB_[A-Za-z0-9_]+):\s*$")
    goto_re = re.compile(r"\bgoto\s+(LAB_[A-Za-z0-9_]+)\s*;")
    labels: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = label_re.match(line)
        if match:
            labels.append((index, match.group(1)))
    if not labels:
        return []
    label_map = {name: index for index, name in labels}
    targeted = []
    for index, line in enumerate(lines):
        for match in goto_re.finditer(line):
            destination = match.group(1)
            if destination in label_map and destination not in targeted:
                targeted.append(destination)
    out: list[str] = []
    for name in targeted[:max_blocks]:
        start = label_map[name]
        next_label = next((idx for idx, _ in labels if idx > start), len(lines))
        body = lines[start: min(next_label, start + max_lines)]
        out.append(f"  {name} destination (raw lines {start + 1}-{start + len(body)}):")
        out.extend(f"    {line}" for line in body)
        if next_label > start + len(body):
            out.append("    ...(destination excerpt truncated)")
    return out


def write_access_evidence_index(package_dir: Path, index: AccessEvidenceIndex) -> Path:
    path = package_dir / "reconstruction" / "access_evidence.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(index.to_json() + "\n", encoding="utf-8")
    return path


def _build_access_fact(
    ctx: FunctionContext,
    line_no: int,
    line: str,
    match: re.Match[str],
    full_text: str,
) -> AccessFact:
    ctype = " ".join(match.group("ctype").split())
    base = match.group("base")
    offset = _parse_int(match.group("offset"))
    callee, arg_index, arg_count = _call_for_span(full_text, match.start())
    roles = _infer_roles(line, ctype, callee, arg_index)
    return AccessFact(
        address=ctx.address,
        function=ctx.ghidra_name or f"FUN_{ctx.address}",
        line_no=line_no,
        base=base,
        offset=offset,
        ctype=ctype,
        size=_ctype_size(ctype),
        snippet=_statement_snippet(full_text, match.start(), fallback=line),
        callee=callee,
        arg_index=arg_index,
        arg_count=arg_count,
        roles=roles,
        access_mode="write" if re.match(r"\s*=(?!=)", full_text[match.end():]) else "read",
    )


def _build_index_fact(
    ctx: FunctionContext,
    line_no: int,
    line: str,
    match: re.Match[str],
    full_text: str,
    *,
    element_size: int = 0,
) -> AccessFact:
    base = match.group("base")
    offset = _parse_int(match.group("offset"))
    callee, arg_index, arg_count = _call_for_span(full_text, match.start())
    return AccessFact(
        address=ctx.address,
        function=ctx.ghidra_name or f"FUN_{ctx.address}",
        line_no=line_no,
        base=base,
        offset=offset,
        ctype="indexed",
        size=element_size,
        snippet=_statement_snippet(full_text, match.start(), fallback=line),
        callee=callee,
        arg_index=arg_index,
        arg_count=arg_count,
        roles=_infer_roles(line, "indexed", callee, arg_index),
        access_kind="index",
        byte_offset=offset * element_size if element_size else None,
        access_mode="write" if re.match(r"\s*=(?!=)", full_text[match.end():]) else "read",
    )


def _parse_int(text: str) -> int:
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _ctype_size(ctype: str) -> int:
    text = ctype.replace(" ", "").lower()
    if "*" in text:
        return 0  # Target pointer width is not available in this text index.
    if "undefined8" in text or "uint64" in text or "int64" in text or "longlong" in text:
        return 8
    if "undefined4" in text or "uint32" in text or text in {"uint", "int", "undefined"}:
        return 4
    if "undefined2" in text or "uint16" in text or "int16" in text or "short" in text:
        return 2
    if "undefined1" in text or "uint8" in text or "int8" in text or "char" in text:
        return 1
    if text == "byte":
        return 1
    return 0


def _infer_roles(
    line: str,
    ctype: str,
    callee: str,
    arg_index: int,
) -> tuple[str, ...]:
    roles: list[str] = []
    compact = line.replace(" ", "")
    if "+*" in compact or ")+*(" in compact or re.search(r"\)\s*\+\s*\*\s*\(", line):
        roles.append("participates_in_pointer_or_offset_addition")
    if callee:
        roles.append(f"passed_to_{callee}_arg{arg_index}")
    if "=" in line and line.find("=") < line.find(ctype.split()[0]):
        roles.append("read_on_assignment_rhs")
    return tuple(dict.fromkeys(roles))


def _call_for_span(line: str, span_start: int) -> tuple[str, int, int]:
    best: tuple[str, int, int, int] | None = None
    for match in _CALL_NAME_RE.finditer(line):
        name = match.group(1)
        if name in _KEYWORDS:
            continue
        open_idx = match.end() - 1
        close_idx = _matching_paren(line, open_idx)
        if close_idx < 0 or not (open_idx < span_start < close_idx):
            continue
        distance = close_idx - open_idx
        if best is not None and distance >= best[3]:
            continue
        args = _split_args_with_spans(line, open_idx + 1, close_idx)
        for idx, (_, start, end) in enumerate(args):
            if start <= span_start <= end:
                best = (name, idx, len(args), distance)
                break
    if best is None:
        return "", -1, 0
    return best[0], best[1], best[2]


def _matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        char = text[idx]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _split_args_with_spans(text: str, start: int, end: int) -> list[tuple[str, int, int]]:
    args: list[tuple[str, int, int]] = []
    depth = 0
    arg_start = start
    idx = start
    while idx < end:
        char = text[idx]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            args.append((text[arg_start:idx], arg_start, idx))
            arg_start = idx + 1
        idx += 1
    if arg_start <= end:
        args.append((text[arg_start:end], arg_start, end))
    return [(arg.strip(), s, e) for arg, s, e in args if arg.strip()]


def _related_objects(
    index: AccessEvidenceIndex,
    target: ObjectEvidence,
    *,
    limit: int,
) -> list[tuple[ObjectEvidence, float]]:
    related: list[tuple[ObjectEvidence, float]] = []
    target_offsets = target.offsets
    if not target_offsets:
        return []
    for objects in index.by_address.values():
        for obj in objects:
            if obj.address == target.address and obj.base == target.base:
                continue
            overlap = target_offsets & obj.offsets
            if len(overlap) < 2:
                continue
            union = target_offsets | obj.offsets
            score = len(overlap) / max(1, len(union))
            # Placeholder names such as param_1 carry no cross-function identity.
            target_calls = {(f.callee, f.arg_index) for f in target.facts if f.callee}
            other_calls = {(f.callee, f.arg_index) for f in obj.facts if f.callee}
            if target_calls & other_calls:
                score += 1.0
            related.append((obj, score))
    related.sort(key=lambda item: (-item[1], item[0].address, item[0].base))
    # Reserve one slot for a complementary writer. Offset similarity still only
    # retrieves a candidate; the prompt must establish the object relationship.
    writer = next((item for item in related if target_offsets <= item[0].offsets and any(
        f.access_mode == "write" and
        (f.byte_offset if f.byte_offset is not None else f.offset) in target_offsets
        for f in item[0].facts
    )), None)
    if writer is not None and limit > 1:
        related.remove(writer)
        related.insert(1, writer)
    return related[:limit]


def _format_consensus_contract(
    index: AccessEvidenceIndex,
    target: ObjectEvidence,
    *,
    max_sites: int,
) -> list[str]:
    """Summarize repeated offset/use contracts for the structure LLM.

    The summary is still retrieval evidence, not an asserted type or identity.
    Repetition across independent functions is surfaced explicitly because a
    list of isolated snippets can otherwise look like unrelated noise to the
    model.  The model must still verify each field against the raw accesses.
    """
    # A score of 2.0 means the offset overlap is accompanied by a shared
    # callee/argument role.  Plain numeric overlap (score 1.0) is deliberately
    # excluded from the consensus summary because it is too easy to mix
    # unrelated placeholder bases into a purported contract.
    peers = [
        (other, score)
        for other, score in _related_objects(index, target, limit=max_sites)
        if score >= 2.0
    ]
    if len(peers) < 2:
        return []
    sites: dict[int, set[str]] = {offset: {target.function} for offset in target.offsets}
    callees: dict[int, set[str]] = {offset: set() for offset in target.offsets}
    for other, _score in peers:
        for fact in other.facts:
            offset = fact.byte_offset if fact.byte_offset is not None else fact.offset
            if offset not in sites:
                continue
            sites[offset].add(other.function)
            if fact.callee:
                callees[offset].add(f"{fact.callee}/arg{fact.arg_index}")
    repeated = [offset for offset in sorted(sites) if len(sites[offset]) >= 3]
    if not repeated:
        return []
    lines = [
        "  repeated cross-function access contract (strong retrieval signal; verify before typing):",
        "    The following offsets recur on the same relative base in at least three functions.",
        "    This supports a shared partial object hypothesis when pointer roles and call arguments also agree.",
    ]
    for offset in repeated:
        call_text = ", ".join(sorted(callees[offset])) or "no shared callee recorded"
        names = sorted(sites[offset])
        shown = ", ".join(names[:3])
        if len(names) > 3:
            shown += f", ... ({len(names)} functions total)"
        lines.append(f"    +0x{offset:x}: observed in {shown}; calls {call_text}")
    return lines


def _select_facts(facts: list[AccessFact], *, limit: int) -> list[AccessFact]:
    selected: list[AccessFact] = []
    seen: set[str] = set()
    for fact in sorted(
        facts,
        key=lambda fact: (
            0 if fact.access_mode == "write" else 1,
            0 if fact.callee else 1,
            fact.offset,
            fact.line_no,
        ),
    ):
        if fact.snippet not in seen:
            selected.append(fact)
            seen.add(fact.snippet)
        if len(selected) >= limit:
            break
    return selected


def _format_object_block(
    obj: ObjectEvidence,
    *,
    heading: str,
    context_code: str = "",
    context_before: int = 5,
    context_after: int = 5,
    context_limit: int = 2,
) -> list[str]:
    lines = [heading + ":"]
    by_offset: dict[int, list[AccessFact]] = {}
    for fact in obj.facts:
        by_offset.setdefault(fact.offset, []).append(fact)
    for offset in sorted(by_offset):
        facts = by_offset[offset]
        sizes = sorted({fact.size for fact in facts if fact.size})
        ctypes = sorted({fact.ctype for fact in facts if fact.ctype})
        roles = sorted({role for fact in facts for role in fact.roles})
        call_text = sorted({_format_call(fact).strip() for fact in facts if fact.callee})
        size_text = ", ".join(f"{size}B" for size in sizes) or "unknown-size"
        type_text = ", ".join(ctypes[:3]) or "unknown-type"
        kinds = "/".join(sorted({fact.access_kind for fact in facts}))
        lines.append(f"  +0x{offset:x} ({kinds}; byte offset unverified): {size_text}; seen as {type_text}")
        derived = sorted({f.byte_offset for f in facts if f.byte_offset is not None})
        if derived:
            lines.append("    scalar-index byte offsets: " + ", ".join(f"+0x{o:x}" for o in derived))
        if call_text:
            lines.append(f"    calls: {'; '.join(call_text[:3])}")
        if roles:
            lines.append(f"    roles: {', '.join(roles[:5])}")
        selected = _select_facts(facts, limit=context_limit)
        for fact in selected:
            lines.append(f"    line {fact.line_no}: {fact.snippet}")
            if context_code:
                lines.append(
                    f"    context around line {fact.line_no} ({context_before} before/{context_after} after):"
                )
                lines.extend(
                    "      " + line
                    for line in _context_window(
                        context_code,
                        fact.line_no,
                        before=context_before,
                        after=context_after,
                        max_chars=1600,
                    )
                )
    return lines


def _context_window(
    code: str,
    line_no: int,
    *,
    before: int,
    after: int,
    max_chars: int,
) -> list[str]:
    """Return numbered source lines around an evidence fact.

    This is deliberately a presentation helper.  It never edits or interprets
    the candidate C, so the LLM still makes every semantic reconstruction
    decision from the complete function and this raw evidence.
    """
    source_lines = code.splitlines()
    if not source_lines:
        return []
    anchor = max(1, min(line_no, len(source_lines)))
    start = max(1, anchor - before)
    end = min(len(source_lines), anchor + after)
    excerpt = [f"L{i}: {source_lines[i - 1]}" for i in range(start, end + 1)]
    joined = "\n".join(excerpt)
    if len(joined) <= max_chars:
        return excerpt
    clipped = joined[:max_chars].rstrip()
    return clipped.splitlines() + ["...(context window truncated)"]


def _format_call(fact: AccessFact) -> str:
    if not fact.callee:
        return ""
    return f"  -> {fact.callee} arg{fact.arg_index}/{fact.arg_count}"


def _known_callees(
    index: AccessEvidenceIndex,
    contexts: dict[str, FunctionContext],
    obj: ObjectEvidence,
) -> list[tuple[str, FunctionContext]]:
    seen: set[str] = set()
    found: list[tuple[str, FunctionContext]] = []
    names = [fact.callee for fact in obj.facts if fact.callee]
    current = contexts.get(obj.address)
    if current:
        # A stack object passed directly to a helper is just as useful as a
        # field passed to it. Reuse the existing call/argument parser.
        for match in _CALL_NAME_RE.finditer(current.code):
            name = match.group(1)
            if name not in index.by_function or index.by_function[name] == obj.address:
                continue
            end = _matching_paren(current.code, match.end() - 1)
            if end < 0:
                continue
            args = _split_args_with_spans(current.code, match.end(), end)
            if any(re.fullmatch(rf"(?:\([^()]*\)\s*)*&?\s*{re.escape(obj.base)}", arg) for arg, _, _ in args):
                names.append(name)
    for name in names:
        if name in seen:
            continue
        callee_addr = index.by_function.get(name)
        if not callee_addr:
            continue
        callee_ctx = contexts.get(callee_addr)
        if not callee_ctx:
            continue
        seen.add(name)
        found.append((name, callee_ctx))
    return found


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for match in re.finditer(r"\n", text):
        starts.append(match.end())
    return starts


def _line_no(starts: list[int], offset: int) -> int:
    return bisect_right(starts, offset)


def _line_text(text: str, starts: list[int], line_no: int) -> str:
    start = starts[line_no - 1]
    end = text.find("\n", start)
    if end < 0:
        end = len(text)
    return text[start:end]


def _statement_snippet(text: str, offset: int, *, fallback: str) -> str:
    start = max(text.rfind(";", 0, offset), text.rfind("{", 0, offset), text.rfind("}", 0, offset))
    start = 0 if start < 0 else start + 1
    end = text.find(";", offset)
    if end < 0:
        end = text.find("\n", offset)
    if end < 0:
        end = len(text)
    snippet = text[start : end + 1].strip() if end < len(text) else text[start:end].strip()
    if not snippet:
        snippet = fallback.strip()
    snippet = re.sub(r"\s+", " ", snippet)
    if len(snippet) > 220:
        snippet = snippet[:217].rstrip() + "..."
    return snippet
