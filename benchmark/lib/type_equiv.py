"""Loose C type equivalence for param-type scoring."""

from __future__ import annotations
import re

_ARRAY_RE = re.compile(r"^(.*?)\[\s*(\d+)\s*\]$", re.S)


def _collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def normalize_type(type_str: str) -> str:
    text = _collapse_ws(type_str)
    text = text.replace("const ", "").replace("volatile ", "")
    text = re.sub(r"\bstruct\s+", "", text)
    text = re.sub(r"\benum\s+", "", text)
    text = text.replace(" *", "*").replace("* ", "*")
    text = text.replace("char*argv[]", "char**")
    text = text.replace("unsigned int", "uint32_t")
    text = text.replace("unsigned long", "uint32_t")
    text = text.replace("unsigned short", "uint16_t")
    text = text.replace("unsigned char", "uint8_t")
    text = text.replace("signed int", "int32_t")
    text = text.replace("long", "int32_t")
    text = text.replace("short", "int16_t")
    return text


_TYPE_ALIASES = {
    "int": {"int32_t", "int", "long", "s32"},
    "uint32_t": {"uint32_t", "unsigned int", "u32", "ulong"},
    "uint16_t": {"uint16_t", "unsigned short", "u16", "ushort"},
    "uint8_t": {"uint8_t", "unsigned char", "u8", "uchar", "byte"},
    "char*": {"char*", "byte*"},
    "char**": {"char**", "char*[]"},
}


def _expand_aliases(norm: str) -> set[str]:
    out = {norm}
    for canonical, aliases in _TYPE_ALIASES.items():
        if norm in aliases or norm == canonical:
            out.add(canonical)
            out.update(aliases)
    return out


def types_equivalent(a: str, b: str) -> bool:
    na, nb = normalize_type(a), normalize_type(b)
    if na == nb:
        return True
    if na in _expand_aliases(nb) or nb in _expand_aliases(na):
        return True
    return False
