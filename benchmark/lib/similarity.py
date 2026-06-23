"""Behavioral similarity between pred and gold function fingerprints."""

from __future__ import annotations
from collections import Counter
from difflib import SequenceMatcher

# Well-known libc / POSIX calls — stable across renames of internal helpers.
_LIBC_CALLS = {
    "read", "write", "open", "close", "socket", "bind", "connect", "listen", "accept",
    "send", "sendto", "recv", "recvfrom", "select", "poll", "ioctl", "fcntl",
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "memcmp",
    "strcpy", "strncpy", "strcmp", "strncmp", "strlen", "printf", "fprintf", "sprintf",
    "snprintf", "syslog", "openlog", "perror", "puts", "putchar", "fgets", "fgetc",
    "time", "gettimeofday", "sleep", "usleep", "signal", "kill", "fork", "daemon",
    "access", "unlink", "system", "popen", "execve", "execl", "ntohl", "htonl",
    "htons", "setsockopt", "socketpair",
}


def _to_set(items: list[str]) -> set[str]:
    return {x for x in items if x}


def _norm_strings(items: list[str]) -> list[str]:
    return [s.strip().lower() for s in items if s and len(s) >= 3]


def _libc_calls(items: list[str]) -> list[str]:
    return [x for x in items if x in _LIBC_CALLS]


def jaccard(a: list[str], b: list[str]) -> float:
    sa, sb = _to_set(a), _to_set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def multiset_jaccard(a: list[str], b: list[str]) -> float:
    ca, cb = Counter(a), Counter(b)
    if not ca and not cb:
        return 1.0
    if not ca or not cb:
        return 0.0
    keys = set(ca) | set(cb)
    inter = sum(min(ca[k], cb[k]) for k in keys)
    union = sum(max(ca[k], cb[k]) for k in keys)
    return inter / union if union else 0.0


def lcs_ratio(a: list[str], b: list[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def combined_similarity(
    pred: dict,
    gold: dict,
    *,
    w_strings: float = 0.30,
    w_api_ms: float = 0.25,
    w_api_lcs: float = 0.20,
    w_libc: float = 0.25,
) -> dict[str, float]:
    strings = jaccard(_norm_strings(pred.get("strings") or []), _norm_strings(gold.get("strings") or []))
    api_ms = multiset_jaccard(pred.get("api_calls") or [], gold.get("api_calls") or [])
    api_lcs = lcs_ratio(pred.get("api_calls") or [], gold.get("api_calls") or [])
    libc = multiset_jaccard(
        _libc_calls(pred.get("api_calls") or []),
        _libc_calls(gold.get("api_calls") or []),
    )
    combined = w_strings * strings + w_api_ms * api_ms + w_api_lcs * api_lcs + w_libc * libc
    return {
        "strings": round(strings, 4),
        "api_multiset": round(api_ms, 4),
        "api_lcs": round(api_lcs, 4),
        "libc_multiset": round(libc, 4),
        "combined": round(combined, 4),
    }
