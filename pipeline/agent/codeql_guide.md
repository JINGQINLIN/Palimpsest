# CodeQL-friendly code guide

Build: `codeql database create --language=cpp --build-mode=none` — no compilation, the C/C++
extractor parses the source directly. Each `.c` includes `recopilot_types.h` (reconstructed
structs), which includes `recopilot_stubs.h` (Ghidra pseudo-types, decompiler macros, and common
libc/Linux/firmware declarations).

## Must parse

- Remove undeclared Ghidra register pseudo-symbols (`unaff_*`, `extraout_*`, `in_*`, `unique0x*`):
  replace with the real variable, delete the dead code, or add a minimal declaration and flag it.
- Every type must resolve — reduce unknown types to ones in the stub header; don't invent
  undeclared types.
- A callee with no declaration cannot become a call edge: stub-declared APIs are fine; for another
  reconstructed function, add a forward declaration matching its definition.
- Balanced braces, valid statements; delete unreachable blocks that reference undeclared symbols.

## Useful for queries

- Keep real calls — do NOT inline or merge functions (that breaks call edges and interprocedural
  taint).
- Dangerous functions (strcpy/strcat/sprintf/memcpy/system/popen/execve) are stub-declared with
  correct prototypes; don't re-declare them locally; pass the tainted buffer to the matching arg.
- Never cut the visible source→sink path (sources: recv/recvfrom/read/getenv; sinks: above).
- Keep array sizes, indices, and sizeof explicit for buffer-overflow queries.
- Prefer struct field access over offset arithmetic (better field-sensitive taint). Align call
  sites after struct-pointer signature changes (get_callers). To merge duplicate structs: confirm
  matching offsets with get_structs, align field names with edit_function, then rename_struct.
  Don't rename struct fields with rename_symbol (the header is authoritative).

## Red lines

No change to observable behavior or side-effect order; no inlining/merging; don't cut the
source→sink path; keep it valid C. When unsure, leave it and note it.
