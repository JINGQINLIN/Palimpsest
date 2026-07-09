# CodeQL-friendly code guide

Build: `codeql database create --language=cpp --build-mode=none` — no compilation, the C/C++
extractor parses the source directly. Each `.c` includes `recopilot_types.h` (reconstructed
structs), which includes `recopilot_stubs.h` (Ghidra pseudo-types, decompiler macros, and common
libc/Linux/firmware declarations).

## Must parse

- Remove undeclared Ghidra register pseudo-symbols (`unaff_*`, `extraout_*`, `in_*`, `unique0x*`):
  replace with the real variable, delete the dead code, or add a minimal declaration and flag it.
- Every type must resolve to one already declared in `recopilot_stubs.h` or `recopilot_types.h`,
  including types used inside casts. An undeclared type name makes the parser drop the WHOLE
  statement, silently deleting the call inside it from the database — e.g. `(uintptr_t)f(x)` or
  `FILE *p = popen(...)` lose the `f`/`popen` call if that type is absent. Never introduce a new
  typedef or cast through a type that is not already declared; if a cast is needed, use one that
  exists in the stub (`int` / `long` / `void *` / `uint32_t` / a declared `struct`).
- A callee with no declaration cannot become a call edge: stub-declared APIs are fine; for another
  reconstructed function, add a forward declaration matching its definition.
- Balanced braces, valid statements; delete unreachable blocks that reference undeclared symbols.

## Useful for queries

- Keep real calls — do NOT inline or merge functions (that breaks call edges).
- libc and firmware APIs in `recopilot_stubs.h` are stub-declared with correct prototypes; don't
  re-declare them locally.
- Keep array sizes, indices, and sizeof explicit where buffers are used.
- Prefer struct field access over offset arithmetic. Align call sites after struct-pointer
  signature changes (get_callers). To merge duplicate structs: confirm matching offsets with
  get_structs, align field names with edit_function, then rename_struct. Don't rename struct
  fields with rename_symbol (the header is authoritative).

## Red lines

No change to observable behavior or side-effect order; no inlining/merging; keep it valid C.
When unsure, leave it and note it.
