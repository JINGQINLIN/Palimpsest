# Benchmark v0

Compare Palimpsest pipeline output against open-source gold labels.

## Layout

```text
benchmark/
  cases/<id>/
    case.yaml          Case config (binary, source_root, context)
    gold/              Labels built from source (step 1)
  lib/                 Core logic (parse, align, score, evaluate)
  tools/               CLI entry points
```

## Pipeline

| Step | Command | Input | Output |
|------|---------|-------|--------|
| 1 | `python -m benchmark.tools.build_gold --case <id>` | Open-source `.c` tree | `cases/<id>/gold/` |
| 2 | `python -m benchmark.tools.extract_pred --case <id>` | `output/<package>/` | `cases/<id>/pred/<stage>.json` |
| 3 | `python -m benchmark.tools.align --case <id>` | pred + gold | `cases/<id>/alignment.json` |
| 4 | `python -m benchmark.tools.score --case <id>` | alignment + gold + pred | `cases/<id>/scores/` |

Steps 2–4 in one shot:

```bash
python -m benchmark.tools.run --case r9000_udhcpd --package output/r9000_udhcpd
```

## Stages

`extract_pred --stages` accepts: `raw`, `structured`, `named`, `post_agent` (default).

- **raw** — Ghidra decompilation JSON
- **structured** / **named** — per-function reconstruction artifacts
- **post_agent** — final `codeql/src/*.c` after agent review

## Metrics

After alignment (pred address ↔ gold function name), scoring reports:

- align coverage, param type accuracy, func name token F1
- API / libc behavioral similarity (multiset jaccard, LCS)
- struct field recall (by offset + type equivalence)
- placeholder-free rate

A/B two pipeline runs:

```bash
python -m benchmark.tools.compare \
  --case r9000_udhcpd \
  --new-package output/r9000_udhcpd \
  --old-package "output/( 06-06-26-T4 ) r9000_udhcpd"
```

Also reads `reconstruction/flows.json` flow metrics when present.

## Experimental probes

Not wired into the main align path yet:

- `benchmark.tools.anchor` — unique string literal pinning
- `benchmark.tools.propagate` — spread pins along call graph

## Prerequisites

1. Copy `local_config.example.yaml` → `local_config.yaml` and run the pipeline once.
2. Set `source_root` in `cases/<id>/case.yaml` to your open-source tree.
3. Run `build_gold` before the first scoring pass.

Gold for `r9000_udhcpd` is checked in; regenerate locally if your source tree differs.

Run artifacts (`pred/`, `scores/`, `alignment.json`, probe JSON) are gitignored.
