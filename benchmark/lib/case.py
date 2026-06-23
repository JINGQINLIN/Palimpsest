"""Benchmark case configuration and shared I/O helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from pipeline.paths import OUTPUT_DIR, find_package_dir

BENCHMARK_DIR = Path(__file__).resolve().parent.parent
CASES_DIR = BENCHMARK_DIR / "cases"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class BenchmarkCase:
    """One firmware case: pipeline binary + open-source gold tree."""
    id: str
    case_dir: Path
    binary: Path
    source_root: Path
    source_headers: Path
    context: str
    package_name: str

    @classmethod
    def load(cls, case_id: str) -> "BenchmarkCase":
        case_dir = CASES_DIR / case_id
        path = case_dir / "case.yaml"
        if not path.is_file():
            raise FileNotFoundError(f"case not found: {path}")

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        source_root = Path(str(data.get("source_root") or "").strip())
        headers_raw = str(data.get("source_headers") or "").strip()
        source_headers = Path(headers_raw) if headers_raw else source_root

        return cls(
            id=str(data.get("id") or case_id),
            case_dir=case_dir,
            binary=Path(str(data.get("binary") or "")),
            source_root=source_root,
            source_headers=source_headers,
            context=str(data.get("context") or "dhcp_server"),
            package_name=str(data.get("package_name") or case_id),
        )

    def gold_dir(self) -> Path:
        return self.case_dir / "gold"

    def pred_dir(self) -> Path:
        return self.case_dir / "pred"

    def resolve_package_dir(self, package: Path | None = None) -> Path:
        if package is not None:
            return find_package_dir(package)
        return find_package_dir(OUTPUT_DIR / self.package_name)

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "binary": str(self.binary),
            "source_root": str(self.source_root),
            "source_headers": str(self.source_headers),
            "context": self.context,
            "package_name": self.package_name,
        }


def load_context_structs(context_name: str) -> dict:
    path = Path("contexts") / f"{context_name}.yaml"
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    layouts = data.get("layouts") or {}
    structs: dict = {}
    for _key, entry in layouts.items():
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("struct") or "").strip()
        if not name:
            continue
        fields = []
        for field in entry.get("fields") or []:
            if not isinstance(field, dict):
                continue
            fields.append(
                {
                    "offset": int(field.get("offset", 0)),
                    "name": str(field.get("name") or ""),
                    "type": str(field.get("type") or ""),
                }
            )
        structs[name] = {
            "size": int(entry.get("size", 0)),
            "fields": fields,
            "source": f"contexts/{context_name}.yaml",
        }
    return structs

