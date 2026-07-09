#!/usr/bin/env python3
"""
Run CLARIS on a Palimpsest job output.
在 Palimpsest 作业产物上运行 CLARIS：环境探测 → 预检 → 生成 config.json → 执行 → 汇总报告。

Two conda environments are expected:
  - Palimpsest (semant_func): run this script here
  - claris (CLARIS-main): used to execute run_program.py

Usage (in Palimpsest conda env):
  python integration/claris/orchestrate.py --job-dir output/r9000_udhcpd

CLARIS env resolution (first match wins):
  1. --claris-python / CLARIS_PYTHON
  2. auto-detect conda envs/<name>/python.exe (same Miniconda as current env)
  3. conda run -n <claris-conda-env>   (default env name: claris)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


SEMANT_FUNC_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CLARIS_ROOT = SEMANT_FUNC_ROOT.parent / "CLARIS-main"
DEFAULT_CLARIS_CONDA_ENV = "claris"
DEFAULT_LLM_THREADS = 2


# =========================================================================
# 环境探测与通用工具 / Environment discovery & shared helpers
# 定位 Git-grep、conda 环境、CLARIS Python 解释器，并构造子进程环境。
# =========================================================================
def find_git_usr_bin() -> Path | None:
    """Locate Git for Windows usr/bin (provides grep used by upstream_constraint)."""
    for candidate in (
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "usr" / "bin",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Git" / "usr" / "bin",
    ):
        if (candidate / "grep.exe").is_file():
            return candidate.resolve()
    return None


def build_claris_subprocess_env() -> dict[str, str]:
    """
    Build env for CLARIS subprocess.

    - PYTHONUTF8: CLARIS taint_analysis reads JSON with open() and no encoding;
      LLM reason fields contain Unicode. On Windows this avoids MySources.qll = 1=0.
    - Git grep on PATH: upstream_constraint uses grep on Windows.
    """
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env.setdefault("PYTHONIOENCODING", "utf-8:replace")
    git_usr_bin = find_git_usr_bin()
    if git_usr_bin:
        env["PATH"] = str(git_usr_bin) + os.pathsep + env.get("PATH", "")
    return env


def preflight_claris_output_dirs(job_dir: Path) -> None:
    """
    Fix common Windows re-run issues under claris/output/source_agent.

    LLMClient uses os.mkdir(llm_log); a prior failed run may leave llm_log as a file.
    """
    source_out = job_dir / "claris" / "output" / "source_agent"
    llm_log = source_out / "llm_log"
    if llm_log.is_file():
        llm_log.unlink()
    llm_log.mkdir(parents=True, exist_ok=True)


def _posix(path: Path) -> str:
    return str(path.resolve())


@dataclass(frozen=True)
class ClarisLaunch:
    command: list[str]
    label: str


def _run_output(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _conda_base() -> Path | None:
    exe = Path(sys.executable).resolve()
    parts = exe.parts
    if "envs" in parts:
        base = Path(*parts[: parts.index("envs")])
        if (base / "envs").is_dir():
            return base

    for key in ("CONDA_EXE", "MAMBA_EXE"):
        raw = os.environ.get(key, "").strip()
        if raw:
            conda_exe = Path(raw).resolve()
            candidate = conda_exe.parent.parent
            if (candidate / "envs").is_dir():
                return candidate

    for name in ("conda.exe", "conda.bat", "conda"):
        which = shutil.which(name)
        if not which:
            continue
        probe = _run_output([which, "info", "--base"])
        if probe.returncode == 0:
            base = Path(probe.stdout.strip())
            if base.is_dir():
                return base
    return None


def _conda_exe(base: Path) -> Path | None:
    for candidate in (
        base / "Scripts" / "conda.exe",
        base / "condabin" / "conda.bat",
        base / "condabin" / "conda.exe",
    ):
        if candidate.is_file():
            return candidate.resolve()
    return None


def find_conda_env_python(env_name: str) -> Path | None:
    base = _conda_base()
    if not base:
        return None

    for candidate in (
        base / "envs" / env_name / "python.exe",
        base / "envs" / env_name / "bin" / "python",
    ):
        if candidate.is_file():
            return candidate.resolve()
    return None


def resolve_claris_launch(
    *,
    python_override: str | None,
    conda_env: str,
    prefer_conda_run: bool,
) -> ClarisLaunch:
    if python_override:
        python = Path(python_override).expanduser().resolve()
        return ClarisLaunch([str(python)], f"python: {python}")

    env_python = os.environ.get("CLARIS_PYTHON", "").strip()
    if env_python:
        python = Path(env_python).expanduser().resolve()
        return ClarisLaunch([str(python)], f"python: {python}")

    conda_python = find_conda_env_python(conda_env)
    if conda_python:
        return ClarisLaunch([str(conda_python)], f"conda env {conda_env}: {conda_python}")

    if prefer_conda_run:
        base = _conda_base()
        conda = _conda_exe(base) if base else None
        if conda:
            return ClarisLaunch(
                [str(conda), "run", "-n", conda_env, "--no-capture-output", "python"],
                f"conda run -n {conda_env}",
            )

    raise SystemExit(
        "Cannot find CLARIS Python.\n"
        "Use one of:\n"
        f"  1) create env: conda env create -f CLARIS-main/environment.yml\n"
        f"  2) set CLARIS_PYTHON to envs/{conda_env}/python.exe\n"
        "  3) pass --claris-python <path>"
    )


# =========================================================================
# 预检与依赖准备 / Preflight & dependency checks
# 运行前校验 CLARIS 运行时、CodeQL CLI/包、查询文件、LLM 配置与作业输入。
# =========================================================================
def preflight_claris_runtime(launch: ClarisLaunch, claris_root: Path) -> None:
    check = _run_output(launch.command + ["-c", "import litellm"], cwd=claris_root)
    if check.returncode == 0:
        return

    detail = (check.stderr or check.stdout or "").strip()
    raise SystemExit(
        "CLARIS runtime check failed (missing litellm or wrong env).\n"
        f"launcher: {launch.label}\n"
        f"{detail}\n"
        f"Fix: conda activate claris  # or your CLARIS env name\n"
        "     python -c \"import litellm\""
    )


def load_codeql_exe_from_config() -> str | None:
    config_path = SEMANT_FUNC_ROOT / "local_config.yaml"
    if not config_path.is_file():
        return None
    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("CODEQL_EXE:"):
            continue
        value = stripped.split(":", 1)[1].strip()
        if value.startswith(("'", '"')):
            value = value[1:-1]
        return value.strip() or None
    return None


def resolve_codeql_bin(cli_override: str) -> str:
    if cli_override and cli_override != "codeql":
        return str(Path(cli_override).expanduser().resolve())

    from_config = load_codeql_exe_from_config()
    if from_config:
        path = Path(from_config).expanduser().resolve()
        if path.is_file():
            return str(path)

    which = shutil.which("codeql")
    if which:
        return str(Path(which).resolve())

    return cli_override


def _pack_cache_root() -> Path:
    return Path.home() / ".codeql" / "packages"


def _pack_installed(pack_name: str, version: str) -> bool:
    scope, name = pack_name.split("/", 1)
    marker = _pack_cache_root() / scope / name / version / "qlpack.yml"
    return marker.is_file()


def _parse_claris_lock_packs(lock_path: Path) -> list[str]:
    if not lock_path.is_file():
        return ["codeql/cpp-all@8.0.0", "codeql/cpp-queries@1.5.12"]

    packs: list[str] = []
    current: str | None = None
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        name_match = re.match(r"^\s{2}([\w-]+/[\w-]+):\s*$", line)
        if name_match:
            current = name_match.group(1)
            continue
        version_match = re.match(r"^\s{4}version:\s*([\d.]+)\s*$", line)
        if current and version_match:
            packs.append(f"{current}@{version_match.group(1)}")
            current = None
    return packs


def ensure_claris_query_files(claris_root: Path) -> None:
    external_ql = claris_root / "src" / "queries" / "fetch_external_apis_cpp.ql"
    if not external_ql.is_file():
        raise SystemExit(
            f"Missing required CLARIS query file: {external_ql}\n"
            "Obtain the correct fetch_external_apis_cpp.ql and place it at the path above."
        )


def ensure_codeql_packs(codeql_bin: str, claris_root: Path) -> None:
    lock_path = claris_root / "src" / "rf_workflow" / "config" / "codeql_pack" / "codeql-pack.lock.yml"
    packs = _parse_claris_lock_packs(lock_path)
    missing = [spec for spec in packs if not _pack_installed(*spec.rsplit("@", 1))]

    if not missing:
        print("codeql packs: cache ok")
        return

    print(f"codeql packs: downloading {len(missing)} missing pack(s)...")
    result = subprocess.run(
        [codeql_bin, "pack", "download", *missing],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise SystemExit(f"Failed to download CodeQL packs.\n{detail}")

    still_missing = [spec for spec in missing if not _pack_installed(*spec.rsplit("@", 1))]
    if still_missing:
        raise SystemExit(
            "CodeQL packs are still missing after download:\n- " + "\n- ".join(still_missing)
        )
    print("codeql packs: ready")


def preflight_claris_llm(claris_root: Path) -> None:
    local_cfg = claris_root / "src" / "models" / "llm_config.local.json"
    if local_cfg.is_file():
        return
    if os.environ.get("CLARIS_API_KEY", "").strip():
        return
    raise SystemExit(
        "CLARIS LLM is not configured.\n"
        f"Create {local_cfg}\n"
        "or set: CLARIS_API_URL, CLARIS_API_KEY, CLARIS_MODEL"
    )


def preflight(job_dir: Path) -> tuple[Path, Path]:
    src = job_dir / "codeql" / "src"
    db = job_dir / "codeql" / "db"
    problems: list[str] = []

    if not src.is_dir():
        problems.append(f"missing source directory: {src}")
    elif not any(src.glob("*.c")):
        problems.append(f"no .c files under: {src}")

    if not (db / "codeql-database.yml").is_file():
        problems.append(f"missing CodeQL database: {db}")

    if problems:
        raise SystemExit("Preflight failed:\n- " + "\n- ".join(problems))

    return src.resolve(), db.resolve()


# =========================================================================
# 配置生成 / CLARIS config.json generation
# =========================================================================
def build_claris_config(
    job_dir: Path,
    src: Path,
    db: Path,
    *,
    codeql_bin: str,
    run_id: str,
    llm_threads: int = DEFAULT_LLM_THREADS,
    upstream_constraint: bool | None = None,
) -> dict:
    if upstream_constraint is None:
        # 默认开启上游约束校验（CLARIS Step 2.1）。已知问题：Palimpsest 反编译产物的
        # 调用/字符串特征常不匹配 CLARIS 的 web/listener 上游规则，可能过滤掉真实源；
        # 且该校验依赖 PATH 上的 Git-grep。可用 --skip-upstream-constraint 关闭。
        upstream_constraint = True
    claris_dir = job_dir / "claris"
    source_out = claris_dir / "output" / "source_agent"
    sink_out = claris_dir / "output" / "taint_sink"
    results_dir = source_out / "results"

    return {
        "project_name": job_dir.name,
        "run_id": run_id,
        "language": "cpp",
        "output_root": _posix(claris_dir / "output_root"),
        "codeql_build": {"enabled": False},
        "stages": {
            "source_classification": True,
            "upstream_constraint_validation": upstream_constraint,
            "taint_sink_classification": True,
            "taint_analysis": True,
            "function_pair_reduction": True,
        },
        "source_agent": {
            "database": _posix(db),
            "source_root": _posix(src),
            "output_dir": _posix(source_out),
            "output_sink_dir": _posix(source_out),
            "codeql_bin": codeql_bin,
            "call_llm": True,
            "context_window": 120000,
            "threads": llm_threads,
            "codeql_worker_count": min(4, max(1, llm_threads)),
            "codeql_runtime_root": _posix(claris_dir / "codeql_runtime"),
            "cleanup_codeql_runtime": True,
            "max_body_lines": 500,
            "tail_lines": 40,
            "callsite_window": 30,
            "max_rounds_per_api": 8,
            "enable_source_rule_enrichment": True,
            "enable_rule_based_source_filter": True,
            "fallback_source_on_failure": False,
            "log_level": "INFO",
        },
        "taint_sink_agent": {
            "database": _posix(db),
            "source_root": _posix(src),
            "output_dir": _posix(sink_out),
            "codeql_bin": codeql_bin,
            "call_llm": True,
            "context_window": 120000,
            "threads": llm_threads,
            "codeql_worker_count": min(4, max(1, llm_threads)),
            "codeql_runtime_root": _posix(claris_dir / "codeql_runtime"),
            "cleanup_codeql_runtime": True,
            "max_body_lines": 500,
            "tail_lines": 40,
            "callsite_window": 30,
            "max_rounds_per_api": 8,
            "log_level": "INFO",
        },
        "func_pair_validation": {
            "output_dir": _posix(results_dir),
            "sarif_path": _posix(results_dir / "codeql.sarif"),
            "func_pairs_path": _posix(results_dir / "func_pairs.json"),
            "parallel_workers": 4,
        },
        "model_config": {
            "pcsolver_model": "gpt-4o-mini",
            "z3solver_model": "gpt-4o-mini",
        },
        "use_any_sink": False,
        "ablation_study": 5,
        "use_external_apis": True,
    }


# =========================================================================
# 报告与执行入口 / Reporting, CLI & execution
# =========================================================================
def write_report(
    job_dir: Path,
    *,
    status: str,
    exit_code: int | None,
    claris_result_path: Path | None,
    config_path: Path,
    log_path: Path,
    claris_launcher: str,
) -> Path:
    report = {
        "job_id": job_dir.name,
        "status": status,
        "claris_exit_code": exit_code,
        "claris_launcher": claris_launcher,
        "claris_config": _posix(config_path),
        "claris_log": _posix(log_path),
        "artifacts": {},
    }

    if claris_result_path and claris_result_path.is_file():
        payload = json.loads(claris_result_path.read_text(encoding="utf-8"))
        report["artifacts"] = payload.get("outputs", {})
        report["claris_result"] = _posix(claris_result_path)

    report_path = job_dir / "claris" / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run CLARIS on a Palimpsest job output.")
    parser.add_argument("--job-dir", required=True, help="Job output directory, e.g. output/r9000_udhcpd")
    parser.add_argument(
        "--claris-root",
        default=str(DEFAULT_CLARIS_ROOT),
        help=f"CLARIS project root (default: {DEFAULT_CLARIS_ROOT})",
    )
    parser.add_argument(
        "--claris-conda-env",
        default=os.environ.get("CLARIS_CONDA_ENV", DEFAULT_CLARIS_CONDA_ENV),
        help=f"CLARIS conda env name (default: {DEFAULT_CLARIS_CONDA_ENV})",
    )
    parser.add_argument(
        "--claris-python",
        default="",
        help="Explicit CLARIS python.exe; overrides conda auto-detection",
    )
    parser.add_argument(
        "--no-conda-run",
        action="store_true",
        help="Do not use `conda run`; resolve python.exe from conda env path instead",
    )
    parser.add_argument(
        "--codeql-bin",
        default="",
        help="CodeQL CLI path (default: CODEQL_EXE from local_config.yaml, else PATH)",
    )
    parser.add_argument(
        "--skip-pack-sync",
        action="store_true",
        help="Skip automatic CodeQL pack download for CLARIS lock file",
    )
    parser.add_argument("--run-id", default="", help="CLARIS run id (default: timestamp)")
    parser.add_argument(
        "--llm-threads",
        type=int,
        default=DEFAULT_LLM_THREADS,
        help=f"Parallel LLM workers for source/sink agents (default: {DEFAULT_LLM_THREADS})",
    )
    parser.add_argument(
        "--skip-upstream-constraint",
        action="store_true",
        help="Disable upstream constraint (default for Palimpsest jobs)",
    )
    parser.add_argument(
        "--enable-upstream-constraint",
        action="store_true",
        help="Enable CLARIS upstream constraint (Step 2.1); requires Git grep on PATH",
    )
    parser.add_argument(
        "--default-upstream",
        choices=("on", "off"),
        default=os.environ.get("DEFAULT_UPSTREAM", "on"),
        help="Default upstream constraint when neither --skip-upstream-constraint nor --enable-upstream-constraint is provided (on/off). Can also be set via DEFAULT_UPSTREAM env var.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only generate claris/config.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    job_dir = Path(args.job_dir).expanduser()
    if not job_dir.is_absolute():
        job_dir = (SEMANT_FUNC_ROOT / job_dir).resolve()

    claris_root = Path(args.claris_root).expanduser().resolve()
    run_program = claris_root / "run_program.py"
    if not run_program.is_file():
        raise SystemExit(f"CLARIS entrypoint not found: {run_program}")

    launch = resolve_claris_launch(
        python_override=args.claris_python or None,
        conda_env=args.claris_conda_env,
        prefer_conda_run=not args.no_conda_run,
    )
    preflight_claris_runtime(launch, claris_root)
    preflight_claris_llm(claris_root)

    codeql_bin = resolve_codeql_bin(args.codeql_bin or "codeql")
    if not Path(codeql_bin).is_file() and not shutil.which(codeql_bin):
        raise SystemExit(f"CodeQL executable not found: {codeql_bin}")

    if not args.skip_pack_sync:
        ensure_codeql_packs(codeql_bin, claris_root)
    ensure_claris_query_files(claris_root)

    src, db = preflight(job_dir)
    run_id = args.run_id or datetime.now().strftime("%Y%m%d_%H%M%S")

    claris_dir = job_dir / "claris"
    claris_dir.mkdir(parents=True, exist_ok=True)
    config_path = claris_dir / "config.json"
    log_path = claris_dir / "run.log"

    if args.llm_threads < 1:
        raise SystemExit("--llm-threads must be >= 1")

    if args.skip_upstream_constraint and args.enable_upstream_constraint:
        raise SystemExit("Use only one of --skip-upstream-constraint or --enable-upstream-constraint")

    upstream_constraint: bool | None = None
    if args.skip_upstream_constraint:
        upstream_constraint = False
    elif args.enable_upstream_constraint:
        upstream_constraint = True
    else:
        upstream_constraint = args.default_upstream == "on"

    preflight_claris_output_dirs(job_dir)
    git_usr_bin = find_git_usr_bin()

    config = build_claris_config(
        job_dir,
        src,
        db,
        codeql_bin=codeql_bin,
        run_id=run_id,
        llm_threads=args.llm_threads,
        upstream_constraint=upstream_constraint,
    )
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"config: {config_path}")
    print(f"codeql bin: {codeql_bin}")
    print(f"claris launcher: {launch.label}")
    print(f"llm threads: {args.llm_threads}")
    if config["stages"]["upstream_constraint_validation"]:
        print(f"upstream constraint: enabled (grep: {git_usr_bin or 'PATH'})")
    else:
        if args.skip_upstream_constraint:
            reason = "--skip-upstream-constraint"
        elif args.enable_upstream_constraint:
            reason = "--enable-upstream-constraint"
        else:
            reason = f"default {args.default_upstream}"
        print(f"upstream constraint: disabled ({reason})")

    if args.dry_run:
        print("dry-run: skipped CLARIS execution")
        return 0

    command = launch.command + [str(run_program), "--config", str(config_path)]
    print(f"running: {' '.join(command)}")

    subprocess_env = build_claris_subprocess_env()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(str(log_path), "w", encoding="utf-8") as log_f:
        process = subprocess.Popen(
            command,
            cwd=str(claris_root),
            env=subprocess_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        combined_lines: list[str] = []
        for line in process.stdout:
            combined_lines.append(line)
            sys.stdout.write(line)
            sys.stdout.flush()
            log_f.write(line)
        process.wait()

    combined = "".join(combined_lines)
    completed = subprocess.CompletedProcess(
        args=command,
        returncode=process.returncode,
        stdout=combined,
        stderr="",
    )

    result_src = claris_root / "run_program_result.json"
    result_dst = claris_dir / "run_program_result.json"
    if result_src.is_file():
        shutil.copy2(result_src, result_dst)

    status = "success" if completed.returncode == 0 else "failed"
    report_path = write_report(
        job_dir,
        status=status,
        exit_code=completed.returncode,
        claris_result_path=result_dst if result_dst.is_file() else None,
        config_path=config_path,
        log_path=log_path,
        claris_launcher=launch.label,
    )

    print(f"report: {report_path}")
    if completed.returncode != 0:
        print(f"CLARIS failed with exit code {completed.returncode}", file=sys.stderr)
        print(f"see log: {log_path}", file=sys.stderr)
        tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-20:]
        if tail:
            print("last log lines:", file=sys.stderr)
            for line in tail:
                print(line, file=sys.stderr)
        return completed.returncode

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
