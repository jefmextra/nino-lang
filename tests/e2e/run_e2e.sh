#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 is required by tests/e2e/run_e2e.sh but was not found in PATH." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
E2E_DIR="$SCRIPT_DIR"
TMP_ROOT="$E2E_DIR/.tmp"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

cd "$REPO_ROOT"

set +e
python3 - "$REPO_ROOT" "$E2E_DIR" "$@" <<'PYEOF'
import argparse
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
VALID_MODES = {
    "build-run",
    "run",
    "compile-fail",
    "c11-audit",
    "verify-proof",
    "binary-inspect",
    "command-check",
}
DEFAULT_C11_FORBID = [
    "__auto_type",
    "__typeof__",
    "({",
    "__asm__",
    "__uint128_t",
    "__sync_",
]


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def to_str_list(val):
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if x is not None]
    return [str(val)]


def parse_args(argv):
    parser = argparse.ArgumentParser(description="NinoLang Cross-Platform E2E Runner (POSIX)")
    parser.add_argument("--tier", action="append", default=[], help="Filter by tier: 1|2|3|4|all (comma-separated or repeated)")
    parser.add_argument("--feature", action="append", default=[], help="Filter by feature F1..F16 (comma-separated or repeated)")
    parser.add_argument("--id", action="append", default=[], help="Filter by test ID")
    parser.add_argument("--ninoc", default="", help="Override ninoc compiler path")
    parser.add_argument("--strict-compliance", action="store_true", help="Enforce strict compliance checks")
    parser.add_argument("--bootstrap", action="store_true", help="Allow bootstrap fallback from bootstrap/ninoc_seed.c")
    parser.add_argument("--verbose", action="store_true", help="Verbose diagnostic output")
    return parser.parse_args(argv)


def run_bounded(cmd_list, cwd, timeout_sec=30, stdin_text=None):
    try:
        proc = subprocess.run(
            cmd_list,
            cwd=cwd,
            input=stdin_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        return {
            "exit_code": proc.returncode,
            "stdout": strip_ansi(proc.stdout),
            "stderr": strip_ansi(proc.stderr),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        out_s = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err_s = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "exit_code": -1,
            "stdout": strip_ansi(out_s),
            "stderr": strip_ansi(err_s),
            "timed_out": True,
        }


def run_e2e_compliance(e2e_dir: str, tmp_root: str, strict: bool):
    nino_files = []
    for root, dirs, files in os.walk(e2e_dir):
        dirs[:] = sorted(d for d in dirs if os.path.abspath(os.path.join(root, d)) != os.path.abspath(tmp_root))
        for fname in sorted(files):
            if fname.endswith(".nino"):
                nino_files.append(os.path.join(root, fname))
    nino_files.sort()

    violations = []
    for fpath in nino_files:
        with open(fpath, "rb") as fh:
            data = fh.read()
        n = len(data)
        line = 1
        in_str = False
        in_lcmt = False
        in_bcmt = False
        idx = 0
        while idx < n:
            b0 = data[idx]
            if b0 == 226 and idx + 2 < n:
                if data[idx + 1] == 128 and data[idx + 2] in (147, 148):
                    violations.append(f"{fpath}:{line} Forbidden UTF-8 em/en dash")
            if b0 == 10:
                line += 1
                in_str = False
                in_lcmt = False
                idx += 1
                continue
            if in_lcmt:
                idx += 1
                continue
            if in_bcmt:
                if b0 == 42 and idx + 1 < n and data[idx + 1] == 47:
                    in_bcmt = False
                    idx += 2
                    continue
                idx += 1
                continue
            if in_str:
                if b0 == 92:
                    if idx + 1 < n and data[idx + 1] == 10:
                        line += 1
                    idx += 2
                    continue
                if b0 == 34:
                    in_str = False
                idx += 1
                continue
            if b0 == 34:
                in_str = True
                idx += 1
                continue
            if b0 == 47 and idx + 1 < n and data[idx + 1] == 47:
                in_lcmt = True
                idx += 2
                continue
            if b0 == 47 and idx + 1 < n and data[idx + 1] == 42:
                in_bcmt = True
                idx += 2
                continue
            if b0 == 42 and idx + 1 < n and data[idx + 1] == 47:
                violations.append(f"{fpath}:{line} Unmatched block comment close '*/'")
                idx += 2
                continue
            if b0 == 35:
                if data[idx : idx + 7] == b"#no_std":
                    idx += 7
                else:
                    violations.append(f"{fpath}:{line} Forbidden '#' directive/comment (only #no_std allowed)")
                    idx += 1
                continue
            idx += 1
        if in_bcmt:
            violations.append(f"{fpath}:{line} Unclosed block comment '/*'")

    if strict:
        for root, dirs, files in os.walk(e2e_dir):
            dirs[:] = sorted(d for d in dirs if os.path.abspath(os.path.join(root, d)) != os.path.abspath(tmp_root))
            for fname in sorted(files):
                if fname.endswith((".json", ".ps1", ".sh")):
                    fpath = os.path.join(root, fname)
                    with open(fpath, "rb") as fh:
                        data = fh.read()
                    line = 1
                    for idx, b0 in enumerate(data):
                        if b0 == 10:
                            line += 1
                        elif b0 == 226 and idx + 2 < len(data):
                            if data[idx + 1] == 128 and data[idx + 2] in (147, 148):
                                violations.append(f"{fpath}:{line} Forbidden UTF-8 em/en dash")

    return len(nino_files), violations


def resolve_gcc(is_windows: bool) -> str:
    for env_name in ("NINO_CC", "CC"):
        val = os.environ.get(env_name, "").strip()
        if val:
            if os.path.exists(val):
                return os.path.abspath(val)
            found = shutil.which(val)
            if found:
                return found
    found = shutil.which("gcc")
    if found:
        return found
    if is_windows:
        for fb in (
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Programs\CLion\bin\mingw\bin\gcc.exe"),
            r"C:\msys64\mingw64\bin\gcc.exe",
            r"C:\msys64\ucrt64\bin\gcc.exe",
        ):
            if os.path.exists(fb):
                return fb
    return ""


def resolve_ninoc(repo_root: str, tmp_root: str, override: str, allow_bootstrap: bool, gcc_bin: str, is_windows: bool) -> str:
    exe_ext = ".exe" if is_windows else ""
    if override:
        cand = override if os.path.isabs(override) else os.path.join(repo_root, override)
        if os.path.exists(cand):
            return os.path.abspath(cand)
        if os.path.exists(override):
            return os.path.abspath(override)
        found = shutil.which(override)
        if found:
            return found
        raise RuntimeError(f"Specified ninoc compiler not found: {override}")

    for cand in (
        os.path.join(repo_root, "ninoc" + exe_ext),
        os.path.join(repo_root, "bin", "ninoc" + exe_ext),
    ):
        if os.path.exists(cand):
            return os.path.abspath(cand)

    if allow_bootstrap:
        seed_c = os.path.join(repo_root, "bootstrap", "ninoc_seed.c")
        if not os.path.exists(seed_c):
            raise RuntimeError(f"Bootstrap requested, but missing {seed_c}")
        if not gcc_bin:
            raise RuntimeError("Bootstrap requested, but no GCC compiler was found")
        os.makedirs(tmp_root, exist_ok=True)
        stage1_out = os.path.join(tmp_root, "stage1" + exe_ext)
        link_libs = ["-lm", "-lgdi32", "-luser32", "-lbcrypt", "-lws2_32"] if is_windows else ["-lm", "-lpthread", "-ldl"]
        res = run_bounded([gcc_bin, "-O2", "-std=c11", seed_c, "-o", stage1_out] + link_libs, repo_root, 120)
        if res["timed_out"] or res["exit_code"] != 0 or not os.path.exists(stage1_out):
            raise RuntimeError(f"Failed to compile bootstrap/ninoc_seed.c:\n{res['stdout']}\n{res['stderr']}")
        return stage1_out

    raise RuntimeError(f"Could not locate ninoc compiler (checked ./ninoc{exe_ext}, ./bin/ninoc{exe_ext}). Pass --ninoc <path> or --bootstrap.")


def find_ebpf_exec_packet_end(c_source: str) -> int:
    search_pos = 0
    n = len(c_source)
    while True:
        ebpf_idx = c_source.find("ebpf_exec_packet(", search_pos)
        if ebpf_idx < 0:
            return -1
        scan = ebpf_idx + len("ebpf_exec_packet(")
        in_str = False
        in_chr = False
        in_lc = False
        in_bc = False
        body_start = -1
        while scan < n:
            ch = c_source[scan]
            if in_lc:
                if ch == "\n":
                    in_lc = False
                scan += 1
                continue
            if in_bc:
                if ch == "*" and scan + 1 < n and c_source[scan + 1] == "/":
                    in_bc = False
                    scan += 2
                    continue
                scan += 1
                continue
            if in_str:
                if ch == "\\" and scan + 1 < n:
                    scan += 2
                    continue
                if ch == '"':
                    in_str = False
                scan += 1
                continue
            if in_chr:
                if ch == "\\" and scan + 1 < n:
                    scan += 2
                    continue
                if ch == "'":
                    in_chr = False
                scan += 1
                continue
            if ch == "/" and scan + 1 < n and c_source[scan + 1] == "/":
                in_lc = True
                scan += 2
                continue
            if ch == "/" and scan + 1 < n and c_source[scan + 1] == "*":
                in_bc = True
                scan += 2
                continue
            if ch == '"':
                in_str = True
                scan += 1
                continue
            if ch == "'":
                in_chr = True
                scan += 1
                continue
            if ch == ";":
                break
            if ch == "{":
                body_start = scan
                break
            scan += 1
        if body_start < 0:
            search_pos = ebpf_idx + len("ebpf_exec_packet(")
            continue
        depth = 0
        k = body_start
        while k < n:
            ch = c_source[k]
            if in_lc:
                if ch == "\n":
                    in_lc = False
                k += 1
                continue
            if in_bc:
                if ch == "*" and k + 1 < n and c_source[k + 1] == "/":
                    in_bc = False
                    k += 2
                    continue
                k += 1
                continue
            if in_str:
                if ch == "\\" and k + 1 < n:
                    k += 2
                    continue
                if ch == '"':
                    in_str = False
                k += 1
                continue
            if in_chr:
                if ch == "\\" and k + 1 < n:
                    k += 2
                    continue
                if ch == "'":
                    in_chr = False
                k += 1
                continue
            if ch == "/" and k + 1 < n and c_source[k + 1] == "/":
                in_lc = True
                k += 2
                continue
            if ch == "/" and k + 1 < n and c_source[k + 1] == "*":
                in_bc = True
                k += 2
                continue
            if ch == '"':
                in_str = True
                k += 1
                continue
            if ch == "'":
                in_chr = True
                k += 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_pos = k + 1
                    while end_pos < n and c_source[end_pos] in ("\r", "\n"):
                        end_pos += 1
                    return end_pos
            k += 1
        return -1


def get_c_scan_text(c_source: str, scope: str) -> str:
    start_idx = 0
    if scope == "generated":
        marker_idx = -1
        for marker in ("/* NINO_RUNTIME_HEADER_END */", "// NINO_RUNTIME_HEADER_END"):
            mpos = c_source.find(marker)
            if mpos >= 0:
                nl_m = c_source.find("\n", mpos)
                marker_idx = (nl_m + 1) if nl_m >= 0 else (mpos + len(marker))
                break
        if marker_idx >= 0:
            start_idx = marker_idx
        else:
            line_idx = 0 if c_source.startswith("#line ") else -1
            if line_idx < 0:
                nl_line = c_source.find("\n#line ")
                if nl_line >= 0:
                    line_idx = nl_line + 1
            after_ebpf = find_ebpf_exec_packet_end(c_source)
            if after_ebpf >= 0:
                if 0 <= line_idx < after_ebpf:
                    start_idx = line_idx
                else:
                    start_idx = after_ebpf
            elif line_idx >= 0:
                start_idx = line_idx
            else:
                raise RuntimeError("Cannot locate generated C boundary for c11_scan_scope='generated' (neither runtime header end nor #line directive found)")

    raw = c_source[start_idx:]
    out = []
    n = len(raw)
    k = 0
    while k < n:
        ch = raw[k]
        if ch == "/" and k + 1 < n and raw[k + 1] == "/":
            out.append(" ")
            k += 2
            while k < n and raw[k] != "\n":
                k += 1
            continue
        if ch == "/" and k + 1 < n and raw[k + 1] == "*":
            out.append(" ")
            k += 2
            while k + 1 < n and not (raw[k] == "*" and raw[k + 1] == "/"):
                k += 1
            k += 2
            continue
        if ch == '"':
            out.append(" ")
            k += 1
            while k < n:
                if raw[k] == "\\" and k + 1 < n:
                    k += 2
                    continue
                if raw[k] == '"':
                    k += 1
                    break
                k += 1
            continue
        if ch == "'":
            out.append(" ")
            k += 1
            while k < n:
                if raw[k] == "\\" and k + 1 < n:
                    k += 2
                    continue
                if raw[k] == "'":
                    k += 1
                    break
                k += 1
            continue
        out.append(ch)
        k += 1
    return "".join(out)


def c11_token_present(scan_text: str, tok: str) -> bool:
    if tok == "({":
        return re.search(r"\(\s*\{", scan_text) is not None
    if tok == "__sync_":
        return re.search(r"\b__sync_[A-Za-z0-9_]*", scan_text) is not None
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok):
        return re.search(r"\b" + re.escape(tok) + r"\b", scan_text) is not None
    return tok in scan_text


def load_and_validate_manifests(manifest_dir: str):
    if not os.path.isdir(manifest_dir):
        raise RuntimeError(f"Manifest directory not found: {manifest_dir}")
    files = sorted(glob.glob(os.path.join(manifest_dir, "*.json")))
    if not files:
        raise RuntimeError(f"No manifest files found in {manifest_dir}")
    seen_ids = set()
    all_tests = []
    for mf in files:
        with open(mf, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        entries = data if isinstance(data, list) else data.get("tests")
        if not isinstance(entries, list):
            raise RuntimeError(f"Manifest {os.path.basename(mf)} missing 'tests' array")
        for t in entries:
            tid = t.get("id", "")
            tier = t.get("tier")
            feat = t.get("feature")
            mode = t.get("mode", "")
            if not isinstance(tid, str) or not tid.strip():
                raise RuntimeError(f"Manifest {os.path.basename(mf)} contains entry missing 'id'")
            if tid in seen_ids:
                raise RuntimeError(f"Duplicate test id '{tid}' detected in {os.path.basename(mf)}")
            seen_ids.add(tid)
            if isinstance(tier, bool) or not isinstance(tier, int) or tier not in (1, 2, 3, 4):
                raise RuntimeError(f"Test '{tid}' in {os.path.basename(mf)} has invalid 'tier': {tier}")
            if not to_str_list(feat):
                raise RuntimeError(f"Test '{tid}' in {os.path.basename(mf)} missing 'feature'")
            if mode not in VALID_MODES:
                raise RuntimeError(f"Test '{tid}' in {os.path.basename(mf)} has invalid 'mode': {mode}")
            all_tests.append(t)
    return all_tests


def stage_source(e2e_dir: str, repo_root: str, rel_source: str, stage_dir: str) -> str:
    os.makedirs(stage_dir, exist_ok=True)
    cand_e2e = os.path.join(e2e_dir, rel_source)
    cand_repo = os.path.join(repo_root, rel_source)
    if os.path.exists(cand_e2e):
        src_abs = os.path.abspath(cand_e2e)
    elif os.path.exists(cand_repo):
        src_abs = os.path.abspath(cand_repo)
    else:
        raise RuntimeError(f"Source file not found: {rel_source}")
    dst = os.path.join(stage_dir, os.path.basename(src_abs))
    shutil.copy2(src_abs, dst)
    return dst


def check_output_assertions(stdout_s, stderr_s, expect_stdout, forbid_stdout, forbid_stderr, expect_combined, expect_any_combined):
    reasons = []
    combined = stdout_s + "\n" + stderr_s
    for s in to_str_list(expect_stdout):
        if s not in stdout_s:
            reasons.append(f"Missing expected stdout substring: '{s}'")
    for s in to_str_list(forbid_stdout):
        if s in stdout_s:
            reasons.append(f"Found forbidden stdout substring: '{s}'")
    for s in to_str_list(forbid_stderr):
        if s in stderr_s:
            reasons.append(f"Found forbidden stderr substring: '{s}'")
    for s in to_str_list(expect_combined):
        if s not in combined:
            reasons.append(f"Missing expected diagnostic substring: '{s}'")
    any_list = to_str_list(expect_any_combined)
    if any_list:
        comb_lower = combined.lower()
        if not any(s.lower() in comb_lower for s in any_list):
            reasons.append(f"None of expected diagnostic markers matched: {any_list}")
    return reasons


def main():
    repo_root = os.path.abspath(sys.argv[1])
    e2e_dir = os.path.abspath(sys.argv[2])
    args = parse_args(sys.argv[3:])
    tmp_root = os.path.join(e2e_dir, ".tmp")
    manifest_dir = os.path.join(e2e_dir, "manifests")
    is_windows = platform.system().lower().startswith("win")
    exe_ext = ".exe" if is_windows else ""
    link_libs = ["-lm", "-lgdi32", "-luser32", "-lbcrypt", "-lws2_32"] if is_windows else ["-lm", "-lpthread", "-ldl"]

    print("=" * 80)
    print("NinoLang E2E Test Harness (POSIX)")
    print(f"Repository: {repo_root}")
    print("=" * 80)

    nino_cnt, violations = run_e2e_compliance(e2e_dir, tmp_root, args.strict_compliance)
    if violations:
        print(f"[e2e-compliance] FAIL ({len(violations)} violation(s) across {nino_cnt} .nino files):")
        for v in violations:
            print(f"  {v}")
        return 1
    print(f"[e2e-compliance] PASS ({nino_cnt} .nino files checked)")

    try:
        all_tests = load_and_validate_manifests(manifest_dir)

        tier_tokens = []
        for item in args.tier:
            for p in item.split(","):
                if p.strip():
                    tier_tokens.append(p.strip().lower())
        tier_set = None
        if tier_tokens and "all" not in tier_tokens:
            tier_set = set(tier_tokens)
        feat_set = set()
        for item in args.feature:
            for p in item.split(","):
                if p.strip():
                    feat_set.add(p.strip().upper())
        id_set = set()
        for item in args.id:
            for p in item.split(","):
                if p.strip():
                    id_set.add(p.strip())

        selected = []
        for t in all_tests:
            if tier_set is not None and str(t["tier"]) not in tier_set:
                continue
            if feat_set:
                t_feats = {f.upper() for f in to_str_list(t["feature"])}
                if not (feat_set & t_feats):
                    continue
            if id_set and t["id"] not in id_set:
                continue
            selected.append(t)

        if not selected:
            print("No tests matched the specified filters.")
            return 1

        gcc_bin = resolve_gcc(is_windows)
        ninoc_bin = resolve_ninoc(repo_root, tmp_root, args.ninoc, args.bootstrap, gcc_bin, is_windows)

        print(f"Compiler : {ninoc_bin}")
        print(f"GCC      : {gcc_bin if gcc_bin else '(not found)'}")
        print(f"Selected : {len(selected)} test(s)")
        print("-" * 80)

        tier_pass = {1: 0, 2: 0, 3: 0, 4: 0}
        tier_fail = {1: 0, 2: 0, 3: 0, 4: 0}
        total_pass = 0
        total_fail = 0

        for t in selected:
            tid = t["id"]
            tier = int(t["tier"])
            mode = t["mode"]
            src_rel = t.get("source", "")
            flags = to_str_list(t.get("flags"))
            run_args = to_str_list(t.get("args"))
            timeout_sec = int(t.get("timeout_sec", 30))
            stdin_text = t.get("stdin")
            safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", tid)
            stage_dir = os.path.join(tmp_root, safe_id)
            shutil.rmtree(stage_dir, ignore_errors=True)
            os.makedirs(stage_dir, exist_ok=True)

            fail_reasons = []
            diag_parts = []

            try:
                if mode == "build-run":
                    staged = stage_source(e2e_dir, repo_root, src_rel, stage_dir)
                    stem = os.path.splitext(os.path.basename(staged))[0]
                    bin_path = os.path.join(stage_dir, stem + exe_ext)
                    bres = run_bounded([ninoc_bin, "build", staged, "-o", bin_path] + flags, repo_root, timeout_sec)
                    diag_parts.append(f"BUILD exit={bres['exit_code']}\n{bres['stdout']}\n{bres['stderr']}")
                    if bres["timed_out"]:
                        fail_reasons.append(f"Build timed out after {timeout_sec}s")
                    elif bres["exit_code"] != 0:
                        fail_reasons.append(f"Build failed with exit {bres['exit_code']}")
                    elif not os.path.exists(bin_path):
                        fail_reasons.append(f"Expected compiled binary not found: {bin_path}")
                    else:
                        for s in to_str_list(t.get("expect_build_stdout")):
                            if s not in bres["stdout"]:
                                fail_reasons.append(f"Missing build stdout substring: '{s}'")
                        rres = run_bounded([bin_path] + run_args, repo_root, timeout_sec, stdin_text)
                        diag_parts.append(f"RUN exit={rres['exit_code']}\n{rres['stdout']}\n{rres['stderr']}")
                        exp_nonzero = bool(t.get("expect_nonzero", False))
                        exp_exit = int(t.get("expect_exit", 0))
                        if rres["timed_out"]:
                            fail_reasons.append(f"Runtime execution timed out after {timeout_sec}s")
                        elif exp_nonzero:
                            if rres["exit_code"] == 0:
                                fail_reasons.append("Expected non-zero exit code, got 0")
                        elif rres["exit_code"] != exp_exit:
                            fail_reasons.append(f"Expected exit {exp_exit}, got {rres['exit_code']}")
                        fail_reasons.extend(check_output_assertions(
                            rres["stdout"], rres["stderr"],
                            t.get("expect_stdout"), t.get("forbid_stdout"), t.get("forbid_stderr"),
                            None, None,
                        ))

                elif mode == "run":
                    staged = stage_source(e2e_dir, repo_root, src_rel, stage_dir)
                    rres = run_bounded([ninoc_bin, "run", staged] + flags, repo_root, timeout_sec, stdin_text)
                    diag_parts.append(f"RUN exit={rres['exit_code']}\n{rres['stdout']}\n{rres['stderr']}")
                    exp_nonzero = bool(t.get("expect_nonzero", False))
                    exp_exit = int(t.get("expect_exit", 0))
                    if rres["timed_out"]:
                        fail_reasons.append(f"Execution timed out after {timeout_sec}s")
                    elif exp_nonzero:
                        if rres["exit_code"] == 0:
                            fail_reasons.append("Expected non-zero exit code, got 0")
                    elif rres["exit_code"] != exp_exit:
                        fail_reasons.append(f"Expected exit {exp_exit}, got {rres['exit_code']}")
                    fail_reasons.extend(check_output_assertions(
                        rres["stdout"], rres["stderr"],
                        t.get("expect_stdout"), t.get("forbid_stdout"), t.get("forbid_stderr"),
                        None, None,
                    ))

                elif mode == "compile-fail":
                    staged = stage_source(e2e_dir, repo_root, src_rel, stage_dir)
                    stem = os.path.splitext(os.path.basename(staged))[0]
                    bin_path = os.path.join(stage_dir, stem + exe_ext)
                    bres = run_bounded([ninoc_bin, "build", staged, "-o", bin_path] + flags, repo_root, timeout_sec)
                    diag_parts.append(f"COMPILE-FAIL exit={bres['exit_code']}\n{bres['stdout']}\n{bres['stderr']}")
                    if bres["timed_out"]:
                        fail_reasons.append(f"Compile timed out after {timeout_sec}s")
                    elif bres["exit_code"] == 0:
                        fail_reasons.append("Expected compilation failure (exit != 0), got exit 0")
                    if bool(t.get("forbid_binary", True)) and os.path.exists(bin_path):
                        fail_reasons.append(f"Expected no output binary on compile-fail, but found {bin_path}")
                    forbid_out = to_str_list(t.get("forbid_stdout"))
                    if bool(t.get("require_frontend_reject", False)):
                        for marker in ("Semantic Check  : [", "Native Codegen", "BACKEND COMPILATION FAILED"):
                            if marker not in forbid_out:
                                forbid_out.append(marker)
                    fail_reasons.extend(check_output_assertions(
                        bres["stdout"], bres["stderr"],
                        t.get("expect_stdout"), forbid_out, t.get("forbid_stderr"),
                        t.get("expect_stderr_or_stdout"), t.get("expect_any_stderr_or_stdout"),
                    ))

                elif mode == "c11-audit":
                    staged = stage_source(e2e_dir, repo_root, src_rel, stage_dir)
                    stem = os.path.splitext(os.path.basename(staged))[0]
                    bin_path = os.path.join(stage_dir, stem + exe_ext)
                    bres = run_bounded([ninoc_bin, "build", staged, "-o", bin_path] + flags, repo_root, timeout_sec)
                    diag_parts.append(f"BUILD exit={bres['exit_code']}\n{bres['stdout']}\n{bres['stderr']}")
                    emitted_c = staged + ".c"
                    if bres["timed_out"]:
                        fail_reasons.append(f"Build timed out after {timeout_sec}s")
                    elif bres["exit_code"] != 0:
                        fail_reasons.append(f"Build failed with exit {bres['exit_code']}")
                    elif not os.path.exists(emitted_c):
                        fail_reasons.append(f"Emitted C file not found: {emitted_c}")
                    else:
                        with open(emitted_c, "r", encoding="utf-8", errors="replace") as fh:
                            c_text = fh.read()
                        scan_scope = str(t.get("c11_scan_scope", "generated"))
                        scan_text = get_c_scan_text(c_text, scan_scope)
                        forbid_tokens = to_str_list(t.get("c11_forbid")) or to_str_list(t.get("forbid_c_tokens")) or DEFAULT_C11_FORBID
                        for tok in forbid_tokens:
                            if c11_token_present(scan_text, tok):
                                fail_reasons.append(f"Forbidden GNU/non-C11 token '{tok}' found in emitted C (scope={scan_scope})")

                        do_pedantic = bool(t.get("pedantic_c11_compile", t.get("expect_c11_compile", True)))
                        exec_path = bin_path
                        if do_pedantic:
                            if not gcc_bin:
                                fail_reasons.append("Pedantic C11 compile requested, but no GCC compiler found")
                            else:
                                ped_bin = os.path.join(stage_dir, stem + "_pedantic" + exe_ext)
                                ped_args = [gcc_bin, "-std=c11", "-pedantic-errors", "-Wall", "-Wextra"]
                                if "--strict-c11" in flags or "-strict-c11" in flags:
                                    ped_args.append("-DNINO_STRICT_C11=1")
                                ped_args.extend([emitted_c, "-o", ped_bin] + link_libs)
                                pres = run_bounded(ped_args, repo_root, timeout_sec)
                                diag_parts.append(f"PEDANTIC-GCC exit={pres['exit_code']}\n{pres['stdout']}\n{pres['stderr']}")
                                if pres["timed_out"]:
                                    fail_reasons.append(f"Pedantic GCC compile timed out after {timeout_sec}s")
                                elif pres["exit_code"] != 0 or not os.path.exists(ped_bin):
                                    fail_reasons.append(f"GCC -std=c11 -pedantic-errors failed (exit {pres['exit_code']})")
                                else:
                                    exec_path = ped_bin

                        if not fail_reasons and os.path.exists(exec_path):
                            rres = run_bounded([exec_path] + run_args, repo_root, timeout_sec, stdin_text)
                            diag_parts.append(f"RUN exit={rres['exit_code']}\n{rres['stdout']}\n{rres['stderr']}")
                            exp_exit = int(t.get("expect_exit", 0))
                            if rres["timed_out"]:
                                fail_reasons.append(f"Execution timed out after {timeout_sec}s")
                            elif rres["exit_code"] != exp_exit:
                                fail_reasons.append(f"Expected exit {exp_exit}, got {rres['exit_code']}")
                            fail_reasons.extend(check_output_assertions(
                                rres["stdout"], rres["stderr"],
                                t.get("expect_stdout"), t.get("forbid_stdout"), t.get("forbid_stderr"),
                                None, None,
                            ))

                elif mode == "verify-proof":
                    staged = stage_source(e2e_dir, repo_root, src_rel, stage_dir)
                    stem = os.path.splitext(os.path.basename(staged))[0]
                    bin_path = os.path.join(stage_dir, stem + exe_ext)
                    bres = run_bounded([ninoc_bin, "build", staged, "-o", bin_path] + flags, repo_root, timeout_sec)
                    diag_parts.append(f"BUILD exit={bres['exit_code']}\n{bres['stdout']}\n{bres['stderr']}")
                    if bres["timed_out"]:
                        fail_reasons.append(f"Build timed out after {timeout_sec}s")
                    elif bres["exit_code"] != 0 or not os.path.exists(bin_path):
                        fail_reasons.append(f"Proof build failed with exit {bres['exit_code']}")
                    else:
                        for s in to_str_list(t.get("expect_build_stdout")):
                            if s not in bres["stdout"]:
                                fail_reasons.append(f"Missing build stdout substring: '{s}'")
                        for s in to_str_list(t.get("forbid_stdout")):
                            if s in bres["stdout"]:
                                fail_reasons.append(f"Found forbidden build stdout substring: '{s}'")
                        vres = run_bounded([bin_path, "--verify-proof"], repo_root, timeout_sec)
                        diag_parts.append(f"VERIFY-PROOF exit={vres['exit_code']}\n{vres['stdout']}\n{vres['stderr']}")
                        exp_exit = int(t.get("expect_exit", 0))
                        if vres["timed_out"]:
                            fail_reasons.append(f"--verify-proof timed out after {timeout_sec}s")
                        elif vres["exit_code"] != exp_exit:
                            fail_reasons.append(f"--verify-proof expected exit {exp_exit}, got {vres['exit_code']}")
                        fail_reasons.extend(check_output_assertions(
                            vres["stdout"], vres["stderr"],
                            t.get("expect_stdout"), t.get("forbid_stdout"), t.get("forbid_stderr"),
                            None, None,
                        ))

                        if bool(t.get("tamper_test", False)):
                            emitted_c = staged + ".c"
                            if not os.path.exists(emitted_c):
                                fail_reasons.append(f"Tamper test requires emitted C file {emitted_c}")
                            elif not gcc_bin:
                                fail_reasons.append("Tamper test requires GCC compiler")
                            else:
                                with open(emitted_c, "r", encoding="utf-8", errors="replace") as fh:
                                    c_text = fh.read()
                                m = re.search(r"(_NINO_PCC_SMT_SPEC\s*\[\s*\]\s*=\s*\{\s*)(\d+)", c_text, flags=re.S)
                                if not m:
                                    fail_reasons.append(f"Could not locate _NINO_PCC_SMT_SPEC byte array in {emitted_c}")
                                else:
                                    orig_b = int(m.group(2))
                                    new_b = 36 if orig_b == 35 else 35
                                    tampered_c = c_text[: m.start(2)] + str(new_b) + c_text[m.end(2) :]
                                    tamper_c_path = staged + ".tamper.c"
                                    tamper_bin = os.path.join(stage_dir, stem + "_tamper" + exe_ext)
                                    with open(tamper_c_path, "w", encoding="utf-8") as fh:
                                        fh.write(tampered_c)
                                    tcc = run_bounded([gcc_bin, "-std=c11", "-O2", "-w", tamper_c_path, "-o", tamper_bin] + link_libs, repo_root, timeout_sec)
                                    if tcc["timed_out"] or tcc["exit_code"] != 0 or not os.path.exists(tamper_bin):
                                        fail_reasons.append(f"Compiling tampered C fixture failed (exit {tcc['exit_code']})")
                                    else:
                                        tvres = run_bounded([tamper_bin, "--verify-proof"], repo_root, timeout_sec)
                                        diag_parts.append(f"TAMPER-VERIFY exit={tvres['exit_code']}\n{tvres['stdout']}\n{tvres['stderr']}")
                                        if tvres["timed_out"]:
                                            fail_reasons.append("Tampered --verify-proof timed out")
                                        elif tvres["exit_code"] == 0:
                                            fail_reasons.append("Tampered binary --verify-proof unexpectedly exited 0")

                elif mode == "binary-inspect":
                    staged = stage_source(e2e_dir, repo_root, src_rel, stage_dir)
                    stem = os.path.splitext(os.path.basename(staged))[0]
                    bin_path = os.path.join(stage_dir, stem + exe_ext)
                    bres = run_bounded([ninoc_bin, "build", staged, "-o", bin_path] + flags, repo_root, timeout_sec)
                    diag_parts.append(f"BUILD exit={bres['exit_code']}\n{bres['stdout']}\n{bres['stderr']}")
                    if bres["timed_out"]:
                        fail_reasons.append(f"Build timed out after {timeout_sec}s")
                    elif bres["exit_code"] != 0 or not os.path.exists(bin_path):
                        fail_reasons.append(f"Build failed with exit {bres['exit_code']}")
                    else:
                        with open(bin_path, "rb") as fh:
                            bin_bytes = fh.read()
                        for forbid_s in to_str_list(t.get("rodata_forbid")):
                            if forbid_s.encode("utf-8") in bin_bytes:
                                fail_reasons.append(f"Forbidden plaintext bytes found in compiled binary: '{forbid_s}'")
                        for req_s in to_str_list(t.get("rodata_require")):
                            if req_s.encode("utf-8") not in bin_bytes:
                                fail_reasons.append(f"Required bytes missing from compiled binary: '{req_s}'")
                        exp_stdout_list = to_str_list(t.get("expect_stdout"))
                        run_binary = bool(t.get("run_binary", bool(exp_stdout_list)))
                        if run_binary:
                            rres = run_bounded([bin_path] + run_args, repo_root, timeout_sec, stdin_text)
                            diag_parts.append(f"RUN exit={rres['exit_code']}\n{rres['stdout']}\n{rres['stderr']}")
                            exp_exit = int(t.get("expect_exit", 0))
                            if rres["timed_out"]:
                                fail_reasons.append(f"Binary execution timed out after {timeout_sec}s")
                            elif rres["exit_code"] != exp_exit:
                                fail_reasons.append(f"Expected exit {exp_exit}, got {rres['exit_code']}")
                            fail_reasons.extend(check_output_assertions(
                                rres["stdout"], rres["stderr"],
                                exp_stdout_list, t.get("forbid_stdout"), t.get("forbid_stderr"),
                                None, None,
                            ))

                elif mode == "command-check":
                    staged = ""
                    if src_rel:
                        cand_e2e = os.path.join(e2e_dir, src_rel)
                        cand_repo = os.path.join(repo_root, src_rel)
                        if os.path.exists(cand_e2e):
                            staged = stage_source(e2e_dir, repo_root, src_rel, stage_dir)
                        elif os.path.exists(cand_repo):
                            staged = os.path.abspath(cand_repo)
                        else:
                            staged = src_rel
                    cmd_steps = t.get("commands")
                    if cmd_steps is None:
                        step_args = ([staged] if staged else []) + run_args
                        cmd_steps = [{
                            "cmd": "ninoc",
                            "args": step_args,
                            "stdin": stdin_text,
                            "expect_exit": t.get("expect_exit", 0),
                            "expect_nonzero": t.get("expect_nonzero", False),
                            "expect_stdout": t.get("expect_stdout"),
                            "forbid_stdout": t.get("forbid_stdout"),
                            "forbid_stderr": t.get("forbid_stderr"),
                            "expect_stderr_or_stdout": t.get("expect_stderr_or_stdout"),
                            "expect_any_stderr_or_stdout": t.get("expect_any_stderr_or_stdout"),
                            "timeout_sec": timeout_sec,
                        }]
                    for step_idx, step in enumerate(cmd_steps, start=1):
                        cmd_spec = str(step.get("cmd", "ninoc"))
                        if cmd_spec in ("", "ninoc", "{ninoc}"):
                            exe_to_run = ninoc_bin
                        elif cmd_spec == "{gcc}":
                            exe_to_run = gcc_bin
                        else:
                            exe_to_run = cmd_spec
                        resolved_args = []
                        for ra in to_str_list(step.get("args")):
                            resolved_args.append(
                                ra.replace("{ninoc}", ninoc_bin)
                                .replace("{gcc}", gcc_bin)
                                .replace("{staged}", staged)
                                .replace("{source}", src_rel)
                                .replace("{tmp_dir}", stage_dir)
                                .replace("{repo_root}", repo_root)
                            )
                        step_timeout = int(step.get("timeout_sec", timeout_sec))
                        cres = run_bounded([exe_to_run] + resolved_args, repo_root, step_timeout, step.get("stdin"))
                        diag_parts.append(f"STEP {step_idx} ({exe_to_run} {' '.join(resolved_args)}) exit={cres['exit_code']}\n{cres['stdout']}\n{cres['stderr']}")
                        step_nonzero = bool(step.get("expect_nonzero", False))
                        step_exp_exit = int(step.get("expect_exit", 0))
                        if cres["timed_out"]:
                            fail_reasons.append(f"Command step {step_idx} timed out after {step_timeout}s")
                        elif step_nonzero:
                            if cres["exit_code"] == 0:
                                fail_reasons.append(f"Command step {step_idx} expected non-zero exit, got 0")
                        elif cres["exit_code"] != step_exp_exit:
                            fail_reasons.append(f"Command step {step_idx} expected exit {step_exp_exit}, got {cres['exit_code']}")
                        fail_reasons.extend(check_output_assertions(
                            cres["stdout"], cres["stderr"],
                            step.get("expect_stdout"), step.get("forbid_stdout"), step.get("forbid_stderr"),
                            step.get("expect_stderr_or_stdout"), step.get("expect_any_stderr_or_stdout"),
                        ))
            except Exception as exc:
                fail_reasons.append(f"Runner exception: {exc}")
            finally:
                shutil.rmtree(stage_dir, ignore_errors=True)

            if not fail_reasons:
                total_pass += 1
                tier_pass[tier] += 1
                print(f"[PASS] {tid} (T{tier}, {mode})")
                if args.verbose and diag_parts:
                    print("\n".join(diag_parts))
            else:
                total_fail += 1
                tier_fail[tier] += 1
                print(f"[FAIL] {tid} (T{tier}, {mode})")
                for fr in fail_reasons:
                    print(f"       - {fr}")
                if args.verbose and diag_parts:
                    print("\n".join(diag_parts))

        print("-" * 80)
        print(f"Summary: PASS={total_pass} FAIL={total_fail} TOTAL={total_pass + total_fail}")
        for tk in (1, 2, 3, 4):
            if tier_pass[tk] + tier_fail[tk] > 0:
                print(f"  Tier {tk}: PASS={tier_pass[tk]} FAIL={tier_fail[tk]}")
        print("=" * 80)
        return 1 if total_fail > 0 else 0
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
PYEOF
rc=$?
set -e
exit $rc
