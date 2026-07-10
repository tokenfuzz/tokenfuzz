#!/usr/bin/env python3
"""Build and verify Firefox sanitizer configurations."""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CONFIG = {
    "asan": (".mozconfig", "build-asan", ("enable-address-sanitizer", "enable-fuzzing", "disable-debug")),
    "ubsan": (".mozconfig-ubsan", "build-ubsan", ("enable-undefined-sanitizer", "enable-fuzzing", "disable-debug")),
    "msan": (".mozconfig-msan", "build-msan", ("enable-memory-sanitizer", "enable-fuzzing", "disable-debug")),
    "coverage": (".mozconfig-asan-cov", "build-asan-cov", ("enable-address-sanitizer", "build-asan-cov", "trace-pc-guard")),
}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="build.py")
    modes = result.add_mutually_exclusive_group()
    modes.add_argument("--binaries", action="store_true")
    modes.add_argument("--build", action="store_true")
    result.add_argument("kinds", nargs="*", choices=(*CONFIG, "all"), default=["asan"])
    return result


def llvm_prefix() -> Path | None:
    candidates = []
    if os.environ.get("LLVM_PREFIX"):
        candidates.append(Path(os.environ["LLVM_PREFIX"]))
    candidates.extend(Path(path) for path in ("/opt/homebrew/opt/llvm", "/usr/local/opt/llvm"))
    candidates.extend(Path(path) for path in glob.glob("/usr/lib/llvm-*"))
    candidates.append(Path("/usr/local"))
    clang = shutil.which("clang")
    if clang:
        candidates.append(Path(clang).resolve().parent.parent)
    return next((path for path in candidates if (path / "bin" / "clang").is_file()), None)


def ensure_msan_config(target: Path) -> None:
    path = target / ".mozconfig-msan"
    if path.exists():
        return
    prefix = llvm_prefix()
    if prefix is None:
        raise RuntimeError("could not locate LLVM clang for MSan config; set LLVM_PREFIX")
    path.write_text(
        f"mk_add_options MOZ_OBJDIR=@TOPSRCDIR@/build-msan\n\n"
        f"export PATH=\"{prefix}/bin:/usr/bin:/usr/local/bin:$PATH\"\n\n"
        f"LLVM_PREFIX=\"{prefix}\"\n"
        f"export CC=\"${{LLVM_PREFIX}}/bin/clang\"\n"
        f"export CXX=\"${{LLVM_PREFIX}}/bin/clang++\"\n"
        f"mk_add_options \"export LIBCLANG_PATH=${{LLVM_PREFIX}}/lib\"\n\n"
        "ac_add_options --enable-memory-sanitizer\n"
        "ac_add_options --disable-jemalloc\n"
        "ac_add_options --enable-fuzzing\n\n"
        "ac_add_options --enable-optimize=\"-O2\"\n"
        "ac_add_options --disable-debug\n"
        "ac_add_options --enable-debug-symbols\n\n"
        "ac_add_options --disable-crashreporter\n"
        "ac_add_options --without-wasm-sandboxed-libraries\n"
        "ac_add_options --enable-js-shell\n",
        encoding="utf-8",
    )
    print(f"created {path}")


def msan_supported() -> bool:
    prefix = llvm_prefix()
    if prefix is None:
        return False
    with tempfile.TemporaryDirectory(prefix="ff-bsan-msan-check.") as directory:
        completed = subprocess.run(
            [str(prefix / "bin" / "clang"), "-fsanitize=memory", "-x", "c", "-", "-o", str(Path(directory) / "a.out")],
            input="int main(void) { return 0; }\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if completed.returncode:
            for line in completed.stdout.splitlines():
                print(f"msan preflight: {line}", file=sys.stderr)
        return completed.returncode == 0


def run_mach(target: Path, python: str, mozconfig: str, *args: str, output=None) -> int:
    environment = os.environ.copy()
    if mozconfig != ".mozconfig":
        environment["MOZCONFIG"] = mozconfig
    return subprocess.run(
        [python, "./mach", *args], cwd=target, env=environment,
        stdout=output, stderr=subprocess.STDOUT if output else None, check=False,
    ).returncode


def require_config(target: Path, kind: str, mozconfig: str, required: tuple[str, ...]) -> None:
    path = target / mozconfig
    if not path.is_file():
        raise RuntimeError(f"missing {path} for {kind}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if any(token not in text for token in required):
        raise RuntimeError(f"{mozconfig} has the wrong flags for {kind}")
    if kind == "coverage" and any(
        "enable-fuzzing" in line and not line.lstrip().startswith("#")
        for line in text.splitlines()
    ):
        raise RuntimeError(f"{mozconfig} must not enable fuzzing for coverage")


def has_symbol(binary: Path, pattern: bytes) -> bool:
    completed = subprocess.run(["nm", str(binary)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return pattern in completed.stdout


def browser_binary(target: Path, objdir: str) -> Path:
    mac = target / objdir / "dist" / "Nightly.app" / "Contents" / "MacOS" / "firefox"
    linux = target / objdir / "dist" / "bin" / "firefox"
    return mac if os.access(mac, os.X_OK) else linux


def verify(target: Path, kind: str, objdir: str) -> None:
    if kind in {"asan", "ubsan", "msan"}:
        browser = browser_binary(target, objdir)
        shell = target / objdir / "dist" / "bin" / "js"
        if not os.access(browser, os.X_OK):
            raise RuntimeError(f"{kind.upper()} browser missing")
        if not shell.is_file():
            raise RuntimeError(f"{kind.upper()} JS shell missing")
        if kind == "asan" and (not has_symbol(browser, b"__asan_") or not has_symbol(shell, b"__asan_")):
            raise RuntimeError("ASan build is not instrumented")
        return
    xul = target / objdir / "dist" / "Nightly.app" / "Contents" / "MacOS" / "XUL"
    if not xul.is_file():
        xul = target / objdir / "dist" / "bin" / "libxul.so"
    if not xul.is_file():
        raise RuntimeError("coverage XUL/libxul missing")
    tool = ["otool", "-l", str(xul)] if shutil.which("otool") else ["readelf", "-WS", str(xul)]
    completed = subprocess.run(tool, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if b"__sancov_guards" not in completed.stdout:
        raise RuntimeError("coverage build lacks sancov guards")


def build_one(target: Path, python: str, kind: str, mach_args: list[str], optional_msan: bool) -> None:
    if kind == "msan":
        ensure_msan_config(target)
        if not msan_supported():
            if optional_msan:
                print("skipping msan requested through all; continue with remaining builds", file=sys.stderr)
                return
            raise RuntimeError("MSan is not supported by the selected LLVM clang on this host")
    mozconfig, objdir, required = CONFIG[kind]
    require_config(target, kind, mozconfig, required)
    log_path = Path(tempfile.gettempdir()) / f"ff-bsan-{kind}.log"
    print(f"building {kind} with {mozconfig} -> {objdir}")
    with log_path.open("w", encoding="utf-8") as log_file:
        rc = run_mach(target, python, mozconfig, *mach_args, output=log_file)
    if rc:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if not re.search(r"Clobbering can be performed automatically|The CLOBBER file has been updated", text):
            raise RuntimeError(f"{kind} build failed; see {log_path}")
        print(f"clobber required for {objdir}; retrying once")
        if run_mach(target, python, mozconfig, "clobber"):
            raise RuntimeError(f"{kind} clobber failed")
        with log_path.open("a", encoding="utf-8") as log_file:
            if run_mach(target, python, mozconfig, *mach_args, output=log_file):
                raise RuntimeError(f"{kind} build retry failed; see {log_path}")
    if kind != "coverage":
        with log_path.open("a", encoding="utf-8") as log_file:
            if run_mach(target, python, mozconfig, "gtest", "build", output=log_file):
                raise RuntimeError(f"{kind} gtest build failed; see {log_path}")
    verify(target, kind, objdir)


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    mode = "binaries" if args.binaries or os.environ.get("BUILD_MODE") == "binaries" else "build"
    if os.environ.get("BUILD_MODE", mode) not in {"build", "binaries"}:
        parser().error("BUILD_MODE must be build or binaries")
    kinds = args.kinds or ["asan"]
    optional_msan = "all" in kinds
    if optional_msan:
        kinds = ["asan", "ubsan", "msan", "coverage"]
    target = Path(os.environ.get("FIREFOX_ROOT", "targets/firefox"))
    python = os.environ.get("PYTHON", "python3.12")
    try:
        for kind in dict.fromkeys(kinds):
            build_one(target, python, kind, ["build"] + (["binaries"] if mode == "binaries" else []), optional_msan)
    except (OSError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
