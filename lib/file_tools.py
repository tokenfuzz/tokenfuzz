#!/usr/bin/env python3
"""Binary-safe file clipping and bounded rendering for command frontends."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence


def reverse_lines(path: Path):
    """Yield decoded lines newest-first without reading the file prefix."""
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            position = stream.tell()
            remainder = b""
            skip_terminal_empty = True
            while position > 0:
                size = min(64 * 1024, position)
                position -= size
                stream.seek(position)
                parts = (stream.read(size) + remainder).split(b"\n")
                remainder = parts[0]
                for line in reversed(parts[1:]):
                    if skip_terminal_empty:
                        skip_terminal_empty = False
                        if not line:
                            continue
                    yield line.decode("utf-8", errors="replace")
            if remainder:
                yield remainder.decode("utf-8", errors="replace")
    except OSError:
        return


def tail_lines(path: Path, count: int, *, nonempty: bool = False) -> list[str]:
    """Return the final lines while reading only as much of the tail as needed."""
    if count <= 0:
        return []
    lines: list[str] = []
    for line in reverse_lines(path):
        if nonempty and not line.strip():
            continue
        lines.append(line)
        if len(lines) == count:
            break
    lines.reverse()
    return lines


def clipped_prefix(path: Path, cap: int) -> bytes:
    with path.open("rb") as source:
        data = source.read(cap)
    newline = data.rfind(b"\n")
    return data[: newline + 1] if newline >= 0 else data


def clipped_prefix_bytes(data: bytes, cap: int) -> bytes:
    clipped = data[:cap]
    newline = clipped.rfind(b"\n")
    return clipped[: newline + 1] if newline >= 0 else clipped


def _non_negative_int(env: Mapping[str, str], name: str, default: int) -> int:
    value = env.get(name, str(default))
    if not value.isdigit():
        raise ValueError(
            f"[output_cap] {name} must be a non-negative integer (got: {value})"
        )
    return int(value)


def _spill_output(data: bytes, label: str, env: Mapping[str, str]) -> str:
    configured = env.get("OUTCAP_SPILL_DIR")
    if configured:
        spill_dir = Path(configured)
    elif env.get("RESULTS_DIR"):
        spill_dir = Path(env["RESULTS_DIR"]) / "logs" / ".raw" / "outcap"
    else:
        spill_dir = Path(tempfile.mkdtemp(prefix="outcap-", dir=env.get("TMPDIR")))
    try:
        spill_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        spill_dir.chmod(0o700)
        digest = hashlib.sha1(data).hexdigest()[:12]
        destination = spill_dir / f"outcap-{label}-{digest}.txt"
        fd, temporary = tempfile.mkstemp(prefix=".outcap-", dir=spill_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(data)
            os.replace(temporary, destination)
        except BaseException:
            if fd >= 0:
                os.close(fd)
            Path(temporary).unlink(missing_ok=True)
            raise
        return str(destination)
    except OSError:
        return ""


def _spill_output_file(path: Path, label: str, env: Mapping[str, str]) -> str:
    configured = env.get("OUTCAP_SPILL_DIR")
    if configured:
        spill_dir = Path(configured)
    elif env.get("RESULTS_DIR"):
        spill_dir = Path(env["RESULTS_DIR"]) / "logs" / ".raw" / "outcap"
    else:
        spill_dir = Path(tempfile.mkdtemp(prefix="outcap-", dir=env.get("TMPDIR")))
    try:
        spill_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        spill_dir.chmod(0o700)
        digest = hashlib.sha1()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        destination = spill_dir / f"outcap-{label}-{digest.hexdigest()[:12]}.txt"
        fd, temporary = tempfile.mkstemp(prefix=".outcap-", dir=spill_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as target, path.open("rb") as source:
                fd = -1
                shutil.copyfileobj(source, target, 1024 * 1024)
            os.replace(temporary, destination)
        except BaseException:
            if fd >= 0:
                os.close(fd)
            Path(temporary).unlink(missing_ok=True)
            raise
        return str(destination)
    except OSError:
        return ""


def render_head_tail(
    data: bytes, head_bytes: int, tail_bytes: int, label: str, spill_path: str = ""
) -> bytes:
    head = data[:head_bytes]
    newline = head.rfind(b"\n")
    if newline >= 0:
        head = head[: newline + 1]

    tail = data[max(0, len(data) - tail_bytes) :]
    newline = tail.find(b"\n")
    if newline >= 0 and newline + 1 < len(tail):
        tail = tail[newline + 1 :]

    return _render_head_tail_parts(head, tail, len(data), label, spill_path)


def _render_head_tail_parts(
    head: bytes, tail: bytes, total_bytes: int, label: str, spill_path: str,
) -> bytes:
    """Render already line-aligned ends with the shared truncation marker."""

    elided = max(0, total_bytes - len(head) - len(tail))
    prefix = (
        f"\n[output_cap: {label} truncated — {total_bytes:,} total bytes, "
        f"{len(head):,} head + {len(tail):,} tail shown, {elided:,} bytes elided. "
    )
    disable = (
        "use OUTCAP_MAX_BYTES=0 to disable only when you intentionally want full "
        "output in the transcript.]\n"
    )
    if spill_path:
        marker = (
            prefix
            + f"Full output: {spill_path}. Inspect bounded ranges with "
            + f"`bin/peek {spill_path}:1-200` or `tail -50 {spill_path}`; "
            + disable
        )
    else:
        marker = prefix + "(spill unavailable.) Narrow your query or " + disable
    return head + marker.encode() + tail + (b"" if tail.endswith(b"\n") else b"\n")


def cap_output_bytes(
    data: bytes, label: str, env: Mapping[str, str] | None = None
) -> bytes:
    environment = os.environ if env is None else env
    maximum = _non_negative_int(environment, "OUTCAP_MAX_BYTES", 51200)
    head = _non_negative_int(environment, "OUTCAP_HEAD_BYTES", 24576)
    tail = _non_negative_int(environment, "OUTCAP_TAIL_BYTES", 20480)
    if maximum == 0 or len(data) <= maximum:
        return data
    safe_label = re.sub(r"[^A-Za-z0-9._-]", "-", label) or "output"
    spill_path = _spill_output(data, safe_label, environment)
    return render_head_tail(data, head, tail, safe_label, spill_path)


def cap_output_file(
    path: Path, label: str, env: Mapping[str, str] | None = None,
) -> bytes:
    """Render a capped file while keeping large producer output off the heap."""
    environment = os.environ if env is None else env
    maximum = _non_negative_int(environment, "OUTCAP_MAX_BYTES", 51200)
    head_bytes = _non_negative_int(environment, "OUTCAP_HEAD_BYTES", 24576)
    tail_bytes = _non_negative_int(environment, "OUTCAP_TAIL_BYTES", 20480)
    size = path.stat().st_size
    if maximum == 0 or size <= maximum:
        return path.read_bytes()
    safe_label = re.sub(r"[^A-Za-z0-9._-]", "-", label) or "output"
    spill_path = _spill_output_file(path, safe_label, environment)
    with path.open("rb") as source:
        head = source.read(head_bytes)
        source.seek(max(0, size - tail_bytes))
        tail = source.read(tail_bytes)
    head_newline = head.rfind(b"\n")
    if head_newline >= 0:
        head = head[: head_newline + 1]
    tail_newline = tail.find(b"\n")
    if tail_newline >= 0 and tail_newline + 1 < len(tail):
        tail = tail[tail_newline + 1 :]
    return _render_head_tail_parts(head, tail, size, safe_label, spill_path)


@dataclass(frozen=True)
class CapturedCommand:
    returncode: int
    stdout: Path
    stderr: Path | None


@contextmanager
def capture_command(
    command: Sequence[str], *, merge_stderr: bool = False,
    capture_stderr: bool = True, **kwargs,
) -> Iterator[CapturedCommand]:
    """Run a command into temporary files and remove them after consumption."""
    if merge_stderr and not capture_stderr:
        raise ValueError("merge_stderr and capture_stderr=False are incompatible")
    with tempfile.TemporaryDirectory(prefix="command-capture-") as directory:
        stdout_path = Path(directory) / "stdout"
        stderr_path = Path(directory) / "stderr" if capture_stderr and not merge_stderr else None
        with stdout_path.open("wb") as stdout_stream:
            if merge_stderr:
                completed = subprocess.run(
                    command, stdout=stdout_stream, stderr=subprocess.STDOUT,
                    check=False, **kwargs,
                )
            elif capture_stderr:
                with stderr_path.open("wb") as stderr_stream:
                    completed = subprocess.run(
                        command, stdout=stdout_stream, stderr=stderr_stream,
                        check=False, **kwargs,
                    )
            else:
                completed = subprocess.run(
                    command, stdout=stdout_stream, check=False, **kwargs,
                )
        yield CapturedCommand(completed.returncode, stdout_path, stderr_path)


def _cmd_clip(args: argparse.Namespace) -> int:
    data = clipped_prefix(Path(args.path), args.cap)
    if args.in_place:
        Path(args.path).write_bytes(data)
    else:
        sys.stdout.buffer.write(data)
    return 0


def _cmd_head_tail(args: argparse.Namespace) -> int:
    path = Path(args.path)
    sys.stdout.buffer.write(
        render_head_tail(
            path.read_bytes(),
            args.head_bytes,
            args.tail_bytes,
            args.label,
            args.spill_path,
        )
    )
    return 0


def _cmd_cap_output(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        return 0
    try:
        rendered = cap_output_file(path, args.label)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(rendered)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="file_tools")
    sub = parser.add_subparsers(dest="command", required=True)

    command = sub.add_parser("clip", help="emit a newline-aligned byte prefix")
    command.add_argument("path")
    command.add_argument("cap", type=int)
    command.add_argument("--in-place", action="store_true")
    command.set_defaults(func=_cmd_clip)

    command = sub.add_parser("head-tail", help="render line-aligned head and tail")
    command.add_argument("path")
    command.add_argument("head_bytes", type=int)
    command.add_argument("tail_bytes", type=int)
    command.add_argument("label")
    command.add_argument("spill_path", nargs="?", default="")
    command.set_defaults(func=_cmd_head_tail)

    command = sub.add_parser("cap-output", help="apply the shared output cap")
    command.add_argument("path")
    command.add_argument("label", nargs="?", default="output")
    command.set_defaults(func=_cmd_cap_output)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if getattr(args, "cap", 0) < 0:
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
