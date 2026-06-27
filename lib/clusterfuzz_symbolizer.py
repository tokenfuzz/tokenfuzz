"""ClusterFuzz-derived offline ASan stack symbolization (isolated + attributed).

Borrowed, like ``lib/clusterfuzz_stacktrace.py``, from Google's ClusterFuzz so
provenance, license, and re-sync points live in one place. ClusterFuzz's
symbolizer is itself LLVM's ``lib/asan/scripts/asan_symbolize.py`` with local
edits; this is a further-trimmed copy of that.

Why the harness runs it: on macOS, ASan's *in-process* symbolizer (atos, forked
from the crashing process) is slow and can deadlock while generating a report,
so under the run timeout the report is killed after the unsymbolized
``ERROR: ...`` header but before any ``#N`` frames print. A frameless report has
no crash_state, so ``bin/cluster-crashes`` falls back to a per-crash
``pending:<id>`` state and every such crash becomes its own singleton cluster
(dedup silently stops). Running the crash with ``symbolize=0`` makes ASan emit
raw ``#N 0xpc (module+0xoffset)`` frames *immediately* — no atos in the crashing
process — and this module resolves those frames offline, with the process
already dead (no signal-context atos deadlock) and off the run-timeout clock.

Upstream source: https://github.com/google/clusterfuzz (branch: master)
  src/clusterfuzz/_internal/crash_analysis/stack_parsing/stack_symbolizer.py
    * STACK_TRACE_LINE_REGEX, fix_filename, fix_function_name, get_stack_frame,
      is_valid_arch, guess_arch
    * LLVMSymbolizer / Addr2LineSymbolizer / DarwinSymbolizer / ChainSymbolizer
      / UnbufferedLineConverter / SystemSymbolizerFactory
    * SymbolizationLoop (line parse + symbolize loop)

License: Apache License 2.0 — Copyright Google LLC; portions under the LLVM
  University of Illinois/NCSA Open Source License (asan_symbolize.py).
  https://github.com/google/clusterfuzz/blob/master/LICENSE

Local divergences from upstream are flagged with ``# DIVERGENCE:`` so they
survive a re-sync. The CF original is wired into Google's bot runtime
(``environment``/, Android/LKL/Trusty symbol download, Chrome ``.dSYM`` hints,
GCS binary fetch); none of that applies to a local audit host, so those paths
are dropped here. What remains is the platform-local
``llvm-symbolizer -> atos/addr2line`` chain, fed from the locally-built
sanitizer binary that ASan named in each frame.
"""

# Disable buffering concerns: this is a batch filter (read all, write all), not
# the streaming pipe CF runs inside its bot, so CF's LineBuffered/disable_buffering
# and the Android/LKL/Trusty/Chrome paths are intentionally absent.

import os
import re
import shutil
import subprocess
import sys

try:
  import pty
  import termios
except ImportError:
  # Applies only on unix platforms; atos (DarwinSymbolizer) needs it.
  pass

stack_inlining = 'false'
llvm_symbolizer_path = ''
pipes = []
symbolizers = {}

# 0 0x7f6e35cf2e45  (/blah/foo.so+0x11fe45)
STACK_TRACE_LINE_REGEX = re.compile(
    r'^( *#([0-9]+) *)(0x[0-9a-f]+) *\(([^+]*)\+(0x[0-9a-f]+)\)')


def _log(message):
  """Diagnostic sink. DIVERGENCE: CF routes these through its metrics ``logs``
  module; here they go to stderr so they never contaminate the symbolized
  report on stdout."""
  print(message, file=sys.stderr)


def fix_filename(file_name):
  """Clean up the filename, nulls out tool specific ones."""
  file_name = re.sub('.*asan_[a-z_]*.cc:[0-9]*', '_asan_rtl_', file_name)
  file_name = re.sub('.*crtstuff.c:0', '', file_name)
  file_name = re.sub(':0$', '', file_name)

  # If we don't have a file name, just bail out.
  if not file_name or file_name.startswith('??'):
    return ''

  return os.path.normpath(file_name)


def fix_function_name(function_name):
  """Clean up function name."""
  if function_name.startswith('??'):
    return ''

  return function_name


def get_stack_frame(binary, addr, function_name, file_name):
  """Return a stack frame entry."""
  # Cleanup file and function name.
  file_name = fix_filename(file_name)
  function_name = fix_function_name(function_name)

  # Check if we don't have any symbols at all. If yes, this is probably
  # a system library. In this case, just return the binary name.
  if not function_name and not file_name:
    return '%s in %s' % (addr, os.path.basename(binary))

  # We just have a file name. Probably running in global context.
  if not function_name:
    # Filter the filename to act as a function name.
    filtered_file_name = os.path.basename(file_name)
    return '%s in %s %s' % (addr, filtered_file_name, file_name)

  # DIVERGENCE: a frame with a function but no source file is a sanitizer-
  # runtime / system-library frame (e.g. the macOS ASan interceptor, which
  # symbolizes to ``wrap_strcpy``). ASan's own symbolizer keeps the
  # ``(module)`` suffix on such frames; llvm-symbolizer drops it. Re-attach the
  # module basename so the path-based ignore rules in
  # ``lib/clusterfuzz_stacktrace.py`` (``.*asan_osx_dynamic\.dylib`` etc.) still
  # fire — otherwise runtime interceptor frames leak to the top of the
  # crash_state and over-merge unrelated bugs. User frames carry source and are
  # unaffected.
  if not file_name:
    return '%s in %s (%s)' % (addr, function_name, os.path.basename(binary))

  # Regular stack frame.
  return '%s in %s %s' % (addr, function_name, file_name)


def is_valid_arch(s):
  """Check if this is a valid supported architecture."""
  # DIVERGENCE: add 'arm64e' (Apple Silicon pointer-auth ABI). Without it the
  # ``module:arm64e`` arch suffix ASan prints for Apple binaries is not
  # stripped off the path, so the binary path fails to resolve.
  return s in [
      "i386", "x86_64", "x86_64h", "arm", "armv6", "armv7", "armv7s", "armv7k",
      "arm64", "arm64e", "powerpc64", "powerpc64le", "s390x", "s390"
  ]


def guess_arch(address):
  """Guess which architecture we're running on (32/64).
  10 = len('0x') + 8 hex digits."""
  if len(address) > 10:
    return 'x86_64'
  else:
    return 'i386'


class Symbolizer:

  def __init__(self):
    pass

  def symbolize(self, addr, binary, offset):
    """Symbolize the given address (pair of binary and offset).

    Overridden in subclasses.
    Args:
        addr: virtual address of an instruction.
        binary: path to executable/shared object containing this instruction.
        offset: instruction offset in the @binary.
    Returns:
        list of strings (one string for each inlined frame) describing
        the code locations for this instruction (that is, function name, file
        name, line and column numbers).
    """
    return None


class LLVMSymbolizer(Symbolizer):

  def __init__(self, symbolizer_path, default_arch, system, dsym_hints=[]):
    super().__init__()
    self.symbolizer_path = symbolizer_path
    self.default_arch = default_arch
    self.system = system
    self.dsym_hints = dsym_hints
    self.pipe = self.open_llvm_symbolizer()

  def open_llvm_symbolizer(self):
    if not self.symbolizer_path or not os.path.exists(self.symbolizer_path):
      _log('llvm-symbolizer not found at %r' % self.symbolizer_path)
      return None

    # Setup symbolizer command line.
    cmd = [
        self.symbolizer_path,
        '--default-arch=%s' % self.default_arch,
        '--demangle',
        '--functions=linkage',
        '--inlining=%s' % stack_inlining,
    ]
    if self.system == 'darwin':
      for hint in self.dsym_hints:
        cmd.append('--dsym-hint=%s' % hint)

    # Set LD_LIBRARY_PATH to use the right libstdc++.
    # DIVERGENCE: os.environ.copy() in place of CF's environment.copy().
    env_copy = os.environ.copy()
    env_copy['LD_LIBRARY_PATH'] = os.path.dirname(self.symbolizer_path)

    # Run the symbolizer.
    pipe = subprocess.Popen(
        cmd, env=env_copy, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    global pipes
    pipes.append(pipe)
    return pipe

  def symbolize(self, addr, binary, offset):
    """Overrides Symbolizer.symbolize."""
    if not self.pipe:
      return None
    if not binary.strip():
      return ['%s in' % addr]

    result = []
    try:
      symbolizer_input = '"%s" %s' % (binary, offset)
      self.pipe.stdin.write(symbolizer_input.encode('utf-8') + b'\n')
      self.pipe.stdin.flush()
      while True:
        function_name = self.pipe.stdout.readline().rstrip().decode('utf-8')
        if not function_name:
          break

        file_name = self.pipe.stdout.readline().rstrip().decode('utf-8')
        result.append(get_stack_frame(binary, addr, function_name, file_name))

    except Exception:
      _log('Symbolization using llvm-symbolizer failed for: "%s".' %
           symbolizer_input)
      result = []
    if not result:
      result = None
    return result


def LLVMSymbolizerFactory(system, default_arch, dsym_hints=[]):
  return LLVMSymbolizer(llvm_symbolizer_path, default_arch, system, dsym_hints)


class Addr2LineSymbolizer(Symbolizer):

  def __init__(self, binary):
    super().__init__()
    self.binary = binary
    self.pipe = self.open_addr2line()

  def open_addr2line(self):
    cmd = ['addr2line', '--demangle', '-f', '-e', self.binary]
    pipe = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    global pipes
    pipes.append(pipe)
    return pipe

  def symbolize(self, addr, binary, offset):
    """Overrides Symbolizer.symbolize."""
    if self.binary != binary:
      return None
    if not binary.strip():
      return ['%s in' % addr]

    try:
      symbolizer_input = str(offset).encode('utf-8')
      self.pipe.stdin.write(symbolizer_input + b'\n')
      self.pipe.stdin.flush()
      function_name = self.pipe.stdout.readline().rstrip().decode('utf-8')
      file_name = self.pipe.stdout.readline().rstrip().decode('utf-8')
    except Exception:
      _log('Symbolization using addr2line failed for: "%s %s".' %
           (binary, str(offset)))
      function_name = ''
      file_name = ''

    return [get_stack_frame(binary, addr, function_name, file_name)]


class UnbufferedLineConverter:
  """Wrap a child process that responds to each line of input with one line of output.

  Uses pty to trick the child into providing unbuffered output.
  """

  def __init__(self, args, close_stderr=False):
    pid, fd = pty.fork()
    if pid == 0:
      # We're the child. Transfer control to command.
      if close_stderr:
        dev_null = os.open('/dev/null', 0)
        os.dup2(dev_null, 2)
      os.execvp(args[0], args)
    else:
      # Disable echoing.
      attr = termios.tcgetattr(fd)
      attr[3] = attr[3] & ~termios.ECHO
      termios.tcsetattr(fd, termios.TCSANOW, attr)
      # Set up a file()-like interface to the child process
      self.r = os.fdopen(fd, 'r', 1)
      self.w = os.fdopen(os.dup(fd), 'w', 1)

  def convert(self, line):
    self.w.write(line + '\n')
    return self.readline()

  def readline(self):
    return self.r.readline().rstrip()


class DarwinSymbolizer(Symbolizer):

  def __init__(self, addr, binary, arch):
    super().__init__()
    self.binary = binary
    self.arch = arch
    self.open_atos()

  def open_atos(self):
    cmdline = ['atos', '-o', self.binary, '-arch', self.arch]
    self.atos = UnbufferedLineConverter(cmdline, close_stderr=True)

  def symbolize(self, addr, binary, offset):
    """Overrides Symbolizer.symbolize."""
    if self.binary != binary:
      return None

    try:
      atos_line = self.atos.convert('0x%x' % int(offset, 16))
      while 'got symbolicator for' in atos_line:
        atos_line = self.atos.readline()
      # A well-formed atos response looks like this:
      #   foo(type1, type2) (in object.name) (filename.cc:80)
      match = re.match(r'^(.*) \(in (.*)\) \((.*:\d*)\)$', atos_line)
      if match:
        function_name = match.group(1)
        function_name = re.sub(r'\(.*?\)', '', function_name)
        file_name = match.group(3)
        return [get_stack_frame(binary, addr, function_name, file_name)]
      else:
        return ['%s in %s' % (addr, atos_line)]
    except Exception:
      _log('Symbolization using atos failed for: "%s %s".' %
           (binary, str(offset)))
      return ['{} ({}:{}+{})'.format(addr, binary, self.arch, offset)]


# Chain several symbolizers so that if one symbolizer fails, we fall back
# to the next symbolizer in chain.
class ChainSymbolizer(Symbolizer):

  def __init__(self, symbolizer_list):
    super().__init__()
    self.symbolizer_list = symbolizer_list

  def symbolize(self, addr, binary, offset):
    """Overrides Symbolizer.symbolize."""
    for symbolizer in self.symbolizer_list:
      if symbolizer:
        result = symbolizer.symbolize(addr, binary, offset)
        if result:
          return result
    return None

  def append_symbolizer(self, symbolizer):
    self.symbolizer_list.append(symbolizer)


def SystemSymbolizerFactory(system, addr, binary, arch):
  if system == 'darwin':
    return DarwinSymbolizer(addr, binary, arch)
  elif system.startswith('linux'):
    return Addr2LineSymbolizer(binary)
  # DIVERGENCE: CF only ever runs on darwin/linux bots; return None on anything
  # else so symbolize_address can fall open instead of CF's bare `assert`.
  return None


class SymbolizationLoop:

  def __init__(self):
    # DIVERGENCE: dropped binary_path_filter / dsym_hint_producer (CF uses them
    # for Android symbol download and Chrome's shared .dSYM); a local audit
    # symbolizes the binary ASan named, in place.
    self.system = sys.platform
    self.llvm_symbolizers = {}

  def symbolize_address(self, addr, binary, offset, arch):
    # Use the chain of symbolizers: LLVM symbolizer -> addr2line/atos
    # (fall back to the next symbolizer if the previous one fails).
    if binary not in self.llvm_symbolizers:
      self.llvm_symbolizers[binary] = LLVMSymbolizerFactory(self.system, arch)
    if binary not in symbolizers:
      symbolizers[binary] = ChainSymbolizer([self.llvm_symbolizers[binary]])
    result = symbolizers[binary].symbolize(addr, binary, offset)
    if result is None:
      # Initialize the system symbolizer only if other symbolizers failed.
      system_symbolizer = SystemSymbolizerFactory(self.system, addr, binary,
                                                  arch)
      # DIVERGENCE: CF asserts a system symbolizer always exists. On an
      # unrecognized platform it is None; fall open (leave the frame raw)
      # rather than abort the whole report.
      if system_symbolizer is None:
        return None
      symbolizers[binary].append_symbolizer(system_symbolizer)
      result = symbolizers[binary].symbolize(addr, binary, offset)
    return result

  def _line_parser(self, line):
    """Parses line for frameno_str, addr, binary, offset, arch."""
    match = STACK_TRACE_LINE_REGEX.match(line)
    if match:
      _, frameno_str, addr, binary, offset = match.groups()
      arch = ""
      # Arch can be embedded in the filename, e.g.: "libabc.dylib:x86_64h"
      colon_pos = binary.rfind(":")
      if colon_pos != -1:
        maybe_arch = binary[colon_pos + 1:]
        if is_valid_arch(maybe_arch):
          arch = maybe_arch
          binary = binary[0:colon_pos]
      if arch == "":
        arch = guess_arch(addr)

      return frameno_str, addr, binary, offset, arch

    return None, None, None, None, None

  def _close_pipes(self):
    """Closes any open pipes."""
    for pipe in pipes:
      pipe.stdin.close()
      pipe.stdout.close()
      try:
        pipe.kill()
      except ProcessLookupError:
        pass

  def process_stacktrace(self, unsymbolized_crash_stacktrace):
    """Symbolizes a crash stacktrace."""
    self.frame_no = 0
    symbolized_crash_stacktrace = ''
    unsymbolized_crash_stacktrace_lines = \
      unsymbolized_crash_stacktrace.splitlines()

    for line in unsymbolized_crash_stacktrace_lines:
      self.current_line = line.rstrip()
      frameno_str, addr, binary, offset, arch = self._line_parser(line)
      if not binary or not offset:
        symbolized_crash_stacktrace += '%s\n' % self.current_line
        continue

      if frameno_str == '0':
        # Assume that frame #0 is the first frame of a new stack trace.
        self.frame_no = 0
      symbolized_line = self.symbolize_address(addr, binary, offset, arch)

      if not symbolized_line:
        symbolized_crash_stacktrace += '%s\n' % self.current_line
      else:
        for symbolized_frame in symbolized_line:
          symbolized_crash_stacktrace += '%s\n' % (
              '    #' + str(self.frame_no) + ' ' + symbolized_frame.rstrip())
          self.frame_no += 1

    self._close_pipes()

    return symbolized_crash_stacktrace


def _resolve_llvm_symbolizer(explicit, disable=False):
  """Resolve an llvm-symbolizer path. DIVERGENCE: replaces CF's
  environment.get_llvm_symbolizer_path(). Precedence: explicit arg, then the
  LLVM_SYMBOLIZER env var, then PATH.

  When ``disable`` is set, return '' without consulting any of those — the empty
  path makes LLVMSymbolizer a no-op, so the chain falls straight to the platform
  tool (atos on macOS, addr2line on Linux). Callers use this to force the
  debug-map-aware backend; an empty ``explicit`` alone does NOT disable llvm
  (it would still fall through to a PATH llvm-symbolizer)."""
  if disable:
    return ''
  for candidate in (explicit, os.environ.get('LLVM_SYMBOLIZER')):
    if candidate and os.path.exists(candidate):
      return candidate
  found = shutil.which('llvm-symbolizer')
  return found or ''


def symbolize_stacktrace(unsymbolized_crash_stacktrace,
                         symbolizer_path=None,
                         enable_inline_frames=False,
                         disable_llvm_symbolizer=False):
  """Symbolize a crash stacktrace produced with symbolize=0.

  Uses the ClusterFuzz symbolizer chain: llvm-symbolizer when available, else
  the platform tool (atos on macOS, addr2line on Linux). We deliberately do NOT
  require llvm-symbolizer — stock macOS (Apple clang from CommandLineTools)
  ships atos but no llvm-symbolizer, and that is the very platform whose inline
  atos hang truncates reports. Run OFFLINE here (on the already-exited process),
  atos does not hang. Frames that no backend can resolve are left as captured,
  so the caller always gets at least the raw module+offset frames."""
  global llvm_symbolizer_path
  global pipes
  global stack_inlining
  global symbolizers
  pipes = []
  stack_inlining = str(enable_inline_frames).lower()
  symbolizers = {}

  llvm_symbolizer_path = _resolve_llvm_symbolizer(symbolizer_path,
                                                  disable_llvm_symbolizer)
  loop = SymbolizationLoop()
  return loop.process_stacktrace(unsymbolized_crash_stacktrace)


def main(argv):
  import argparse
  parser = argparse.ArgumentParser(
      description='Offline-symbolize an ASan report captured with symbolize=0. '
      'Reads the report on stdin, writes the symbolized report to stdout.')
  parser.add_argument(
      '--llvm-symbolizer', default='',
      help='Path to llvm-symbolizer (else $LLVM_SYMBOLIZER, else PATH).')
  parser.add_argument(
      '--no-llvm-symbolizer', action='store_true',
      help='Skip llvm-symbolizer entirely and use the platform tool (atos on '
      'macOS, addr2line on Linux). atos is debug-map-aware, needs no .dSYM, and '
      'is immune to a stale one — unlike llvm-symbolizer, which an empty '
      '--llvm-symbolizer would still reach via PATH.')
  args = parser.parse_args(argv)

  raw = sys.stdin.read()
  sys.stdout.write(
      symbolize_stacktrace(raw, symbolizer_path=args.llvm_symbolizer,
                           disable_llvm_symbolizer=args.no_llvm_symbolizer))
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
