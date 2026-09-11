#!/usr/bin/env python3
"""lib/languages.py — single source of truth for language support.

Audit-harness consumers (workqueue, target_config, crash_artifacts, probe,
setup-target, find-seed, scratch-status) each need a slice of "which
languages does this harness understand": which extensions are
audit-rankable source, which extensions are valid HARNESS files, how do
we dispatch a harness extension to a compiler or interpreter, what
runner defaults belong in target.toml for a given build_system, and
what bootstrap commands turn a fresh source checkout into something the
runner can actually execute.

Historically each consumer kept its own hardcoded list. That made
"add a new language" a five-file diff and let the lists drift — the
case that motivated this module was rank-work missing ``.py`` while
target_config.LANGUAGE_RUNNERS already supported Python.

The registry is intentionally a flat tuple of frozen dataclasses. All
consumers derive their needed slice via helper functions; nothing else
in the harness should special-case a language.

Two interfaces:

1. Python API (preferred — pure stdlib, no external deps):

       import languages
       languages.all_source_exts()        # {'.c', '.cc', ..., '.py', '.ts', ...}
       languages.source_reference_ext_pattern()  # regex alternation for reports
       languages.for_build_system("python")
       languages.for_harness_ext(".rs")
       languages.runner_table()           # {'cargo': {...}, 'python': {...}, ...}

2. Subcommand CLI for operator inspection and automation:

       python3 lib/languages.py exts --kind source        # newline-separated
       python3 lib/languages.py exts --kind harness
       python3 lib/languages.py probe-dispatch <harness_ext>
       python3 lib/languages.py bootstrap-cmds <build_system>
       python3 lib/languages.py list                       # human-readable table
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


@dataclass(frozen=True)
class SwiftPackageInfo:
    name: str
    tools_version: str
    platforms: tuple[tuple[str, str], ...]
    library_products: tuple[tuple[str, tuple[str, ...]], ...]
    executable_products: tuple[str, ...]


@dataclass(frozen=True)
class CargoLibraryProduct:
    package: str
    crate: str
    manifest_dir: str
    default_member: bool = False


@dataclass(frozen=True)
class CargoExecutableProduct:
    package: str
    name: str
    manifest_dir: str
    default: bool = False
    default_member: bool = False


@dataclass(frozen=True)
class CargoWorkspaceInfo:
    libraries: tuple[CargoLibraryProduct, ...]
    executables: tuple[CargoExecutableProduct, ...]


@dataclass(frozen=True)
class RubyPackageInfo:
    name: str
    entrypoint: str
    entrypoint_path: str
    extensions: tuple[str, ...]


def _cargo_workspace_info(raw: object, target_root: str | os.PathLike) -> CargoWorkspaceInfo:
    """Parse Cargo metadata into runnable products from workspace members."""
    if not isinstance(raw, dict):
        raise ValueError("Cargo metadata is not an object")
    member_ids = raw.get("workspace_members")
    packages = raw.get("packages")
    if not isinstance(member_ids, list) or not isinstance(packages, list):
        raise ValueError("Cargo metadata omits packages or workspace_members")
    members = {str(value) for value in member_ids}
    default_ids = raw.get("workspace_default_members")
    default_members = (
        {str(value) for value in default_ids}
        if isinstance(default_ids, list) else set()
    )
    root = Path(target_root).resolve()
    libraries: list[CargoLibraryProduct] = []
    executables: list[CargoExecutableProduct] = []
    for package in packages:
        if not isinstance(package, dict) or str(package.get("id")) not in members:
            continue
        package_id = str(package.get("id"))
        name = str(package.get("name") or "")
        manifest = Path(str(package.get("manifest_path") or ""))
        try:
            manifest_dir = manifest.resolve().parent
            manifest_dir.relative_to(root)
        except (OSError, ValueError):
            continue
        relative = os.path.relpath(manifest_dir, root)
        relative = "" if relative == "." else relative
        default_run = str(package.get("default_run") or "")
        targets = package.get("targets")
        if not name or not isinstance(targets, list):
            continue
        for target in targets:
            if not isinstance(target, dict):
                continue
            target_name = str(target.get("name") or "")
            kinds = target.get("kind")
            if not target_name or not isinstance(kinds, list):
                continue
            kind_set = {str(value) for value in kinds}
            if kind_set & {"lib", "rlib", "dylib", "staticlib", "cdylib"}:
                libraries.append(CargoLibraryProduct(
                    name, target_name, relative, package_id in default_members,
                ))
            if "bin" in kind_set:
                executables.append(CargoExecutableProduct(
                    name, target_name, relative, target_name == default_run,
                    package_id in default_members,
                ))
    return CargoWorkspaceInfo(
        tuple(sorted(set(libraries), key=lambda row: (row.manifest_dir, row.package, row.crate))),
        tuple(sorted(set(executables), key=lambda row: (row.manifest_dir, row.package, row.name))),
    )


def cargo_workspace_info(target_root: str | os.PathLike) -> CargoWorkspaceInfo:
    """Ask Cargo which workspace packages and products actually exist."""
    root = Path(target_root).resolve()
    try:
        completed = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1",
             "--manifest-path", str(root / "Cargo.toml")],
            capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Cargo could not describe {root / 'Cargo.toml'}: {exc}") from exc
    if completed.returncode:
        detail = next((line.strip() for line in completed.stderr.splitlines() if line.strip()), "no diagnostic output")
        raise ValueError(f"Cargo could not describe {root / 'Cargo.toml'}: {detail}")
    try:
        return _cargo_workspace_info(json.loads(completed.stdout), root)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cargo returned malformed metadata for {root}: {exc}") from exc


def cargo_runner_args(
    target_root: str | os.PathLike, target_slug: str = "",
) -> tuple[str, ...]:
    """Select one declared Cargo binary, or mark a source-library route."""
    info = cargo_workspace_info(target_root)
    candidates = info.executables
    default_candidates = tuple(row for row in candidates if row.default_member)
    default_libraries = tuple(row for row in info.libraries if row.default_member)
    pool = (
        default_candidates
        if default_candidates or default_libraries else candidates
    )
    defaults = tuple(row for row in pool if row.default)
    leaf = target_slug.rsplit("/", 1)[-1].replace("_", "-")
    exact_binary = tuple(
        row for row in pool
        if row.name.replace("_", "-") == leaf
    )
    exact_package = tuple(
        row for row in pool
        if row.package.replace("_", "-") == leaf
    )
    selected = (
        defaults[0] if len(defaults) == 1 else
        exact_binary[0] if len(exact_binary) == 1 else
        exact_package[0] if len(exact_package) == 1 else
        pool[0] if len(pool) == 1 else None
    )
    if selected is None and default_libraries:
        return ("{TESTCASE}",)
    if selected is None:
        if info.libraries:
            return ("{TESTCASE}",)
        raise ValueError(
            "Cargo workspace exposes neither a library nor one unambiguous "
            f"binary target (binaries: {', '.join(row.name for row in candidates) or 'none'})"
        )
    manifest = (
        "{TARGET_ROOT}/Cargo.toml" if not selected.manifest_dir
        else f"{{TARGET_ROOT}}/{selected.manifest_dir}/Cargo.toml"
    )
    return (
        "run", "--quiet", "--manifest-path", manifest,
        "--bin", selected.name, "--", "{TESTCASE}",
    )


def preferred_cargo_libraries(
    info: CargoWorkspaceInfo,
) -> tuple[CargoLibraryProduct, ...]:
    """Prefer libraries Cargo builds from the workspace root by default."""
    defaults = tuple(row for row in info.libraries if row.default_member)
    return defaults or info.libraries


def swiftpm_paths(target_root: str | os.PathLike) -> dict[str, Path]:
    root = Path(target_root)
    paths = {
        "cache": root / ".audit" / "swiftpm" / "cache",
        "config": root / ".audit" / "swiftpm" / "configuration",
        "security": root / ".audit" / "swiftpm" / "security",
        "modules": root / ".audit" / "clang-module-cache",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def swift_package_info(target_root: str | os.PathLike) -> SwiftPackageInfo:
    """Return SwiftPM's structured description of a package."""
    root = Path(target_root)
    paths = swiftpm_paths(root)
    environment = os.environ.copy()
    environment["CLANG_MODULE_CACHE_PATH"] = str(paths["modules"])
    environment["SWIFTPM_MODULECACHE_OVERRIDE"] = str(paths["modules"])
    try:
        completed = subprocess.run(
            [
                "swift", "package", "--disable-sandbox",
                "--package-path", str(root),
                "--cache-path", str(paths["cache"]),
                "--config-path", str(paths["config"]),
                "--security-path", str(paths["security"]),
                "dump-package",
            ],
            capture_output=True, text=True, check=False, timeout=60,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(
            f"SwiftPM did not describe {root / 'Package.swift'} within 60s"
        ) from exc
    except OSError as exc:
        raise ValueError(
            f"SwiftPM could not describe {root / 'Package.swift'}: {exc}"
        ) from exc
    if completed.returncode:
        detail = next((line.strip() for line in completed.stderr.splitlines() if line.strip()), "no diagnostic output")
        raise ValueError(f"SwiftPM could not describe {root / 'Package.swift'}: {detail}")
    try:
        raw = json.loads(completed.stdout)
        products = raw.get("products", [])
        libraries = tuple(
            (str(product["name"]), tuple(str(value) for value in product.get("targets", [])))
            for product in products
            if isinstance(product, dict)
            and isinstance(product.get("type"), dict)
            and "library" in product["type"]
            and product.get("targets")
        )
        executables = tuple(
            str(product["name"])
            for product in products
            if isinstance(product, dict)
            and isinstance(product.get("type"), dict)
            and "executable" in product["type"]
        )
        version = str(raw.get("toolsVersion", {}).get("_version", "5.9.0"))
        platforms = tuple(
            (str(row["platformName"]), str(row["version"]))
            for row in raw.get("platforms", [])
            if isinstance(row, dict) and row.get("platformName") and row.get("version")
        )
        return SwiftPackageInfo(
            name=str(raw["name"]), tools_version=version,
            platforms=platforms, library_products=libraries,
            executable_products=executables,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"SwiftPM returned malformed package metadata for {root}: {exc}") from exc


def swift_executable_runner_args(product: str) -> tuple[str, ...]:
    return (
        "run", "--quiet", "--disable-sandbox", "--skip-build",
        "--cache-path", "{TARGET_ROOT}/.audit/swiftpm/cache",
        "--config-path", "{TARGET_ROOT}/.audit/swiftpm/configuration",
        "--security-path", "{TARGET_ROOT}/.audit/swiftpm/security",
        "-c", "release", "-Xswiftc", "-sanitize={SWIFT_SANITIZER}",
        "-Xswiftc", "-O", "-Xswiftc", "-module-cache-path",
        "-Xswiftc", "{TARGET_ROOT}/.audit/clang-module-cache", "--scratch-path",
        "{TARGET_ROOT}/.audit/swift-build-{SWIFT_SANITIZER}",
        "--package-path", "{TARGET_ROOT}", product, "{TESTCASE}",
    )


def swift_runner_args(target_root: str | os.PathLike, target_slug: str = "") -> tuple[str, ...]:
    """Select a source-library or executable SwiftPM route without guessing."""
    info = swift_package_info(target_root)
    if info.library_products:
        return ("{TESTCASE}",)
    candidates = info.executable_products
    exact = tuple(name for name in candidates if name == target_slug)
    if len(exact) == 1:
        return swift_executable_runner_args(exact[0])
    if len(candidates) == 1:
        return swift_executable_runner_args(candidates[0])
    raise ValueError(
        "SwiftPM package exposes neither a library nor one unambiguous "
        f"executable product (executables: {', '.join(candidates) or 'none'})"
    )


def java_classpath_entries(
    target_root: str | os.PathLike, build_system: str,
    target_file: str = "", testcase: str | os.PathLike | None = None,
) -> tuple[str, ...]:
    """Return compiled target classes and build-tool-resolved dependencies."""
    root = Path(target_root)
    if build_system == "maven":
        class_roots = [
            path for path in sorted(root.rglob("target/classes")) if path.is_dir()
        ]
    else:
        class_roots = []
        for suffix in (
            "build/classes/java/main", "build/classes/kotlin/main",
            "build/classes/kotlin/jvm/main",
        ):
            class_roots.extend(
                path for path in sorted(root.rglob(suffix)) if path.is_dir()
            )
    entries: list[Path] = []
    if build_system == "maven":
        receipts: list[Path] = []
        selected_roots: list[Path] = []
        if target_file:
            source = Path(target_file.split(":", 1)[0])
            if not source.is_absolute():
                source = root / source
            try:
                source.resolve().relative_to(root.resolve())
            except (OSError, ValueError):
                source = root
            if source.is_file():
                for parent in [source.parent, *source.parents]:
                    if parent == root.parent:
                        break
                    candidate = parent / "target" / "tokenfuzz-classpath.txt"
                    if candidate.is_file():
                        receipts = [candidate]
                        compiled = candidate.parent / "classes"
                        if compiled.is_dir():
                            selected_roots = [compiled]
                        break
                    if parent == root:
                        break
        if not receipts and testcase:
            try:
                source_text = Path(testcase).read_text(
                    encoding="utf-8", errors="replace",
                )
            except OSError:
                source_text = ""
            imports = re.findall(
                r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*;",
                source_text,
            )
            for imported in imports:
                parts = imported.split(".")
                while parts:
                    relative = Path(*parts).with_suffix(".class")
                    matched = next(
                        (class_root for class_root in class_roots
                         if (class_root / relative).is_file()),
                        None,
                    )
                    if matched is not None:
                        receipt = matched.parent / "tokenfuzz-classpath.txt"
                        if receipt.is_file() and receipt not in receipts:
                            receipts.append(receipt)
                        if matched not in selected_roots:
                            selected_roots.append(matched)
                        break
                    parts.pop()
        if not receipts:
            receipts = sorted(root.rglob("target/tokenfuzz-classpath.txt"))
        entries.extend(selected_roots or class_roots)
        artifact_roots: dict[str, list[Path]] = {}
        for class_root in class_roots:
            manifest = class_root.parent.parent / "pom.xml"
            try:
                project = ET.parse(manifest).getroot()
                artifact = project.find("{*}artifactId")
                name = (artifact.text or "").strip() if artifact is not None else ""
            except (OSError, ET.ParseError):
                name = ""
            if name:
                artifact_roots.setdefault(name, []).append(class_root)
        seen_receipts: set[Path] = set()
        receipt_index = 0
        while receipt_index < len(receipts):
            receipt = receipts[receipt_index]
            receipt_index += 1
            if receipt in seen_receipts:
                continue
            seen_receipts.add(receipt)
            try:
                values = receipt.read_text(encoding="utf-8").strip().split(os.pathsep)
            except OSError:
                continue
            for value in values:
                dependency = Path(value)
                if not value or not dependency.exists():
                    continue
                artifact = dependency.parent.parent.name
                local = artifact_roots.get(artifact, [])
                if len(local) == 1:
                    entries.append(local[0])
                    transitive = local[0].parent / "tokenfuzz-classpath.txt"
                    if transitive.is_file() and transitive not in seen_receipts:
                        receipts.append(transitive)
                else:
                    entries.append(dependency)
    else:
        receipts: list[Path] = []
        build_outputs: dict[Path, list[Path]] = {}
        for class_root in class_roots:
            build_dir = next(
                (parent for parent in class_root.parents if parent.name == "build"),
                None,
            )
            if build_dir is not None:
                build_outputs.setdefault(build_dir.resolve(), []).append(class_root)

        def add_nearest_receipt(path: Path) -> None:
            for parent in [path.parent, *path.parents]:
                candidate = parent / "build" / "tokenfuzz-classpath.txt"
                if candidate.is_file():
                    if candidate not in receipts:
                        receipts.append(candidate)
                    return
                if parent == root:
                    return

        if target_file:
            source = Path(target_file.split(":", 1)[0])
            add_nearest_receipt(source if source.is_absolute() else root / source)
        if testcase:
            try:
                source_text = Path(testcase).read_text(
                    encoding="utf-8", errors="replace",
                )
            except OSError:
                source_text = ""
            for imported in re.findall(
                r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*;",
                source_text,
            ):
                parts = imported.split(".")
                while parts:
                    relative = Path(*parts).with_suffix(".class")
                    matched = next(
                        (class_root for class_root in class_roots
                         if (class_root / relative).is_file()),
                        None,
                    )
                    if matched is not None:
                        build_dir = next(
                            (parent for parent in matched.parents
                             if parent.name == "build"),
                            None,
                        )
                        if build_dir is not None:
                            receipt = build_dir / "tokenfuzz-classpath.txt"
                            if receipt.is_file() and receipt not in receipts:
                                receipts.append(receipt)
                        break
                    parts.pop()
        if not receipts:
            receipts = sorted(root.rglob("build/tokenfuzz-classpath.txt"))
        seen_receipts: set[Path] = set()
        receipt_index = 0
        while receipt_index < len(receipts):
            receipt = receipts[receipt_index]
            receipt_index += 1
            if receipt in seen_receipts:
                continue
            seen_receipts.add(receipt)
            try:
                values = receipt.read_text(encoding="utf-8").strip().split(os.pathsep)
            except OSError:
                continue
            for value in values:
                dependency = Path(value)
                if not value:
                    continue
                # Gradle resolves project dependencies to the jar a normal
                # consumer would receive, but `classes` does not necessarily
                # materialize that jar. Use the dependency project's compiled
                # output directly and follow its receipt for the same runtime
                # closure. This is the Gradle equivalent of the Maven reactor
                # mapping above and avoids broadening every probe to the whole
                # workspace.
                build_dir = (
                    dependency.parent.parent.resolve()
                    if dependency.parent.name == "libs"
                    and dependency.parent.parent.name == "build"
                    else None
                )
                local = build_outputs.get(build_dir, []) if build_dir else []
                if local:
                    entries.extend(local)
                    transitive = build_dir / "tokenfuzz-classpath.txt"
                    if transitive.is_file() and transitive not in seen_receipts:
                        receipts.append(transitive)
                elif dependency.exists():
                    entries.append(dependency)
            for suffix in ("resources/main", "processedResources/jvm/main"):
                resource_root = receipt.parent / suffix
                if resource_root.is_dir():
                    entries.append(resource_root)
        if not entries:
            entries.extend(class_roots)
    return tuple(dict.fromkeys(str(path.resolve()) for path in entries))


def java_probe_runner_args(
    target_root: str | os.PathLike, build_system: str, target_file: str,
    testcase: str | os.PathLike | None = None,
) -> tuple[str, ...]:
    """Use the named source module's dependencies for one direct testcase."""
    entries = java_classpath_entries(
        target_root, build_system, target_file, testcase,
    )
    if not entries:
        return ()
    return ("--class-path", os.pathsep.join(entries), "{TESTCASE}")


def java_runner_args(
    target_root: str | os.PathLike, build_system: str,
) -> tuple[str, ...]:
    entries = java_classpath_entries(target_root, build_system)
    if not entries:
        return ("{TESTCASE}",)
    argfile = Path(target_root) / ".audit" / "java-runner.args"
    if not argfile.is_file():
        return ("{TESTCASE}",)
    return ("@{TARGET_ROOT}/.audit/java-runner.args", "{TESTCASE}")


def write_java_runner_argfile(
    target_root: str | os.PathLike, build_system: str,
) -> Path:
    """Materialize the resolved classpath outside target.toml/model context."""
    root = Path(target_root)
    entries = java_classpath_entries(root, build_system)
    if not entries:
        raise ValueError("Java bootstrap produced no compiled target classes")
    path = root / ".audit" / "java-runner.args"
    path.parent.mkdir(parents=True, exist_ok=True)
    classpath = os.pathsep.join(entries).replace("\\", "\\\\").replace('"', '\\"')
    path.write_text(f'--class-path\n"{classpath}"\n', encoding="utf-8")
    return path


def java_canary_classes(
    target_root: str | os.PathLike, build_system: str,
) -> tuple[str, ...]:
    """Return loadable-name candidates backed by this checkout's class dirs."""
    root = Path(target_root)
    names: list[str] = []
    class_roots = java_classpath_entries(root, build_system)
    for value in class_roots:
        class_root = Path(value)
        if not class_root.is_dir() or "classes" not in class_root.parts:
            continue
        for compiled in sorted(class_root.rglob("*.class")):
            relative = compiled.relative_to(class_root)
            if "$" in relative.name or relative.name in {
                "module-info.class", "package-info.class",
            }:
                continue
            names.append(".".join(relative.with_suffix("").parts))
            break
    return tuple(dict.fromkeys(names))


def write_gradle_init_script(target_root: str | os.PathLike) -> Path:
    """Create the target-agnostic task that records JVM runtime closures."""
    path = Path(target_root) / ".audit" / "tokenfuzz-gradle.init.gradle"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "allprojects { p ->\n"
        "  def prepare = p.tasks.register('tokenfuzzPrepare') { task ->\n"
        "    task.doLast {\n"
        "      def buildRoot = p.layout.buildDirectory.get().asFile\n"
        "      def entries = [\n"
        "        new File(buildRoot, 'classes/java/main'),\n"
        "        new File(buildRoot, 'classes/kotlin/main'),\n"
        "        new File(buildRoot, 'classes/kotlin/jvm/main'),\n"
        "        new File(buildRoot, 'resources/main'),\n"
        "        new File(buildRoot, 'processedResources/jvm/main')\n"
        "      ].findAll { it.isDirectory() }\n"
        "      p.configurations.findAll { c ->\n"
        "        c.canBeResolved && (c.name == 'runtimeClasspath' || c.name == 'jvmRuntimeClasspath')\n"
        "      }.each { c -> entries.addAll(c.files) }\n"
        "      if (!entries.isEmpty()) {\n"
        "        def receipt = new File(buildRoot, 'tokenfuzz-classpath.txt')\n"
        "        receipt.parentFile.mkdirs()\n"
        "        receipt.text = entries.collect { it.canonicalPath }.unique().join(File.pathSeparator)\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "  p.afterEvaluate {\n"
        "    ['classes', 'jvmMainClasses'].each { name ->\n"
        "      def lifecycle = p.tasks.findByName(name)\n"
        "      if (lifecycle != null) {\n"
        "        prepare.configure { task -> task.dependsOn(lifecycle) }\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    return path


# ─── Language entry ─────────────────────────────────────────────────
#
# Conventions:
#   - source_exts / harness_exts are lower-case and include the leading
#     dot. Workqueue and crash_artifacts compare via Path.suffix.lower()
#     so the leading-dot form is the natural shape.
#   - build_systems list every target.toml `build_system` slug that
#     selects this language. Multiple slugs are normal (java has
#     maven+gradle, c/c++ has cmake+meson+autotools+make+mach).
#   - interpreted=True means probe runs the harness directly through an
#     interpreter (no build cache). interpreted=False means probe shells
#     out to the language's compiler/build tool and caches the result.
#   - runner_* fields seed target.toml's [runner] block. They only apply
#     to build_systems whose targets typically lack an ASan build
#     (interpreted languages, plus cargo/go where the language runtime
#     IS the test driver). C/C++ build_systems (cmake/meson/...) leave
#     these empty so seed_toml does not emit a [runner] block.
#   - bootstrap_cmds runs inside the target checkout to make the source
#     tree importable/runnable. None means "no automatic build needed".
#     Each command is a tuple; arguments are NOT shell-expanded — the
#     caller execs them via subprocess.run([...]).
#
# Adding a language: append one entry to LANGUAGES and add coverage to
# tests/test_languages_py.py. No other file should need to change.


@dataclass(frozen=True)
class Language:
    name: str
    source_exts: tuple[str, ...] = ()
    harness_exts: tuple[str, ...] = ()
    build_systems: tuple[str, ...] = ()
    interpreted: bool = False

    # Compiled-harness build dispatch (probe build_kind). Only set when
    # the language has compiled harnesses; "" means no compiled path.
    build_kind: str = ""
    compiler_env: str = ""
    compiler_default: str = ""
    compiler_flags_env: str = ""

    # Interpreted-harness run dispatch. interpreter_default is the
    # binary probe invokes; interpreter_env is the override variable
    # (e.g. PYTHON3). interpreter_preargs are inserted before the
    # harness source path (e.g. ("-script",) for .kts).
    interpreter_env: str = ""
    interpreter_default: str = ""
    interpreter_preargs: tuple[str, ...] = ()

    # Script-only harness extensions for an otherwise-compiled
    # language. Kotlin is the motivating case: `.kt` is compiled via
    # `kotlinc` and run as a jar wrapper, but `.kts` is a script that
    # `kotlinc -script` interprets directly. Listing `.kts` here makes
    # probe_dispatch return the interpreted branch for that extension
    # while keeping `.kt` on the compiled path.
    script_exts: tuple[str, ...] = ()

    # target.toml [runner] block defaults. Only present for languages
    # whose typical target ships as source-only (interpreted) or whose
    # build tool doubles as a test driver. The dict shape matches
    # target_config.language_runner_defaults().
    runner_bin: str = ""
    runner_args: tuple[str, ...] = ("{TESTCASE}",)
    runner_env: tuple[str, ...] = ()
    crash_patterns: tuple[str, ...] = ()
    default_sanitizers: tuple[str, ...] = ()

    # Workqueue mode hint. workqueue.mode_for_file returns this string
    # when the file matches this language; the audit loop treats "js"
    # specially (browser-style probes). Empty defaults to "auto".
    work_mode: str = ""

    # Source-tree bootstrap. Tuple-of-tuples; each inner tuple is
    # argv-style (no shell expansion). When provided, the build step
    # (bin/audit lazily, or bin/setup-target --build) runs them
    # sequentially inside TARGET_ROOT. Use this to compile C extensions,
    # run cargo build, etc. before the audit loop starts. Recipes are
    # RELEASE mode (NDEBUG, -O2-class) so the build does not pull in
    # debug-only asserts that fire as noise rather than security signal —
    # see sanitizer_env below.
    bootstrap_cmds: tuple[tuple[str, ...], ...] = ()

    # When True, bootstrap is gated on the presence of a manifest file
    # in TARGET_ROOT (setup.py, pyproject.toml, Cargo.toml, ...).
    # Empty means "always run when a build is requested".
    bootstrap_manifests: tuple[str, ...] = ()

    # Fallback alternatives tried when the LAST bootstrap_cmd fails.
    # Used by `bin/setup-target` to express the npm "ci → install →
    # install --legacy-peer-deps" chain without target-specific
    # branching. Each entry is a full argv that replaces the failing
    # last command; the first one to exit zero wins. Empty (default)
    # means "the primary command must succeed or bootstrap aborts".
    bootstrap_alternatives: tuple[tuple[str, ...], ...] = ()

    # True when bootstrap installs a *copy* of the source (an R package
    # library, say) that nothing rebuilds on demand. Such a snapshot goes
    # stale when the checkout moves, and bin/setup-target forces a build
    # rather than letting every later probe audit the old copy.
    bootstrap_snapshot: bool = False

    # Environment variables to export before running bootstrap_cmds
    # AND captured into .audit/bootstrap.sh so reruns are
    # bit-identical. Use this to inject release-mode sanitizer flags
    # (CFLAGS, LDFLAGS, RUSTFLAGS, ...) that the language's build
    # tool consumes. KEY/value pairs; never expanded by a shell.
    sanitizer_env: tuple[tuple[str, str], ...] = ()

    # A reachability canary: one testcase in this language that bin/probe runs
    # through the seeded [runner] before an audit starts. What it prints is
    # what it asserts -- a `cwd=` line claims the runner executes from
    # TARGET_ROOT, and `path=` lines claim the runtime searches inside it.
    # Printing neither still proves the route executes at all. Empty means the
    # language cannot self-check: Swift's runner hands the testcase to the
    # package's own executable rather than running it as source.
    canary_source: str = ""

    # Maintained sanitizer / coverage-guided fuzzer toolchains that
    # exist for this language as of 2025. Informational; setup-target
    # prints it as one line so the operator sees what's auditable for
    # the target. Empty tuple = "no first-class toolchain in tree;
    # don't pretend otherwise." Drives nothing else — keep the field
    # honest rather than aspirational.
    fuzz_backends: tuple[str, ...] = ()


# ─── The registry ──────────────────────────────────────────────────
#
# Crash-pattern guidance: list runtime diagnostics that lib/triage.py
# should flag as crash signal. Always include the LLVM sanitizer
# banners — even interpreted runtimes can be invoked under a
# sanitizer wrapper and emit one. Keep patterns anchored where
# possible (^FATAL beats FATAL) so we don't false-positive on
# narrative testcase output.


_ASAN_BANNER = r"==\d+==ERROR: AddressSanitizer"
_TSAN_BANNER = r"WARNING: ThreadSanitizer:"
_MSAN_BANNER = r"WARNING: MemorySanitizer:"
RUBY_EXCEPTION_PATTERN = (
    r"^[^ \n].*:\d+:in .+: .* "
    r"\((?:[A-Z]\w*::)*[A-Z]\w*(?:Error|Exception)\)$"
)




# Node package-manager install chains, keyed by manager. Each chain is
# "primary first, then manager-specific fallbacks." `_js_bootstrap_chain`
# detects the manager a checkout expects (lockfile / Corepack
# `packageManager` field / `workspace:` protocol) and runs that chain
# first, with the other managers appended as last-ditch fallbacks. This
# is what keeps a pnpm/yarn monorepo from burning three doomed npm
# commands before it reaches the right tool. `npx --yes` fetches pnpm or
# yarn on demand, so a tree that needs them requires no global install.
_JS_INSTALL_CHAINS: dict[str, tuple[tuple[str, ...], ...]] = {
    # npm primary is `npm ci` (deterministic from package-lock.json);
    # fall back to `npm install` for lockfile drift, then
    # `--legacy-peer-deps` for npm-7+ strict peer-dep resolution.
    "npm": (
        ("npm", "ci", "--no-audit", "--no-fund"),
        ("npm", "install", "--no-audit", "--no-fund"),
        ("npm", "install", "--no-audit", "--no-fund", "--legacy-peer-deps"),
    ),
    # pnpm/yarn understand the `workspace:` protocol that npm rejects;
    # they are the install path for modern monorepos.
    "pnpm": (("npx", "--yes", "pnpm", "install"),),
    "yarn": (("npx", "--yes", "yarn", "install"),),
}


LANGUAGES: tuple[Language, ...] = (
    # ── C ──────────────────────────────────────────────────────────
    # Headers (.h) are auditable under C: many C public APIs live in
    # headers and prior-fix cards routinely touch them. C++ headers
    # (.hh/.hpp/.hxx) are under cpp below; .h is C by tradition though
    # C++ uses it too — workqueue.iter_source_files unions both so the
    # split doesn't matter for ranking.
    Language(
        name="c",
        source_exts=(".c", ".h"),
        harness_exts=(".c",),
        build_systems=("cmake", "meson", "autotools", "make", "mach", "gn"),
        interpreted=False,
        build_kind="cc",
        compiler_env="CC",
        compiler_default="clang",
        compiler_flags_env="CFLAGS",
        # No `bootstrap_cmds` here — C/C++ targets converge their
        # sanitizer build recipe through `bin/auto-build-script`,
        # which writes targets/<slug>/.audit/build.sh. Release-mode
        # ASan/UBSAN/MSAN/TSAN flags are produced there; this field
        # advertises which backends apply to a C target.
        fuzz_backends=("asan", "ubsan", "msan", "tsan", "libfuzzer"),
    ),

    # ── C++ ────────────────────────────────────────────────────────
    # C++ shares the C build_systems list — it's the same native tree.
    # We list build_systems empty here to avoid double-mapping a slug
    # to two languages in for_build_system(); C wins the lookup. The
    # source_exts and harness_exts still flow into the global unions.
    Language(
        name="cpp",
        source_exts=(".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"),
        harness_exts=(".cc", ".cpp", ".cxx", ".C"),
        build_systems=(),
        interpreted=False,
        build_kind="cc",
        compiler_env="CXX",
        compiler_default="clang++",
        compiler_flags_env="CXXFLAGS",
        fuzz_backends=("asan", "ubsan", "msan", "tsan", "libfuzzer"),
    ),

    # ── Rust ───────────────────────────────────────────────────────
    Language(
        name="rust",
        source_exts=(".rs",),
        harness_exts=(".rs",),
        build_systems=("cargo",),
        interpreted=False,
        build_kind="rust",
        compiler_env="RUSTC",
        compiler_default="rustc",
        compiler_flags_env="RUSTFLAGS",
        runner_bin="cargo",
        canary_source=r"""fn main() { print!("TOKENFUZZ-CANARY built"); }
""",
        runner_args=(
            "run", "--quiet",
            "--manifest-path", "{TARGET_ROOT}/Cargo.toml",
            "--", "{TESTCASE}",
        ),
        # Audit agents cannot populate a user-global Cargo registry from their
        # sandbox. Setup fills this target-owned cache before the audit, and
        # probes consume it without reaching the network.
        runner_env=(
            "CARGO_HOME={TARGET_ROOT}/.audit/cargo-home",
            "CARGO_NET_OFFLINE=true",
        ),
        crash_patterns=(
            r"thread '.*'( \([^)]*\))? panicked at",
            r"fatal runtime error:",
            _ASAN_BANNER,
            _TSAN_BANNER,
            _MSAN_BANNER,
        ),
        # Release build so `debug-assertions` (Rust's panic-on-invariant
        # equivalent of C `assert()`) and `overflow-checks` are off —
        # they produce panics on conditions that are not security
        # findings. `--locked` makes the bootstrap reproducible.
        # `cargo fetch` runs first because it also pulls dev-dependencies,
        # which a direct .rs testcase links and `cargo build` never fetches.
        # It regenerates a drifted lockfile, reaching the same place the
        # fallback below would; the exact commands stay in .audit/bootstrap.sh.
        bootstrap_cmds=(
            ("cargo", "fetch"),
            ("cargo", "build", "--release", "--locked"),
        ),
        # Fallback drops --locked: handles lockfile drift (older
        # Cargo.lock schema vs. current cargo, transitive yanks,
        # minimum-rust-version bumps). Cargo may regenerate the lock,
        # which is fine for an audit — the recipe persisted to
        # .audit/bootstrap.sh still names the exact command that ran.
        bootstrap_alternatives=(
            ("cargo", "build", "--release"),
        ),
        bootstrap_manifests=("Cargo.toml",),
        sanitizer_env=(("CARGO_HOME", ".audit/cargo-home"),),
        # ASan via `-Zsanitizer=address` requires the nightly toolchain
        # plus `rust-src` to rebuild std. That's a real setup step the
        # operator must take separately; we don't try to inject it here
        # because a wrong RUSTFLAGS hides the failure from cargo. The
        # release build alone is still useful — runs under the project's
        # own test suite with overflow/debug-asserts off.
        fuzz_backends=("cargo-fuzz", "afl.rs", "asan-nightly"),
    ),

    # ── Go ─────────────────────────────────────────────────────────
    Language(
        name="go",
        source_exts=(".go",),
        harness_exts=(".go",),
        build_systems=("go",),
        interpreted=False,
        build_kind="go",
        compiler_env="GO",
        compiler_default="go",
        compiler_flags_env="GOFLAGS",
        runner_bin="go",
        canary_source=r"""package main

import (
	"fmt"
	"os"
)

func main() {
	d, _ := os.Getwd()
	fmt.Print("TOKENFUZZ-CANARY cwd=" + d)
}
""",
        runner_args=("run", "-race", "{TESTCASE}"),
        runner_env=(
            "GOFLAGS=-mod=mod",
            "GORACE=halt_on_error=1",
            "GOCACHE={TARGET_ROOT}/.audit/go-build",
            "GOMODCACHE={TARGET_ROOT}/.audit/go-mod",
        ),
        default_sanitizers=("race",),
        crash_patterns=(
            r"WARNING: DATA RACE",
            r"panic: runtime error:",
            r"fatal error: stack overflow",
            r"fatal error: out of memory",
            r"runtime: out of memory",
            r"^goroutine \d+ \[",
        ),
        # `-race` is Go's maintained sanitizer (TSan-class data-race
        # detection) and works on stock toolchains. `-trimpath` keeps
        # paths reproducible across hosts. `-asan`/`-msan` apply only
        # to cgo and degrade silently on pure-Go trees, so we leave
        # them out of the default and rely on -race + the release
        # build (assertions are not a Go concept).
        # `go build std` primes the default build cache and runs first:
        # Go ships no precompiled standard library, so without it the first
        # `go run` — the runner canary — compiles std inside the per-run
        # execution deadline and a cold host reads as an unreachable route.
        # The -race build caches separately and does not cover it, and it
        # needs cgo, so a host with no C compiler falls back to the plain
        # release build rather than losing the target entirely.
        bootstrap_cmds=(
            ("go", "build", "std"),
            ("go", "build", "-race", "-trimpath", "./..."),
        ),
        bootstrap_alternatives=(
            ("go", "build", "-race", "-trimpath", "."),
            ("go", "build", "-trimpath", "./..."),
            ("go", "build", "-trimpath", "."),
        ),
        bootstrap_manifests=("go.mod",),
        sanitizer_env=(
            ("GOCACHE", "{TARGET_ROOT}/.audit/go-build"),
            ("GOMODCACHE", "{TARGET_ROOT}/.audit/go-mod"),
        ),
        fuzz_backends=("native-fuzz", "race"),
    ),

    # ── Swift ──────────────────────────────────────────────────────
    Language(
        name="swift",
        source_exts=(".swift",),
        harness_exts=(".swift",),
        build_systems=("swift",),
        interpreted=False,
        build_kind="swift",
        compiler_env="SWIFTC",
        compiler_default="swiftc",
        compiler_flags_env="SWIFTFLAGS",
        runner_bin="swift",
        # Package metadata refines this seed. Library products compile direct
        # Swift testcases through a detached path-dependent package; a package
        # with one executable product uses swift run with its real product
        # name. The source form is the safe fallback when metadata is not yet
        # readable: it never invents an executable from the target slug.
        runner_args=("{TESTCASE}",),
        runner_env=(
            "CLANG_MODULE_CACHE_PATH={TARGET_ROOT}/.audit/clang-module-cache",
            "SWIFTPM_MODULECACHE_OVERRIDE={TARGET_ROOT}/.audit/clang-module-cache",
        ),
        # Importing the module injected by runner_canary is the reachability
        # proof; the detached executable need not inherit TARGET_ROOT as cwd.
        canary_source='print("TOKENFUZZ-CANARY built")\n',
        default_sanitizers=("asan",),
        crash_patterns=(
            r"Fatal error:",
            _ASAN_BANNER,
            _TSAN_BANNER,
        ),
        # Release config (`-c release` strips Swift debug asserts and turns on
        # optimization). Direct library probes build outside the testcase
        # execution deadline and cache their package dependencies.
        bootstrap_cmds=(
            (
                "swift", "build", "--disable-sandbox", "-c", "release",
                "--cache-path", ".audit/swiftpm/cache",
                "--config-path", ".audit/swiftpm/configuration",
                "--security-path", ".audit/swiftpm/security",
                "-Xswiftc", "-O", "-Xswiftc", "-module-cache-path",
                "-Xswiftc", ".audit/clang-module-cache",
            ),
        ),
        bootstrap_manifests=("Package.swift",),
        fuzz_backends=("asan", "tsan", "ubsan", "libfuzzer"),
    ),

    # ── Java ───────────────────────────────────────────────────────
    # Both .java source compilation and single-file script execution
    # (JEP 330) are valid. We classify .java as interpreted in the
    # harness-dispatch table because `java <file>` runs without an
    # explicit compile step — but build_kind="java" is set so callers
    # that care can distinguish from a pure script language.
    Language(
        name="java",
        source_exts=(".java",),
        harness_exts=(".java",),
        build_systems=("maven", "gradle"),
        interpreted=True,
        build_kind="java",
        interpreter_env="JAVA",
        interpreter_default="java",
        canary_source=r"""public class Canary {
    public static void main(String[] args) {
        System.out.print("TOKENFUZZ-CANARY cwd=" + System.getProperty("user.dir"));
    }
}
""",
        runner_bin="java",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"Exception in thread",
            r"java\.lang\.OutOfMemoryError",
            r"java\.lang\.StackOverflowError",
            r"^\s+at \S+\(\S+:\d+\)",
        ),
        # The JVM is the memory-safety boundary; there is no
        # `-fsanitize=address`-style instrumentation for `javac`
        # output. The only first-class coverage-guided tool is
        # Code Intelligence's jazzer, which needs a written
        # FuzzXxx.java harness (a separate generator step).
        fuzz_backends=("jazzer",),
    ),

    # ── Kotlin ─────────────────────────────────────────────────────
    # Two harness extensions: .kt is compiled (kotlinc + jar wrapper),
    # .kts is script-interpreted (kotlinc -script). Both flow through
    # the same toolchain binary. .kt is treated as compiled by probe
    # while .kts is interpreted; interpreter_preargs encodes the
    # -script switch the kts path needs.
    Language(
        name="kotlin",
        source_exts=(".kt", ".kts"),
        harness_exts=(".kt", ".kts"),
        build_systems=("kotlin",),
        interpreted=False,
        build_kind="kotlin",
        compiler_env="KOTLINC",
        compiler_default="kotlinc",
        compiler_flags_env="KOTLINCFLAGS",
        # .kts is the script variant — same toolchain binary,
        # invoked with -script and run without an intermediate jar.
        # See script_exts docstring for the dispatch impact.
        script_exts=(".kts",),
        interpreter_env="KOTLINC",
        interpreter_default="kotlinc",
        canary_source=r"""print("TOKENFUZZ-CANARY cwd=" + java.io.File(".").canonicalPath)
""",
        interpreter_preargs=("-script",),
        runner_bin="kotlinc",
        runner_args=("-script", "{TESTCASE}"),
        crash_patterns=(
            r"Exception in thread",
            r"kotlin\.\w+(Exception|Error):",
            r"java\.lang\.\w+(Exception|Error):",
        ),
        fuzz_backends=("jazzer",),
    ),

    # ── Python ─────────────────────────────────────────────────────
    # Cython (.pyx/.pxd) is included as source so pyyaml-style trees
    # that ship a .pyx alongside a generated .c are ranked under
    # both. The .pyx is the audit-relevant source; the generated .c
    # is also picked up via the C entry.
    Language(
        name="python",
        source_exts=(".py", ".pyx", ".pxd"),
        harness_exts=(".py",),
        build_systems=("python",),
        interpreted=True,
        interpreter_env="PYTHON3",
        interpreter_default="python3",
        canary_source=r"""import os, sys
sys.stdout.write("\n".join(
    ["TOKENFUZZ-CANARY cwd=" + os.getcwd()]
    + ["TOKENFUZZ-CANARY path=" + p for p in sys.path if p]
))
""",
        runner_bin="python3",
        runner_args=("{TESTCASE}",),
        runner_env=(
            "PYTHONDEVMODE=1",
            "PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib",
        ),
        crash_patterns=(
            r"Traceback \(most recent call last\):",
            r"MemoryError",
            r"RecursionError",
            r"SystemError",
            r"Fatal Python error:",
            _ASAN_BANNER,
        ),
        # Build C extensions in-place so cp-tagged .so files match the
        # currently-running interpreter. Without this, prebuilt sdist
        # extensions (e.g. pyyaml shipping cp39 .so under a cp314
        # interpreter) ENV-BLOCK every C-side work card. The manifest
        # gate is `setup.py`: pure-Python or pyproject-only projects
        # without a shim do not need this step at all.
        #
        # Three-step recipe hardened against PEP 668 (Homebrew /
        # Debian externally-managed pythons), missing setuptools,
        # and projects that need Cython/numpy provisioned per
        # `[build-system].requires`:
        #   1. Create a venv at .audit/venv. The venv's interpreter
        #      is a thin wrapper around system python3, so .so files
        #      built under it carry the same cpython-XYZ ABI tag as
        #      the runner's python3 — the runner can still use
        #      system python3 to import them.
        #   2. Upgrade pip inside the venv (older pip lacks PEP 660
        #      editable-install hooks for C-extension projects).
        #   3. `pip install -e .` — editable install with build
        #      isolation. pip auto-provisions setuptools/Cython/numpy
        #      from pyproject.toml `[build-system].requires` into an
        #      ephemeral build env, so this works on guest accounts
        #      without setuptools and on projects that need Cython
        #      to regenerate .c sources. setuptools' editable_mode
        #      defaults to "compat" for C-ext projects, which writes
        #      the .so files in-place next to the source — exactly
        #      what the runner's PYTHONPATH expects. CFLAGS/LDFLAGS
        #      from sanitizer_env propagate through build isolation.
        bootstrap_cmds=(
            ("python3", "-m", "venv", ".audit/venv"),
            (".audit/venv/bin/python", "-m", "pip", "install",
             "--upgrade", "pip"),
            (".audit/venv/bin/python", "-m", "pip", "install", "-e", "."),
        ),
        bootstrap_manifests=("setup.py",),
        # Release-mode build flags. NDEBUG strips C-level asserts that
        # produce noise (defensive checks, internal invariants) and
        # are not security findings. -O2 matches what distros ship.
        # No `-fsanitize=address` here: importing an ASan-instrumented
        # .so under a non-ASan Python aborts with link-order errors;
        # the runner does not LD_PRELOAD libasan. Use the atheris
        # backend (see fuzz_backends) when ASan instrumentation is
        # actually needed.
        sanitizer_env=(
            ("CFLAGS", "-O2 -g1 -DNDEBUG -fno-omit-frame-pointer"),
            ("CXXFLAGS", "-O2 -g1 -DNDEBUG -fno-omit-frame-pointer"),
        ),
        fuzz_backends=("atheris",),
    ),

    # ── JavaScript (Node) ──────────────────────────────────────────
    Language(
        name="javascript",
        source_exts=(".js", ".mjs", ".cjs"),
        harness_exts=(".js", ".mjs"),
        build_systems=("npm",),
        interpreted=True,
        interpreter_env="NODE",
        interpreter_default="node",
        canary_source=r"""process.stdout.write("TOKENFUZZ-CANARY cwd=" + process.cwd())
""",
        runner_bin="node",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"^FATAL ERROR:",
            r"RangeError: Maximum call stack",
            r"Allocation failed",
            r"^Error:",
            r"node:internal/.*",
        ),
        work_mode="js",
        # Bootstrap is gated on package.json so monorepos without one
        # (e.g. plain script bundles) skip the step. We dropped `--silent`
        # so failures are diagnosable in .audit/bootstrap.log — the old
        # quiet form ate ERESOLVE messages and made bootstrap "fail
        # without explanation."
        #
        # These static fields are the npm-default chain: the primary and
        # alternatives setup-target uses when it has no target to inspect
        # (e.g. `bootstrap-cmds npm` with no root). At run time
        # `_js_bootstrap_chain` re-derives the order from the actual
        # checkout, so a pnpm/yarn workspace (Angular and most modern
        # monorepos use `workspace:`) runs the right manager first
        # instead of falling through three failing npm invocations. Both
        # the default and the derived chains come from _JS_INSTALL_CHAINS
        # so there is one source of truth.
        bootstrap_cmds=(_JS_INSTALL_CHAINS["npm"][0],),
        bootstrap_alternatives=(
            _JS_INSTALL_CHAINS["npm"][1:]
            + _JS_INSTALL_CHAINS["pnpm"]
            + _JS_INSTALL_CHAINS["yarn"]
        ),
        bootstrap_manifests=("package.json",),
        # JS itself has no memory unsafety to instrument; native
        # addons (N-API) could be ASan-instrumented but require
        # rebuilding Node under ASan, out of scope here. jsfuzz is
        # the maintained coverage-guided option; mark and move on.
        fuzz_backends=("jsfuzz",),
    ),

    # ── TypeScript ─────────────────────────────────────────────────
    # TS shares npm with JavaScript but has its own extension set and
    # ts-node interpreter. We list it as build_systems=() to avoid
    # double-mapping the "npm" slug; for_build_system("npm") will
    # return javascript, and for_harness_ext(".ts") will return
    # typescript — the right answer in both lookups.
    Language(
        name="typescript",
        source_exts=(".ts", ".tsx"),
        harness_exts=(".ts", ".tsx"),
        build_systems=(),
        interpreted=True,
        interpreter_env="TSNODE",
        interpreter_default="ts-node",
        # No runner_bin: a TS-only target is rare; npm is the build_system
        # and javascript supplies the runner block.
        fuzz_backends=("jsfuzz",),
    ),

    # ── PHP ────────────────────────────────────────────────────────
    Language(
        name="php",
        source_exts=(".php",),
        harness_exts=(".php",),
        build_systems=("composer",),
        interpreted=True,
        interpreter_env="PHP",
        interpreter_default="php",
        canary_source=r"""<?php print("TOKENFUZZ-CANARY cwd=" . getcwd());
""",
        runner_bin="php",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"Fatal error:",
            r"PHP Fatal error:",
            r"Stack trace:",
            r"Uncaught \w+Error:",
        ),
        # Dropped --quiet so install failures (network, plugin
        # signatures, php-extension version pins) surface in
        # .audit/bootstrap.log instead of vanishing into a silent rc=1.
        bootstrap_cmds=(("composer", "install", "--no-interaction"),),
        bootstrap_manifests=("composer.json",),
        # No maintained sanitizer/coverage-guided fuzzer for PHP as
        # of 2025. Keep the field empty rather than name something
        # that is not actively maintained.
        fuzz_backends=(),
    ),

    # ── Ruby ───────────────────────────────────────────────────────
    Language(
        name="ruby",
        source_exts=(".rb",),
        harness_exts=(".rb",),
        build_systems=("bundler",),
        interpreted=True,
        interpreter_env="RUBY",
        interpreter_default="ruby",
        canary_source=r"""print(["TOKENFUZZ-CANARY cwd=#{Dir.pwd}"]
    .concat($LOAD_PATH.map { |p| "TOKENFUZZ-CANARY path=#{p}" })
    .join("\n"))
""",
        runner_bin="ruby",
        runner_args=("{TESTCASE}",),
        runner_env=(
            "RUBYLIB={TARGET_ROOT}/lib",
            "BUNDLE_GEMFILE={TARGET_ROOT}/Gemfile",
            "BUNDLE_PATH={TARGET_ROOT}/vendor/bundle",
            "RUBYOPT=-rbundler/setup",
        ),
        crash_patterns=(
            r"^[A-Z]\w*Error",
            RUBY_EXCEPTION_PATTERN,
            r"SystemStackError",
            r"\(NoMemoryError\)",
            r"\(fatal\)",
        ),
        # Dropped --quiet for the same reason as composer/npm above.
        bootstrap_cmds=(("bundle", "install"),),
        bootstrap_manifests=("Gemfile",),
        # Install gems into the project (`vendor/bundle/`) instead of
        # the system Ruby gem dir. The default path on Homebrew /
        # rbenv-managed Rubies is not writable without sudo, and even
        # when it is, polluting the system gemset across targets is
        # the wrong default for an audit harness. BUNDLE_PATH is the
        # canonical bundler env var for this; honoured since bundler
        # 1.x. Operators must `bundle exec` to pick up the vendored
        # gems at run time (separate runner change).
        sanitizer_env=(("BUNDLE_PATH", "vendor/bundle"),),
        fuzz_backends=(),
    ),

    # ── Perl ───────────────────────────────────────────────────────
    Language(
        name="perl",
        source_exts=(".pl", ".pm"),
        harness_exts=(".pl",),
        build_systems=("perl",),
        interpreted=True,
        interpreter_env="PERL",
        interpreter_default="perl",
        canary_source=r"""use Cwd ();
print join("\n",
    "TOKENFUZZ-CANARY cwd=" . Cwd::getcwd(),
    map { "TOKENFUZZ-CANARY path=$_" } @INC);
""",
        runner_bin="perl",
        runner_args=("{TESTCASE}",),
        runner_env=(
            "PERL5LIB={TARGET_ROOT}/blib/lib:{TARGET_ROOT}/blib/arch:{TARGET_ROOT}/.audit/perl5/lib/perl5:{TARGET_ROOT}/lib",
        ),
        crash_patterns=(
            r"^Out of memory!",
            r"^Segmentation fault",
            r"died at .* line",
        ),
        bootstrap_cmds=(
            ("cpanm", "--verbose", "--local-lib-contained", ".audit/perl5", "--installdeps", "."),
            ("perl", "Makefile.PL", "INSTALL_BASE={TARGET_ROOT}/.audit/perl5"),
            ("make",),
            ("make", "install"),
        ),
        bootstrap_manifests=("Makefile.PL",),
        sanitizer_env=(
            ("PERL5LIB", "{TARGET_ROOT}/.audit/perl5/lib/perl5"),
            ("PERL_MM_OPT", "INSTALL_BASE={TARGET_ROOT}/.audit/perl5"),
            ("PERL_MB_OPT", "--install_base {TARGET_ROOT}/.audit/perl5"),
        ),
    ),

    # ── R ──────────────────────────────────────────────────────────
    Language(
        name="r",
        source_exts=(".r", ".R"),
        harness_exts=(".r", ".R"),
        build_systems=("rlang",),
        interpreted=True,
        interpreter_env="RSCRIPT",
        interpreter_default="Rscript",
        canary_source=r"""cat(paste0("TOKENFUZZ-CANARY ", c(paste0("cwd=", getwd()),
                     paste0("path=", .libPaths()))), sep="\n")
""",
        runner_bin="Rscript",
        runner_args=("{TESTCASE}",),
        runner_env=("R_LIBS_USER={TARGET_ROOT}/.audit/r-library",),
        crash_patterns=(r"^Error in", r"^Error:"),
        # Sourcing the package's R files would miss any compiled component,
        # so the package and its hard dependencies are installed into a
        # target-local library instead. remotes reads DESCRIPTION using R's
        # package metadata rules and avoids rebuilding dependencies that are
        # already current.
        bootstrap_cmds=(
            (
                "Rscript", "-e",
                "dir.create('.audit/r-library', recursive=TRUE, showWarnings=FALSE)",
            ),
            (
                "Rscript", "-e",
                "lib <- normalizePath('.audit/r-library'); "
                ".libPaths(c(lib, .libPaths())); "
                "repos <- getOption('repos'); "
                "if (!length(repos) || is.na(repos['CRAN']) || "
                "repos['CRAN'] == '@CRAN@') "
                "repos['CRAN'] <- 'https://cloud.r-project.org'; "
                "if (!requireNamespace('remotes', quietly=TRUE)) "
                "install.packages('remotes', lib=lib, repos=repos); "
                "remotes::install_deps('.', dependencies=NA, "
                "upgrade='always', lib=lib, repos=repos)",
            ),
            ("R", "CMD", "INSTALL", "--library=.audit/r-library", "."),
        ),
        bootstrap_manifests=("DESCRIPTION",),
        bootstrap_snapshot=True,
        sanitizer_env=(("R_LIBS_USER", ".audit/r-library"),),
    ),

    # ── Shell ──────────────────────────────────────────────────────
    # Shell scripts are not audit-rankable as source (no shell target in
    # the ranker's wheelhouse) but they ARE valid harness drivers — a
    # // HARNESS: harness.sh wrapping a CLI is the simplest possible
    # repro. We keep source_exts empty so workqueue doesn't pick up
    # build/*.sh by accident.
    Language(
        name="shell",
        source_exts=(),
        harness_exts=(".sh", ".bash"),
        build_systems=(),
        interpreted=True,
        interpreter_env="BASH",
        interpreter_default="bash",
    ),
)


# ─── Internal lookup tables ────────────────────────────────────────


def _by_name() -> dict[str, Language]:
    return {lang.name: lang for lang in LANGUAGES}


def _by_build_system() -> dict[str, Language]:
    table: dict[str, Language] = {}
    for lang in LANGUAGES:
        for slug in lang.build_systems:
            # First entry wins — order in LANGUAGES is the tie-break.
            # This is why C lists the native build systems and C++
            # lists none: a "cmake" target is C (its source_exts union
            # picks up C++ too).
            table.setdefault(slug, lang)
    return table


def _by_harness_ext() -> dict[str, Language]:
    table: dict[str, Language] = {}
    for lang in LANGUAGES:
        for ext in lang.harness_exts:
            # Case folding: store both lower and upper if both are
            # registered (e.g. ".C" vs ".c"). Probe passes the raw
            # extension; we look up lower-cased.
            table.setdefault(ext.lower(), lang)
    return table


def _by_source_ext() -> dict[str, Language]:
    table: dict[str, Language] = {}
    for lang in LANGUAGES:
        for ext in lang.source_exts:
            table.setdefault(ext.lower(), lang)
    return table


# ─── Public API ────────────────────────────────────────────────────


def all_source_exts() -> frozenset[str]:
    """All extensions workqueue should consider audit-rankable source.

    Returned as a frozenset of lower-cased ext strings with leading
    dots (".c", ".py", ".ts", ...). This is the union across every
    Language entry — adding a new language to LANGUAGES automatically
    widens the set everywhere workqueue uses it.
    """
    out: set[str] = set()
    for lang in LANGUAGES:
        for ext in lang.source_exts:
            out.add(ext.lower())
    return frozenset(out)


# Report locations may cite source embedded in a target even when TokenFuzz
# cannot compile or run that language directly. Keep those established source
# forms alongside the runnable-language registry so every location parser uses
# one extension family instead of drifting per consumer.
_REPORT_ONLY_SOURCE_EXTS = frozenset({
    ".bash", ".cs", ".fs", ".hs", ".jsx", ".lua", ".m", ".ml", ".mm",
    ".scala", ".sh", ".zsh",
})


def source_reference_ext_pattern() -> str:
    """Regex alternation for source paths cited in reports, without dots."""
    names = {ext.removeprefix(".") for ext in all_source_exts()}
    names.update(ext.removeprefix(".") for ext in _REPORT_ONLY_SOURCE_EXTS)
    return "|".join(re.escape(name) for name in sorted(names, key=lambda n: (-len(n), n)))


def all_crash_patterns() -> tuple[str, ...]:
    """All runtime crash / sanitizer banners across every Language.

    The deduped union of every Language's ``crash_patterns`` — the LLVM
    sanitizer banners (ASan/UBSan/MSan/TSan) plus per-runtime crash
    signatures (Rust/Go panics, ``fatal runtime error:``). Adding a language
    or a new sanitizer banner to LANGUAGES widens this everywhere it is used,
    so consumers stay generic across every sanitizer the harness supports.
    Registry order is preserved so a compiled alternation is deterministic.
    """
    out: list[str] = []
    seen: set[str] = set()
    for lang in LANGUAGES:
        for pat in lang.crash_patterns:
            if pat not in seen:
                seen.add(pat)
                out.append(pat)
    return tuple(out)


def all_harness_exts(*, compiled: Optional[bool] = None) -> frozenset[str]:
    """All extensions probe accepts as a // HARNESS: source.

    `compiled=True`  -> only extensions probe routes to a compiler
    `compiled=False` -> only extensions probe routes to an interpreter
    `compiled=None`  -> both

    Script extensions on a compiled language (e.g. `.kts` on Kotlin)
    are correctly bucketed as interpreted — probe runs them directly
    via `kotlinc -script` rather than going through the build cache.
    """
    out: set[str] = set()
    for lang in LANGUAGES:
        scripts = {e.lower() for e in lang.script_exts}
        for ext in lang.harness_exts:
            is_script = ext.lower() in scripts
            ext_compiled = (not lang.interpreted) and (not is_script)
            if compiled is True and not ext_compiled:
                continue
            if compiled is False and ext_compiled:
                continue
            out.add(ext.lower())
    return frozenset(out)


def for_name(name: str) -> Optional[Language]:
    return _by_name().get(name.lower())


def for_build_system(slug: str) -> Optional[Language]:
    """Return the language that owns `slug` as one of its build_systems."""
    return _by_build_system().get(slug)


def default_sanitizers_for_build_system(slug: str) -> tuple[str, ...]:
    """Sanitizers selected by a language's canonical runner."""
    language = for_build_system(slug)
    return language.default_sanitizers if language else ()


def runner_preflight_args(
    language: Language, configured_args: Sequence[str],
) -> tuple[str, ...]:
    """Build argv matching a configured runner route, or no preparation.

    Swift's ``--skip-build`` route is the only registry runner that requires a
    prepared product. Derive its build prefix from the operator-visible run
    argv so target-local compiler flags and scratch paths cannot drift from
    the binary probes execute.
    """
    values = tuple(str(value) for value in configured_args)
    if language.name != "swift" or "--skip-build" not in values:
        return ()
    if not values or values[0] != "run" or values.count("{TESTCASE}") != 1:
        raise ValueError(
            "Swift [runner].args with --skip-build must be `run <options> "
            "<product> {TESTCASE}`"
        )
    testcase_index = values.index("{TESTCASE}")
    if testcase_index < 2 or values[testcase_index - 1].startswith("-"):
        raise ValueError(
            "Swift [runner].args must name the executable product immediately "
            "before {TESTCASE}"
        )
    return (
        "build",
        *(value for value in values[1:testcase_index - 1] if value != "--skip-build"),
        "--product", values[testcase_index - 1],
    )


def for_harness_ext(ext: str) -> Optional[Language]:
    """Return the language whose harness dispatch claims `ext`.

    `ext` may be passed with or without the leading dot; case is
    folded. Returns None when no language claims it — probe will
    surface this as an unsupported-extension error.
    """
    if not ext:
        return None
    if not ext.startswith("."):
        ext = "." + ext
    return _by_harness_ext().get(ext.lower())


def for_source_ext(ext: str) -> Optional[Language]:
    """Return the language whose source_exts claims `ext`, or None."""
    if not ext:
        return None
    if not ext.startswith("."):
        ext = "." + ext
    return _by_source_ext().get(ext.lower())


def mode_for_ext(ext: str) -> str:
    """Return the workqueue work_mode for a source extension.

    Defaults to "auto" when no language claims the extension or the
    language has no explicit mode. This replaces the hardcoded
    ".js/.mjs -> js" check in workqueue.mode_for_file.
    """
    lang = for_source_ext(ext)
    if lang and lang.work_mode:
        return lang.work_mode
    return "auto"


def runner_table() -> dict[str, dict]:
    """Build the LANGUAGE_RUNNERS dict consumed by target_config.

    The returned dict's keys are target.toml `build_system` slugs and
    the values are the [runner] block defaults (bin/args/env/crash_patterns).
    Languages whose runner_bin is empty (e.g. pure native C/C++) are
    omitted — seed_toml won't emit a [runner] block for them.
    """
    table: dict[str, dict] = {}
    for lang in LANGUAGES:
        if not lang.runner_bin:
            continue
        block = {
            "bin": lang.runner_bin,
            "args": list(lang.runner_args),
            "env": list(lang.runner_env),
            "crash_patterns": list(lang.crash_patterns),
        }
        for slug in lang.build_systems:
            table.setdefault(slug, block)
    return table


def probe_dispatch(ext: str) -> Optional[dict]:
    """Return a dict describing how bin/probe should run a harness ext.

    Shape:
        {
          "build_kind": "cc" | "rust" | ... | "interpret",
          "compiler_env":     str (compiled only),
          "compiler_default": str (compiled only),
          "flags_env":        str (compiled only),
          "interpreter_env":     str (interpreted only),
          "interpreter_default": str (interpreted only),
          "interpreter_preargs": list[str] (interpreted only),
        }

    Scripts on otherwise-compiled languages (`.kts` on Kotlin) return
    the interpreted branch so probe can run them directly without a
    compile cache.
    """
    lang = for_harness_ext(ext)
    if not lang:
        return None
    norm_ext = ("." + ext.lstrip(".")).lower()
    is_script = norm_ext in {e.lower() for e in lang.script_exts}
    if lang.interpreted or is_script:
        return {
            "build_kind": "interpret",
            "interpreter_env": lang.interpreter_env,
            "interpreter_default": lang.interpreter_default,
            "interpreter_preargs": list(lang.interpreter_preargs),
        }
    return {
        "build_kind": lang.build_kind,
        "compiler_env": lang.compiler_env,
        "compiler_default": lang.compiler_default,
        "flags_env": lang.compiler_flags_env,
    }


def _js_package_manager(target_root: Path) -> str:
    """Detect the Node package manager a JS/TS checkout expects.

    Pure tree inspection — no target-specific knowledge. The signals are
    industry-wide conventions, strongest first:
      1. a manager's lockfile (pnpm-lock.yaml / yarn.lock / package-lock.json);
      2. package.json's "packageManager" field (the Corepack standard);
      3. the "workspace:" dependency protocol, which npm cannot resolve —
         such a tree needs pnpm or yarn, and pnpm is the more common
         monorepo choice (and the one npx already fetches for us).
    Returns "pnpm", "yarn", or "npm" (the default when nothing matches).
    """
    locks = (
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
    )
    existing = [(name, manager) for name, manager in locks
                if (target_root / name).exists()]
    if len(existing) > 1:
        # A failed fallback can leave an ignored foreign lockfile beside the
        # project's tracked one. Ask Git for the repository's actual choice
        # before file-name priority; outside Git, retain the stable convention
        # order below.
        try:
            tracked = subprocess.run(
                ["git", "-C", str(target_root), "ls-files", "--",
                 *(name for name, _manager in existing)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            tracked_names = set(tracked.stdout.splitlines()) if not tracked.returncode else set()
        except (OSError, subprocess.TimeoutExpired):
            tracked_names = set()
        selected = [manager for name, manager in existing if name in tracked_names]
        if len(selected) == 1:
            return selected[0]
    if existing:
        return existing[0][1]
    pkg = target_root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            data = {}
        pm = str(data.get("packageManager", "")).strip()
        for name in ("pnpm", "yarn", "npm"):
            if pm.startswith(name):
                return name
        for section in ("dependencies", "devDependencies",
                        "optionalDependencies", "peerDependencies"):
            deps = data.get(section)
            if isinstance(deps, dict) and any(
                isinstance(v, str) and v.startswith("workspace:")
                for v in deps.values()
            ):
                return "pnpm"
    return "npm"


def _js_bootstrap_chain(target_root: Path) -> list[tuple[str, ...]]:
    """Ordered install chain for a JS/TS target: the detected manager's
    commands first, then the other managers' install commands as
    last-ditch fallbacks. setup-target runs the head as the primary and
    the tail as alternatives."""
    pm = _js_package_manager(target_root)
    order = [pm] + [m for m in ("npm", "pnpm", "yarn") if m != pm]
    chain: list[tuple[str, ...]] = []
    for manager in order:
        chain.extend(_JS_INSTALL_CHAINS[manager])
    return chain


def _js_build_commands(target_root: Path) -> list[list[str]]:
    """Build a package that declares the conventional root build script."""
    try:
        package = json.loads(
            (target_root / "package.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    scripts = package.get("scripts", {})
    if not isinstance(scripts, dict) or not isinstance(scripts.get("build"), str):
        return []
    manager = _js_package_manager(target_root)
    if manager == "npm":
        return [["npm", "run", "build"]]
    return [["npx", "--yes", manager, "run", "build"]]


def _js_python_shim_env(target_root: Path) -> list[list[str]]:
    """Expose the legacy ``python`` name to native npm build scripts.

    Modern hosts commonly install only ``python3``. node-gyp understands that
    executable, but older vendored gyp files still spawn ``python`` directly.
    Keep the compatibility name inside the target's audit directory and put it
    first only for bootstrap subprocesses; never modify the host installation.
    """
    if shutil.which("python"):
        return []
    python3 = shutil.which("python3")
    if not python3:
        return []
    tool_dir = target_root / ".audit" / "tool-bin"
    tool_dir.mkdir(parents=True, exist_ok=True)
    shim = tool_dir / "python"
    body = f"#!/bin/sh\nexec {shlex.quote(python3)} \"$@\"\n"
    temporary = shim.with_name(f".{shim.name}.{os.getpid()}.tmp")
    temporary.write_text(body, encoding="utf-8")
    temporary.chmod(0o755)
    os.replace(temporary, shim)
    path = os.environ.get("PATH", "")
    return [
        ["PATH", f"{{TARGET_ROOT}}/.audit/tool-bin{os.pathsep}{path}"],
        ["PYTHON", python3],
    ]


def _composer_bootstrap_chain(target_root: Path) -> list[tuple[str, ...]]:
    """Prefer a full install, then fall back to production dependencies.

    Composer still resolves root ``require-dev`` platform requirements during
    an update with ``--no-dev``.  A missing development-only PHP extension can
    therefore prevent a usable production autoloader from being created.  The
    fallback ignores only extension requirements declared exclusively by the
    root development set; production requirements remain enforced.
    """
    primary = ("composer", "install", "--no-interaction")
    manifest = target_root / "composer.json"
    try:
        package = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return [primary]
    required = package.get("require", {})
    development = package.get("require-dev", {})
    if not isinstance(required, dict) or not isinstance(development, dict):
        return [primary]
    dev_extensions = sorted(
        name for name in development
        if name.startswith("ext-") and name not in required
    )
    if not dev_extensions:
        return [primary]
    fallback = primary + ("--no-dev",) + tuple(
        f"--ignore-platform-req={name}" for name in dev_extensions
    )
    return [primary, fallback]


def preferred_ruby_toolchain(
    environment: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Return the newest usable Ruby and its matching Bundler.

    Version managers normally expose their selected Ruby on PATH.  Homebrew's
    keg-only Ruby is a common exception, so ask an available ``brew`` for its
    prefix without embedding a platform path.  An explicit RUBY selection
    remains authoritative.
    """
    env = dict(os.environ if environment is None else environment)
    path = env.get("PATH", "")

    def resolve(value: str) -> Path | None:
        if not value:
            return None
        found = shutil.which(value, path=path)
        candidate = Path(found or value)
        return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None

    explicit = resolve(env.get("RUBY", ""))
    if explicit is not None:
        bundle = explicit.with_name("bundle")
        return str(explicit), str(bundle if os.access(bundle, os.X_OK) else "bundle")

    candidates: list[Path] = []
    path_ruby = resolve("ruby")
    if path_ruby is not None:
        candidates.append(path_ruby)
    brew = shutil.which("brew", path=path)
    if brew:
        try:
            completed = subprocess.run(
                [brew, "--prefix", "ruby"], env=env, capture_output=True,
                text=True, timeout=10, check=False,
            )
            brew_ruby = resolve(
                str(Path(completed.stdout.strip()) / "bin" / "ruby")
            ) if completed.returncode == 0 and completed.stdout.strip() else None
            if brew_ruby is not None and brew_ruby not in candidates:
                candidates.append(brew_ruby)
        except (OSError, subprocess.TimeoutExpired):
            pass

    versions: list[tuple[tuple[int, ...], Path]] = []
    for candidate in candidates:
        try:
            completed = subprocess.run(
                [str(candidate), "-e", "print RUBY_VERSION"], env=env,
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        match = re.fullmatch(r"\s*(\d+(?:\.\d+)+)\s*", completed.stdout)
        if completed.returncode == 0 and match:
            versions.append((tuple(map(int, match.group(1).split("."))), candidate))
    if not versions:
        return "ruby", "bundle"
    ruby = max(versions, key=lambda item: item[0])[1]
    bundle = ruby.with_name("bundle")
    if not bundle.is_file() or not os.access(bundle, os.X_OK):
        resolved_bundle = shutil.which("bundle", path=path)
        bundle = Path(resolved_bundle) if resolved_bundle else Path("bundle")
    return str(ruby), str(bundle)


def ruby_package_info(target_root: str | os.PathLike) -> RubyPackageInfo:
    """Read the root gem specification through Ruby's package API."""
    root = Path(target_root).resolve()
    ruby, _bundle = preferred_ruby_toolchain()
    script = r'''
require "json"
paths = Dir.glob("*.gemspec").sort
abort "expected one root gemspec, found #{paths.length}" unless paths.length == 1
spec = Gem::Specification.load(paths.first)
abort "could not load #{paths.first}" unless spec
puts JSON.generate({
  "name" => spec.name,
  "require_paths" => spec.require_paths,
  "extensions" => spec.extensions,
})
'''
    try:
        completed = subprocess.run(
            [ruby, "-e", script], cwd=root, capture_output=True,
            text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Ruby could not describe the root gem: {exc}") from exc
    if completed.returncode:
        detail = next(
            (line.strip() for line in completed.stderr.splitlines() if line.strip()),
            "no diagnostic output",
        )
        raise ValueError(f"Ruby could not describe the root gem: {detail}")
    try:
        raw = json.loads(completed.stdout)
        name = str(raw["name"])
        require_paths = tuple(str(value) for value in raw["require_paths"])
        extensions = tuple(str(value) for value in raw["extensions"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"Ruby returned malformed gem metadata: {exc}") from exc
    entrypoint = ""
    entrypoint_path = ""
    for require_path in require_paths:
        for candidate in (name, name.replace("-", "/"), name.replace("-", "_")):
            path = root / require_path / f"{candidate}.rb"
            if path.is_file():
                entrypoint = candidate
                entrypoint_path = str(path.resolve())
                break
        if entrypoint:
            break
    return RubyPackageInfo(name, entrypoint, entrypoint_path, extensions)


def preferred_perl_toolchain(
    environment: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Return the newest usable Perl and a cpanm script it can execute."""
    env = dict(os.environ if environment is None else environment)
    path = env.get("PATH", "")

    def usable(value: str) -> Path | None:
        candidate = Path(value)
        return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None

    explicit_value = env.get("PERL", "")
    if explicit_value:
        explicit = usable(shutil.which(explicit_value, path=path) or explicit_value)
        if explicit is not None:
            return str(explicit), shutil.which("cpanm", path=path) or "cpanm"

    candidates: list[Path] = []
    for directory in path.split(os.pathsep):
        candidate = usable(str(Path(directory) / "perl")) if directory else None
        if candidate is not None and candidate not in candidates:
            candidates.append(candidate)
    brew = shutil.which("brew", path=path)
    if brew:
        try:
            completed = subprocess.run(
                [brew, "--prefix", "perl"], env=env, capture_output=True,
                text=True, timeout=10, check=False,
            )
            candidate = usable(str(Path(completed.stdout.strip()) / "bin" / "perl"))
            if completed.returncode == 0 and candidate is not None and candidate not in candidates:
                candidates.append(candidate)
        except (OSError, subprocess.TimeoutExpired):
            pass

    versions: list[tuple[tuple[int, ...], Path]] = []
    for candidate in candidates:
        try:
            completed = subprocess.run(
                [str(candidate), "-e", "print $^V"], env=env,
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        match = re.fullmatch(r"\s*v?(\d+(?:\.\d+)+)\s*", completed.stdout)
        if completed.returncode == 0 and match:
            versions.append((tuple(map(int, match.group(1).split("."))), candidate))
    perl = max(versions, key=lambda item: item[0])[1] if versions else Path("perl")
    return str(perl), shutil.which("cpanm", path=path) or "cpanm"


def perl_local_lib_root(
    perl: str, environment: dict[str, str] | None = None,
) -> str:
    """Return a target-relative CPAN root isolated by Perl's binary ABI."""
    env = dict(os.environ if environment is None else environment)
    try:
        completed = subprocess.run(
            [perl, "-MConfig", "-e", 'print "$^V-$Config{archname}"'],
            env=env, capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        completed = None
    identity = completed.stdout.strip() if completed and completed.returncode == 0 else "current"
    identity = re.sub(r"[^A-Za-z0-9._-]+", "-", identity).strip("-") or "current"
    return f".audit/perl5/{identity}"


def perl_cpanm_prefix(perl: str, cpanm: str, local_lib: str) -> list[str]:
    """Return a deterministic, target-local cpanm invocation prefix."""
    return [
        perl, cpanm, "--verbose",
        "--mirror", "https://cpan.metacpan.org", "--mirror-only",
        "--local-lib-contained", local_lib,
    ]


def perl_canary_module(target_root: str | os.PathLike[str]) -> str:
    """Return the shallowest library module a Perl distribution ships."""
    root = Path(target_root) / "lib"
    try:
        modules = sorted(
            (path.relative_to(root).as_posix() for path in root.rglob("*.pm")),
            key=lambda value: (value.count("/"), len(value), value),
        )
    except OSError:
        return ""
    return modules[0] if modules else ""


def _go_embed_asset_commands(target_root: Path) -> list[list[str]]:
    """Build declared JS assets when a Go embed input is not generated yet."""
    package_roots: set[Path] = set()
    for source in target_root.rglob("*.go"):
        try:
            relative = source.relative_to(target_root)
            if any(part.startswith(".") or part == "vendor" for part in relative.parts):
                continue
            lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, ValueError):
            continue
        for line in lines:
            match = re.match(r"\s*//go:embed\s+(.+)$", line)
            if not match:
                continue
            try:
                patterns = shlex.split(match.group(1))
            except ValueError:
                continue
            for pattern in patterns:
                clean = pattern.removeprefix("all:")
                if not clean or any(source.parent.glob(clean)):
                    continue
                expected = source.parent / clean
                candidate = expected.parent
                while candidate != source.parent.parent:
                    manifest = candidate / "package.json"
                    if manifest.is_file():
                        try:
                            package = json.loads(manifest.read_text(encoding="utf-8"))
                        except (OSError, ValueError):
                            break
                        scripts = package.get("scripts", {})
                        if isinstance(scripts, dict) and isinstance(
                            scripts.get("build"), str
                        ):
                            package_roots.add(candidate)
                        break
                    if candidate == source.parent:
                        break
                    candidate = candidate.parent

    commands: list[list[str]] = []
    for package_root in sorted(package_roots):
        relative = package_root.relative_to(target_root).as_posix()
        manager = _js_package_manager(package_root)
        if manager == "npm":
            commands.extend([
                ["npm", "--prefix", relative, "ci", "--no-audit", "--no-fund"],
                ["npm", "--prefix", relative, "run", "build"],
            ])
        elif manager == "pnpm":
            commands.extend([
                ["npx", "--yes", "pnpm", "--dir", relative, "install"],
                ["npx", "--yes", "pnpm", "--dir", relative, "run", "build"],
            ])
        else:
            commands.extend([
                ["npx", "--yes", "yarn", "--cwd", relative, "install"],
                ["npx", "--yes", "yarn", "--cwd", relative, "run", "build"],
            ])
    return commands


def bootstrap_for_target(target_root: Path, build_system: str) -> list[list[str]]:
    """Return the bootstrap commands setup-target should run.

    Each command is an argv list (no shell expansion). The build_system
    selects the language; bootstrap_manifests gates per-command on the
    presence of the matching file in `target_root` so we don't try to
    `npm install` a tree that has no package.json.
    """
    lang = for_build_system(build_system)
    if not lang:
        return []
    if build_system == "maven":
        tool = "./mvnw" if os.access(target_root / "mvnw", os.X_OK) else "mvn"
        return [
            [tool, "-q", "-DskipTests", "compile"],
            [tool, "-q", "-DskipTests", "dependency:build-classpath",
             "-DincludeScope=runtime",
             "-Dmdep.outputFile=target/tokenfuzz-classpath.txt"],
        ]
    if build_system == "gradle":
        tool = "./gradlew" if os.access(target_root / "gradlew", os.X_OK) else "gradle"
        write_gradle_init_script(target_root)
        return [[
            tool, "--no-daemon", "-Dorg.gradle.configuration-cache=false",
            "--init-script",
            ".audit/tokenfuzz-gradle.init.gradle", "tokenfuzzPrepare",
        ]]
    if build_system == "bundler":
        _ruby, bundle = preferred_ruby_toolchain()
        return [[bundle, "install"]]
    if build_system == "perl":
        perl, cpanm = preferred_perl_toolchain()
        local_lib = perl_local_lib_root(perl)
        commands = []
        if (target_root / "Makefile").is_file():
            commands.append(["make", "realclean"])
        commands.extend([
            [*perl_cpanm_prefix(perl, cpanm, local_lib), "--installdeps", "."],
            [perl, "Makefile.PL", f"INSTALL_BASE={{TARGET_ROOT}}/{local_lib}"],
            ["make"],
            ["make", "install"],
        ])
        return commands
    if not lang.bootstrap_cmds:
        return []
    if lang.bootstrap_manifests:
        if not any((target_root / m).exists() for m in lang.bootstrap_manifests):
            return []
    if lang.name == "javascript":
        return [list(_js_bootstrap_chain(target_root)[0])] + \
            _js_build_commands(target_root)
    if lang.name == "php":
        return [list(_composer_bootstrap_chain(target_root)[0])]
    return [list(cmd) for cmd in lang.bootstrap_cmds]


def bootstrap_plan_for_target(target_root: Path, build_system: str) -> dict:
    """Return the full bootstrap plan: cmds, alternatives, env, backends.

    Shape (always all keys present, possibly empty):
        {
          "language": <name>,
          "cmds": [["python3", "-m", "pip", ...], ...],
          "alternatives": [["npm", "install", ...], ...],
          "post_cmds": [["npm", "run", "build"]],
          "module_queries": [{"cmd": [...], "install_prefix": [...]}],
          "clean_dirs": [".audit/generated-release"],
          "env": [["CFLAGS", "-O2 ..."], ...],
          "unset_env": ["NO_COLOR"],
          "fuzz_backends": ["atheris", ...],
        }

    `alternatives` apply to the LAST command in `cmds`: setup-target
    tries the primary, then each alternative in order. Empty list = no
    fallback. `env` is a list of [key, value] pairs to export before
    running cmds (also persisted into .audit/bootstrap.sh). Module queries
    return validated cpanm requirement lines for a subsequent install;
    generated directories eligible for cleanup must be children of `.audit`.
    """
    lang = for_build_system(build_system)
    out = {
        "language": lang.name if lang else "",
        "cmds": [],
        "alternatives": [],
        "post_cmds": [],
        "module_queries": [],
        "clean_dirs": [],
        "env": [],
        "unset_env": [],
        "fuzz_backends": [],
    }
    if not lang:
        return out
    out["fuzz_backends"] = list(lang.fuzz_backends)
    out["env"] = [list(p) for p in lang.sanitizer_env]
    if build_system in {"maven", "gradle"}:
        out["cmds"] = bootstrap_for_target(target_root, build_system)
        return out
    if build_system == "bundler":
        _ruby, bundle = preferred_ruby_toolchain()
        out["cmds"] = [[bundle, "install"]]
        if os.environ.get("CONFIGURE_ARGS"):
            out["env"].append(["CONFIGURE_ARGS", os.environ["CONFIGURE_ARGS"]])
        gemspecs = list(target_root.glob("*.gemspec"))
        ruby_package = ruby_package_info(target_root) if len(gemspecs) == 1 else None
        if ruby_package and ruby_package.extensions:
            out["post_cmds"] = [[bundle, "exec", "rake", "compile"]]
        return out
    if build_system == "perl":
        perl, cpanm = preferred_perl_toolchain()
        local_lib = perl_local_lib_root(perl)
        cpanm_prefix = perl_cpanm_prefix(perl, cpanm, local_lib)
        if (target_root / "dist.ini").is_file() and not (
            target_root / "Makefile.PL"
        ).is_file():
            dzil = f"{{TARGET_ROOT}}/{local_lib}/bin/dzil"
            dist_root = ".audit/perl-dist"
            out["cmds"] = [[*cpanm_prefix, "Dist::Zilla"]]
            out["module_queries"] = [{
                "cmd": [perl, dzil, "authordeps", "--missing", "--cpanm-versions"],
                "install_prefix": cpanm_prefix,
            }]
            out["clean_dirs"] = [dist_root]
            out["post_cmds"] = [
                [perl, dzil, "build", "--in", dist_root],
                [*cpanm_prefix, dist_root],
            ]
        else:
            out["cmds"] = bootstrap_for_target(target_root, build_system)
        out["env"] = [
            ["PERL5LIB", f"{{TARGET_ROOT}}/{local_lib}/lib/perl5"],
            ["PERL_MM_OPT", f"INSTALL_BASE={{TARGET_ROOT}}/{local_lib}"],
            ["PERL_MB_OPT", f"--install_base {{TARGET_ROOT}}/{local_lib}"],
            ["PERL_CPANM_HOME", "{TARGET_ROOT}/.audit/cpanm"],
        ]
        # Presentation preferences from the operator shell must not change a
        # dependency's test result during a non-interactive package build.
        out["unset_env"] = ["NO_COLOR"]
        return out
    if not lang.bootstrap_cmds:
        return out
    if lang.bootstrap_manifests:
        if not any((target_root / m).exists() for m in lang.bootstrap_manifests):
            return out
    if lang.name == "javascript":
        chain = _js_bootstrap_chain(target_root)
        out["cmds"] = [list(chain[0])]
        out["alternatives"] = [list(c) for c in chain[1:]]
        out["post_cmds"] = _js_build_commands(target_root)
        out["env"].extend(_js_python_shim_env(target_root))
    elif lang.name == "php":
        chain = _composer_bootstrap_chain(target_root)
        out["cmds"] = [list(chain[0])]
        out["alternatives"] = [list(c) for c in chain[1:]]
    else:
        out["cmds"] = [list(c) for c in lang.bootstrap_cmds]
        out["alternatives"] = [list(c) for c in lang.bootstrap_alternatives]
        if lang.name == "go":
            asset_commands = _go_embed_asset_commands(target_root)
            out["cmds"] = asset_commands + out["cmds"]
            if asset_commands:
                out["env"].extend(_js_python_shim_env(target_root))
    return out


def fuzz_backends_for_build_system(build_system: str) -> list[str]:
    """Return the maintained fuzz/sanitizer backends for `build_system`."""
    lang = for_build_system(build_system)
    return list(lang.fuzz_backends) if lang else []


def execute_bootstrap_plan(
    target_root: Path,
    plan: dict,
    log_path: Path,
    recipe_path: Path,
) -> int:
    """Execute a registry bootstrap plan without shell expansion."""
    import subprocess
    import tempfile

    commands: list[list[str]] = plan.get("cmds") or []
    alternatives: list[list[str]] = plan.get("alternatives") or []
    post_commands: list[list[str]] = plan.get("post_cmds") or []
    module_queries: list[dict] = plan.get("module_queries") or []
    clean_dirs: list[str] = plan.get("clean_dirs") or []
    env_pairs: list[list[str]] = plan.get("env") or []
    unset_env: list[str] = plan.get("unset_env") or []
    def materialize(value: str) -> str:
        return value.replace("{TARGET_ROOT}", str(target_root.resolve()))

    environment = os.environ.copy()
    for key, value in env_pairs:
        environment[key] = materialize(value)
    for key in unset_env:
        environment.pop(key, None)

    recipe_lines = [
        "#!/usr/bin/env bash",
        "# Auto-generated by bin/setup-target --build. Reproduces the",
        "# release-mode sanitizer build that the audit harness ran against.",
        "set -euo pipefail",
        'cd "$(dirname "$0")/.."',
    ]
    for key, value in env_pairs:
        recipe_lines.append(f"export {key}={shlex.quote(materialize(value))}")
    for key in unset_env:
        recipe_lines.append(f"unset {key}")

    log_path.parent.mkdir(parents=True, exist_ok=True)
    # The log describes this setup attempt. Keeping an earlier failed build's
    # diagnostics beside a later success makes the current result ambiguous.
    log_path.write_text("", encoding="utf-8")
    # A failed attempt must not leave a runnable recipe from an older source
    # revision that appears to reproduce the failure on record.
    recipe_path.unlink(missing_ok=True)

    js_metadata_names = (
        "package-lock.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "yarn.lock",
    )

    def js_install_snapshot() -> dict[Path, tuple[bytes | str, int] | None]:
        if plan.get("language") != "javascript":
            return {}
        snapshot: dict[Path, tuple[bytes | str, int] | None] = {}
        for name in js_metadata_names:
            path = target_root / name
            try:
                snapshot[path] = (
                    (os.readlink(path), 0) if path.is_symlink()
                    else (path.read_bytes(), path.stat().st_mode)
                )
            except FileNotFoundError:
                snapshot[path] = None
        return snapshot

    def restore_failed_js_install(
        snapshot: dict[Path, tuple[bytes | str, int] | None],
    ) -> None:
        if not snapshot:
            return
        node_modules = target_root / "node_modules"
        if node_modules.is_symlink():
            node_modules.unlink()
        elif node_modules.is_dir():
            shutil.rmtree(node_modules)
        elif node_modules.exists():
            node_modules.unlink()
        restore_js_metadata(snapshot)

    def restore_js_metadata(
        snapshot: dict[Path, tuple[bytes | str, int] | None],
    ) -> None:
        if not snapshot:
            return

        def remove_current(path: Path) -> None:
            if path.is_symlink() or not path.is_dir():
                path.unlink(missing_ok=True)
            else:
                shutil.rmtree(path)

        # An installer may replace metadata with a symlink, hard link, or
        # directory. Remove that object and restore the saved file atomically.
        with tempfile.TemporaryDirectory(prefix=".bootstrap-restore-", dir=target_root) as directory:
            for path, prior in snapshot.items():
                if prior is None:
                    remove_current(path)
                    continue
                content, mode = prior
                temporary = Path(directory) / path.name
                if isinstance(content, str):
                    temporary.symlink_to(content)
                else:
                    temporary.write_bytes(content)
                    temporary.chmod(mode)
                remove_current(path)
                os.replace(temporary, path)

    initial_js_snapshot = js_install_snapshot()

    for relative in clean_dirs:
        path = target_root / relative
        try:
            resolved = path.resolve()
            child = resolved.relative_to(target_root.resolve() / ".audit")
            # Only generated child directories are disposable. A link must
            # not turn that cleanup into deletion of unrelated audit state.
            if not child.parts or path.is_symlink():
                raise ValueError("cleanup requires a non-symlink child directory")
        except ValueError:
            print(
                f"[setup-target] bootstrap: refusing unsafe cleanup path: {path}",
                file=sys.stderr,
            )
            return 2
        path = resolved
        if path.exists():
            shutil.rmtree(path)
        recipe_lines.append(f"rm -rf -- {shlex.quote(str(path))}")

    def run(
        argv: list[str], *, clean_failed_js_install: bool = False,
    ) -> tuple[int, str]:
        argv = [materialize(arg) for arg in argv]
        js_snapshot = js_install_snapshot() if clean_failed_js_install else {}
        rendered = " ".join(shlex.quote(arg) for arg in argv)
        message = (
            f"[setup-target] bootstrap: {rendered} "
            f"(live log: {log_path})\n"
        )
        sys.stdout.write(message)
        sys.stdout.flush()
        with log_path.open("a+", encoding="utf-8") as log:
            log.write(message)
            log.flush()
            output_start = log.tell()
            process = subprocess.run(
                argv,
                cwd=target_root,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            log.flush()
            log.seek(output_start)
            output = log.read()
        if process.returncode and js_snapshot:
            restore_failed_js_install(js_snapshot)
        lines = output.splitlines()
        if process.returncode != 0:
            for line in lines[-40:]:
                print(line)
        elif lines:
            print(
                f"[setup-target] bootstrap: command completed "
                f"({len(lines)} output line(s); full output in {log_path})"
            )
        return process.returncode, output

    def cpanm_prerequisite_repair(
        argv: list[str], output: str, already_requested: set[str],
    ) -> list[str]:
        """Turn cpanm's own missing-prerequisite report into one safe retry.

        Repository checkouts often omit the META files shipped in a CPAN
        release.  In that case cpanm must execute Makefile.PL to discover
        configure requirements, but Makefile.PL can itself need those
        requirements.  cpanm reports them in a stable diagnostic before it
        fails.  Installing only those declared module names breaks the cycle
        without guessing from target source or weakening dependency checks.
        """
        if (
            not argv or "--installdeps" not in argv
            or not any(Path(arg).name == "cpanm" for arg in argv[:argv.index("--installdeps")])
        ):
            return []
        missing = []
        reported = re.findall(
            r"Warning: prerequisite ([A-Za-z_][A-Za-z0-9_:]*) "
            r"(?:[^\n]* )?not found(?:\.|$)",
            output,
        )
        reported.extend(
            module.replace("/", "::")
            for module in re.findall(
                r"Can't locate ([A-Za-z_][A-Za-z0-9_/]*)\.pm in @INC(?: .*?)? "
                r"at (?:Makefile\.PL|Build\.PL) line \d+",
                output,
            )
        )
        for module in reported:
            if module not in already_requested and module not in missing:
                missing.append(module)
        if not missing:
            return []
        split = argv.index("--installdeps")
        return [*argv[:split], *missing]

    def cpanm_download_failed(argv: list[str], output: str) -> bool:
        """Whether cpanm identified a transient repository transfer failure."""
        return (
            any(Path(arg).name == "cpanm" for arg in argv)
            and bool(re.search(r"(?m)^!?\s*(?:Download https?://\S+ failed|Couldn't fetch )", output))
        )

    def run_with_cpanm_retry(
        argv: list[str], *, clean_failed_js_install: bool = False,
    ) -> tuple[int, str]:
        returncode, output = run(
            argv, clean_failed_js_install=clean_failed_js_install,
        )
        if returncode and cpanm_download_failed(argv, output):
            print(
                "[setup-target] bootstrap: retrying cpanm after its "
                "reported repository transfer failure"
            )
            return run(
                argv, clean_failed_js_install=clean_failed_js_install,
            )
        return returncode, output

    final_index = len(commands) - 1
    for index, command in enumerate(commands):
        returncode, output = run_with_cpanm_retry(
            command,
            clean_failed_js_install=(
                plan.get("language") == "javascript" and index == final_index
            ),
        )
        requested_prerequisites: set[str] = set()
        while returncode:
            repair = cpanm_prerequisite_repair(
                command, output, requested_prerequisites,
            )
            if not repair:
                break
            modules = repair[len(command[:command.index("--installdeps")]):]
            requested_prerequisites.update(modules)
            print(
                "[setup-target] bootstrap: installing prerequisites reported "
                "by cpanm before retrying dependency discovery"
            )
            repair_returncode, _repair_output = run_with_cpanm_retry(repair)
            if repair_returncode:
                returncode = repair_returncode
                break
            recipe_lines.append(
                " ".join(shlex.quote(materialize(arg)) for arg in repair)
            )
            returncode, output = run_with_cpanm_retry(command)
        if returncode == 0:
            recipe_lines.append(
                " ".join(shlex.quote(materialize(arg)) for arg in command)
            )
            continue
        if index != final_index or not alternatives:
            print(
                f"[setup-target] bootstrap: command failed (rc={returncode}); "
                "aborting bootstrap",
                file=sys.stderr,
            )
            restore_js_metadata(initial_js_snapshot)
            return returncode
        succeeded = False
        for alternative in alternatives:
            print(
                f"[setup-target] bootstrap: primary failed (rc={returncode}); "
                "trying alternative"
            )
            returncode, _output = run_with_cpanm_retry(
                alternative,
                clean_failed_js_install=plan.get("language") == "javascript",
            )
            if returncode == 0:
                recipe_lines.append(
                    " ".join(shlex.quote(materialize(arg)) for arg in alternative)
                )
                succeeded = True
                break
        if not succeeded:
            print(
                f"[setup-target] bootstrap: all alternatives exhausted "
                f"(rc={returncode}); aborting",
                file=sys.stderr,
            )
            restore_js_metadata(initial_js_snapshot)
            return returncode

    cpanm_spec = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*(?:~[^\r\n]+)?"
    )
    for query in module_queries:
        query_command = [materialize(arg) for arg in query.get("cmd", [])]
        install_prefix = [
            materialize(arg) for arg in query.get("install_prefix", [])
        ]
        if not query_command or not install_prefix:
            print(
                "[setup-target] bootstrap: invalid module query in bootstrap plan",
                file=sys.stderr,
            )
            return 2
        rendered = " ".join(shlex.quote(arg) for arg in query_command)
        message = f"[setup-target] bootstrap: {rendered}\n"
        sys.stdout.write(message)
        sys.stdout.flush()
        process = subprocess.run(
            query_command, cwd=target_root, env=environment,
            capture_output=True, text=True,
        )
        with log_path.open("a", encoding="utf-8") as log:
            log.write(message)
            log.write(process.stdout or "")
            log.write(process.stderr or "")
        if process.returncode:
            for line in (process.stderr or process.stdout or "").splitlines()[-40:]:
                print(line)
            print(
                f"[setup-target] bootstrap: module query failed "
                f"(rc={process.returncode}); aborting bootstrap",
                file=sys.stderr,
            )
            return process.returncode
        specs = [line.strip() for line in process.stdout.splitlines() if line.strip()]
        malformed = [spec for spec in specs if not cpanm_spec.fullmatch(spec)]
        if malformed:
            print(
                "[setup-target] bootstrap: module query returned an invalid "
                f"cpanm requirement: {malformed[0]}",
                file=sys.stderr,
            )
            return 2
        if not specs:
            continue
        returncode, _output = run_with_cpanm_retry([*install_prefix, *specs])
        if returncode:
            print(
                f"[setup-target] bootstrap: queried module install failed "
                f"(rc={returncode}); aborting bootstrap",
                file=sys.stderr,
            )
            return returncode
        recipe_lines.append(
            " ".join(shlex.quote(arg) for arg in [*install_prefix, *specs])
        )

    for command in post_commands:
        returncode, _output = run_with_cpanm_retry(command)
        if returncode:
            print(
                f"[setup-target] bootstrap: post-install command failed "
                f"(rc={returncode}); aborting bootstrap",
                file=sys.stderr,
            )
            restore_js_metadata(initial_js_snapshot)
            return returncode
        recipe_lines.append(
            " ".join(shlex.quote(materialize(arg)) for arg in command)
        )

    recipe_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=recipe_path.parent,
            prefix=f".{recipe_path.name}.",
            delete=False,
        ) as recipe:
            temporary = Path(recipe.name)
            recipe.write("\n".join(recipe_lines) + "\n")
        temporary.chmod(0o755)
        os.replace(temporary, recipe_path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    print(f"[setup-target] bootstrap: wrote {recipe_path}")
    return 0


# `<modname>.cpython-NN[-platform...]` or `<modname>.pypyNN-NN[-platform...]`.
# We match the cpython/pypy + version prefix and stop — anything after
# (e.g. `-darwin`, `-x86_64-linux-gnu`) is the platform tag and varies.
_PY_EXT_ABI_RE = re.compile(r"^(cpython-\d+|pypy\d*-\d+)")


BOOTSTRAP_STAMP = ".audit/bootstrap.stamp"


def bootstrap_snapshot_stale(target_root: Path) -> bool:
    """Whether the last bootstrap snapshot predates the current source."""
    import target_config
    try:
        recorded = (Path(target_root) / BOOTSTRAP_STAMP).read_text(encoding="utf-8").strip()
    except OSError:
        return True
    return recorded != target_config.source_signature(target_root)


def write_bootstrap_stamp(target_root: Path) -> None:
    import target_config
    stamp = Path(target_root) / BOOTSTRAP_STAMP
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(target_config.source_signature(target_root) + "\n", encoding="utf-8")


def stale_python_extensions(target_root: Path) -> list[Path]:
    """Return Python C-extension .so files in ``target_root`` that the
    current interpreter cannot load.

    A file is "stale" when its ABI tag does not match
    ``sys.implementation.cache_tag`` AND no sibling .so for the active
    tag exists alongside it. The sibling check prevents false positives
    on targets that ship a matrix of prebuilt extensions (e.g. pillow
    keeps `cp39` and `cp314` .so files side-by-side — the cp314 file
    loads under Python 3.14, so the cp39 file is not blocking import).

    Detection is purely structural: filename → embedded ABI tag → set
    comparison. No knowledge of which modules a given target ships, no
    target-specific paths. Plain `libfoo.so` wrappers and abi3 .so files
    are ignored because they have no version-specific cache tag.

    Drives ``bin/setup-target``'s auto-bootstrap path: when this returns
    non-empty for a Python target, the runner cannot import any of the
    listed extensions and ``setup.py build_ext --inplace`` must rebuild
    against the current interpreter.
    """
    expected = sys.implementation.cache_tag  # e.g. "cpython-314"
    if not expected or not target_root.is_dir():
        return []

    # Group extension files by (parent_dir, module_name) so we can ask
    # "is at least one .so under this base loadable by the current
    # interpreter?" If yes, the base is satisfied; if no, every .so
    # under it is stale.
    #
    # Skip transient build-tool output trees (``build/``, ``dist/``,
    # ``.tox/``, ``.eggs/``, ``*.egg-info/``). Stale artifacts there are
    # not what the runner imports — they're intermediate copies left by
    # ``setup.py build_ext``. Without this, a target that has ever been
    # built for any interpreter would flag forever even after a correct
    # in-place build lands the right .so under the package dir.
    skip_segments = {"build", "dist", ".tox", ".eggs", "__pycache__"}
    bases: dict[tuple[Path, str], list[Path]] = {}
    for so in target_root.rglob("*.so"):
        rel_parts = so.relative_to(target_root).parts[:-1]
        if any(seg in skip_segments or seg.endswith(".egg-info") for seg in rel_parts):
            continue
        parts = so.name.split(".")
        if len(parts) < 3:
            continue  # libfoo.so — not an ABI-tagged extension
        suffix = parts[-2]
        if not _PY_EXT_ABI_RE.match(suffix):
            continue  # abi3, unrelated .so, etc.
        module_name = parts[0]
        bases.setdefault((so.parent, module_name), []).append(so)

    stale: list[Path] = []
    for files in bases.values():
        if any(_PY_EXT_ABI_RE.match(f.name.split(".")[-2]).group(1) == expected
               for f in files):
            continue
        stale.extend(files)
    return sorted(stale)


def supported_extension_help() -> str:
    """Human-readable summary used by probe's unsupported-extension error."""
    compiled = sorted(all_harness_exts(compiled=True))
    interpreted = sorted(all_harness_exts(compiled=False))
    return (
        f"compiled:   {' '.join(compiled)}\n"
        f"interpreted: {' '.join(interpreted)}"
    )


# ─── CLI ───────────────────────────────────────────────────────────


def _shell_quote(s: str) -> str:
    """Minimal POSIX shell single-quote escape."""
    if s == "":
        return "''"
    if all(c.isalnum() or c in "@%+=:,./-_" for c in s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _cmd_exts(args: argparse.Namespace) -> int:
    kind = args.kind
    if kind == "source":
        exts = sorted(all_source_exts())
    elif kind == "harness":
        exts = sorted(all_harness_exts())
    elif kind == "harness-compiled":
        exts = sorted(all_harness_exts(compiled=True))
    elif kind == "harness-interpreted":
        exts = sorted(all_harness_exts(compiled=False))
    else:
        print(f"unknown --kind: {kind}", file=sys.stderr)
        return 2
    for e in exts:
        # Drop the leading dot so callers can splice into
        # `find -iname '*.{e}'` style commands cleanly.
        print(e.lstrip("."))
    return 0


def _cmd_probe_dispatch(args: argparse.Namespace) -> int:
    info = probe_dispatch(args.ext)
    if not info:
        print(f"unsupported harness extension: {args.ext}", file=sys.stderr)
        print(supported_extension_help(), file=sys.stderr)
        return 2
    print(json.dumps(info))
    return 0


def _cmd_runner_block(args: argparse.Namespace) -> int:
    table = runner_table()
    block = table.get(args.build_system)
    if not block:
        return 1
    print(json.dumps(block, indent=2 if args.pretty else None))
    return 0


def _cmd_bootstrap_cmds(args: argparse.Namespace) -> int:
    target_root = Path(args.target_root).expanduser().resolve()
    cmds = bootstrap_for_target(target_root, args.build_system)
    if args.format == "json":
        print(json.dumps(cmds))
    else:
        for cmd in cmds:
            print(" ".join(_shell_quote(p) for p in cmd))
    return 0


def _cmd_bootstrap_plan(args: argparse.Namespace) -> int:
    target_root = Path(args.target_root).expanduser().resolve()
    plan = bootstrap_plan_for_target(target_root, args.build_system)
    print(json.dumps(plan))
    return 0


def _cmd_bootstrap_target(args: argparse.Namespace) -> int:
    target_root = Path(args.target_root).expanduser().resolve()
    plan = bootstrap_plan_for_target(target_root, args.build_system)
    language = plan.get("language") or args.build_system
    backends = " ".join(plan.get("fuzz_backends") or [])
    if backends:
        print(f"[setup-target] bootstrap: fuzz backends for {language}: {backends}")
    else:
        print(
            f"[setup-target] bootstrap: fuzz backends for {language}: "
            "(none registered - no maintained toolchain)"
        )
    commands = plan.get("cmds") or []
    if not commands:
        print(
            f"[setup-target] bootstrap: skipped ({language} has no bootstrap "
            f"commands, or required manifest is absent in {target_root})"
        )
        return 0
    print(
        f"[setup-target] bootstrap: running {len(commands)} {language} "
        f"release-mode command(s) in {target_root}"
    )
    returncode = execute_bootstrap_plan(
        target_root,
        plan,
        Path(args.log_file),
        Path(args.recipe_file),
    )
    if returncode == 0:
        print(
            f"[setup-target] bootstrap: completed (log: {args.log_file}, "
            f"recipe: {args.recipe_file})"
        )
    return returncode


def _cmd_fuzz_backends(args: argparse.Namespace) -> int:
    backends = fuzz_backends_for_build_system(args.build_system)
    print(" ".join(backends))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    rows: list[tuple[str, str, str, str]] = []
    for lang in LANGUAGES:
        rows.append((
            lang.name,
            " ".join(lang.source_exts) or "-",
            " ".join(lang.harness_exts) or "-",
            " ".join(lang.build_systems) or "-",
        ))
    widths = [max(len(r[i]) for r in rows + [("LANGUAGE", "SOURCE", "HARNESS", "BUILD_SYSTEMS")]) for i in range(4)]
    header = ("LANGUAGE", "SOURCE", "HARNESS", "BUILD_SYSTEMS")
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(header)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)))
    return 0


def _cmd_stale_python_extensions(args: argparse.Namespace) -> int:
    target_root = Path(args.target_root).expanduser().resolve()
    stale = stale_python_extensions(target_root)
    for path in stale:
        print(path)
    return 0


def _cmd_supports_build_system(args: argparse.Namespace) -> int:
    lang = for_build_system(args.build_system)
    print(lang.name if lang else "")
    return 0 if lang else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="lib/languages.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("exts", help="emit source or harness extensions, one per line")
    p.add_argument("--kind", choices=("source", "harness", "harness-compiled", "harness-interpreted"),
                   required=True)
    p.set_defaults(func=_cmd_exts)

    p = sub.add_parser("probe-dispatch", help="describe how probe should handle a harness extension")
    p.add_argument("ext", help="harness extension, with or without leading dot (e.g. py, .rs)")
    p.set_defaults(func=_cmd_probe_dispatch)

    p = sub.add_parser("runner-block", help="emit the target.toml [runner] block for a build_system")
    p.add_argument("build_system")
    p.add_argument("--pretty", action="store_true")
    p.set_defaults(func=_cmd_runner_block)

    p = sub.add_parser("bootstrap-cmds", help="emit bootstrap commands for a build_system + target_root")
    p.add_argument("build_system")
    p.add_argument("target_root")
    p.add_argument("--format", choices=("shell", "json"), default="shell")
    p.set_defaults(func=_cmd_bootstrap_cmds)

    p = sub.add_parser("bootstrap-plan",
                       help="emit full bootstrap plan (cmds + alternatives + env + fuzz_backends) as JSON")
    p.add_argument("build_system")
    p.add_argument("target_root")
    p.set_defaults(func=_cmd_bootstrap_plan)

    p = sub.add_parser("bootstrap-target",
                       help="plan and execute a target bootstrap without shell expansion")
    p.add_argument("build_system")
    p.add_argument("target_root")
    p.add_argument("log_file")
    p.add_argument("recipe_file")
    p.set_defaults(func=_cmd_bootstrap_target)

    p = sub.add_parser("fuzz-backends",
                       help="emit maintained fuzz/sanitizer backends for a build_system, space-separated")
    p.add_argument("build_system")
    p.set_defaults(func=_cmd_fuzz_backends)

    p = sub.add_parser("supports-build-system",
                       help="exit 0 and print language name if build_system is known, else exit 1")
    p.add_argument("build_system")
    p.set_defaults(func=_cmd_supports_build_system)

    p = sub.add_parser("stale-python-extensions",
                       help="list Python C-extension .so files in target_root whose ABI tag mismatches the active interpreter")
    p.add_argument("target_root")
    p.set_defaults(func=_cmd_stale_python_extensions)

    p = sub.add_parser("list", help="print the registry as a table")
    p.set_defaults(func=_cmd_list)

    ns = parser.parse_args(argv)
    return int(ns.func(ns) or 0)


if __name__ == "__main__":
    sys.exit(main())
