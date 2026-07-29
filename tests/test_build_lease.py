#!/usr/bin/env python3
"""tests/test_build_lease.py — reader/writer lease over a target build tree.

The invariant under test: while any run is executing a build tree, nothing may
replace it, and the moment that run is gone (including by SIGKILL) the tree is
available again. Both halves matter — the first protects recorded evidence from
being measured against a binary that has since changed, and the second keeps a
crashed run from wedging every later build.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import build_lease  # noqa: E402
import build_materialize  # noqa: E402
import target_config  # noqa: E402

_HOLDER = """
import sys, time
from pathlib import Path
sys.path.insert(0, {lib!r})
import build_lease
root, name, ready, stop = sys.argv[1:5]
with build_lease.shared(root, name) as held:
    assert held, "holder could not take the shared lease"
    Path(ready).write_text("up\\n")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not Path(stop).exists():
        time.sleep(0.02)
"""


class BuildLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="lease-"))
        self.target = self.tmp / "target"
        (self.target / "build-asan").mkdir(parents=True)
        self.holders: list[subprocess.Popen] = []

    def tearDown(self) -> None:
        for holder in self.holders:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=10)
            for stream in (holder.stdout, holder.stderr):
                if stream is not None:
                    stream.close()
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def _start_holder(self, name: str = "build-asan") -> subprocess.Popen:
        ready = self.tmp / f"ready-{len(self.holders)}"
        stop = self.tmp / f"stop-{len(self.holders)}"
        holder = subprocess.Popen(
            [sys.executable, "-c", _HOLDER.format(lib=str(ROOT / "lib")),
             str(self.target), name, str(ready), str(stop)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.holders.append(holder)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not ready.exists():
            if holder.poll() is not None:
                self.fail(f"holder exited early: {holder.communicate()[1].decode()}")
            time.sleep(0.02)
        self.assertTrue(ready.exists(), "holder never acquired the shared lease")
        return holder

    def test_shared_leases_coexist(self) -> None:
        """Concurrent runs on identical inputs share one build, so they must
        both be able to hold it."""
        self._start_holder()
        self._start_holder()
        with build_lease.shared(self.target, "build-asan") as held:
            self.assertTrue(held)

    def test_consumers_active_sees_another_process(self) -> None:
        self.assertFalse(build_lease.consumers_active(self.target, "build-asan"))
        self._start_holder()
        self.assertTrue(build_lease.consumers_active(self.target, "build-asan"))

    def test_consumers_active_ignores_our_own_hold(self) -> None:
        """A run converges its build and then takes its lease; its own hold must
        not read as a foreign consumer or it could never build again."""
        with build_lease.shared(self.target, "build-asan"):
            self.assertFalse(build_lease.consumers_active(self.target, "build-asan"))

    def test_separate_trees_are_independent(self) -> None:
        self._start_holder("build-asan")
        self.assertFalse(
            build_lease.consumers_active(self.target, "build-asan+cfg-widened-abc")
        )

    def test_exclusive_nests_within_this_process(self) -> None:
        """flock is per file description, so a re-entrant acquisition would
        block against itself. Nesting is legitimate and must not deadlock."""
        with build_lease.exclusive(self.target, "build-asan") as outer:
            self.assertTrue(outer)
            with build_lease.exclusive(self.target, "build-asan") as inner:
                self.assertTrue(inner)

    def test_lease_survives_holder_kill(self) -> None:
        """A SIGKILLed run must not wedge the tree: the kernel drops the lock,
        and no marker file is left behind to reap."""
        holder = self._start_holder()
        self.assertTrue(build_lease.consumers_active(self.target, "build-asan"))
        holder.kill()
        holder.wait(timeout=10)
        self.assertFalse(build_lease.consumers_active(self.target, "build-asan"))
        with build_lease.exclusive(self.target, "build-asan") as held:
            self.assertTrue(held)

    def test_pending_markers_are_per_writer(self) -> None:
        """One shared marker would have writers overwriting each other's
        announcement and clearing each other's on the way out."""
        lock = build_lease.lease_path(self.target, "build-asan")
        lock.parent.mkdir(parents=True, exist_ok=True)
        peer = lock.with_name(f"{lock.name}.pending.999999")
        peer.write_text("999999\n")  # a pid that is not running
        build_lease._announce_pending(lock)
        markers = sorted(lock.parent.glob(f"{lock.name}.pending.*"))
        self.assertEqual(2, len(markers), markers)
        # Ours must not be mistaken for a foreign writer, and the dead peer's is
        # reaped rather than believed.
        self.assertFalse(build_lease._pending_writer_alive(lock))
        build_lease._clear_pending(lock)
        self.assertFalse(build_lease._pending_path(lock).exists())

    def test_a_live_peer_announcement_defers_a_reader(self) -> None:
        """A whole-run shared lease taken ahead of a queued builder would trap
        that builder for the full timeout."""
        lock = build_lease.lease_path(self.target, "build-asan")
        lock.parent.mkdir(parents=True, exist_ok=True)
        holder = self._start_holder()  # a live process to own the marker
        lock.with_name(f"{lock.name}.pending.{holder.pid}").write_text(f"{holder.pid}\n")
        self.assertTrue(build_lease._pending_writer_alive(lock))
        holder.kill()
        holder.wait(timeout=10)
        self.assertFalse(build_lease._pending_writer_alive(lock))

    def test_dead_writer_marker_does_not_defer_forever(self) -> None:
        """A rebuild killed mid-announcement leaves a pending marker. Believing
        it would stall every later consumer."""
        lock = build_lease.lease_path(self.target, "build-asan")
        lock.parent.mkdir(parents=True, exist_ok=True)
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait(timeout=10)
        lock.with_name(lock.name + ".pending").write_text(f"{dead.pid}\n")
        self.assertFalse(build_lease.writer_pending(self.target, "build-asan"))
        started = time.monotonic()
        with build_lease.shared(self.target, "build-asan") as held:
            self.assertTrue(held)
        self.assertLess(time.monotonic() - started, 5)

    def test_materialize_refuses_to_replace_a_held_tree(self) -> None:
        """The whole point: a rebuild must not run while a live run is executing
        that tree, and must leave the existing build exactly as it was."""
        (self.target / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
        (self.target / "main.c").write_text("int main(void){return 0;}\n")
        recipe = self.target / ".audit" / "build.sh"
        recipe.parent.mkdir(parents=True, exist_ok=True)
        recipe.write_text("#!/bin/sh\necho rebuilt > \"$2/marker\"\n")
        recipe.chmod(0o755)
        witness = self.target / "build-asan" / "witness"
        witness.write_text("original\n")

        self._start_holder()
        result = build_materialize.materialize(
            self.target, "asan", recipe, recipe, lambda tree: True,
        )
        self.assertEqual("held", result.status)
        self.assertIn("build-asan", result.reason)
        self.assertEqual("original\n", witness.read_text())
        self.assertFalse((self.target / "build-asan" / "marker").exists())

    def test_materialize_proceeds_when_no_run_holds_the_tree(self) -> None:
        """The refusal must be specific to a held tree — with nothing holding
        it, the same build runs. Otherwise the guard is a false positive that
        silently stops every rebuild."""
        (self.target / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
        (self.target / "main.c").write_text("int main(void){return 0;}\n")
        recipe = self.target / ".audit" / "build.sh"
        recipe.parent.mkdir(parents=True, exist_ok=True)
        recipe.write_text("#!/bin/sh\nmkdir -p \"$2\"\necho rebuilt > \"$2/marker\"\n")
        recipe.chmod(0o755)
        result = build_materialize.materialize(
            self.target, "asan", recipe, recipe, lambda tree: True,
        )
        self.assertEqual("built", result.status)
        self.assertEqual("rebuilt\n", (self.target / "build-asan" / "marker").read_text())
        self.assertEqual(
            "fresh", target_config.build_freshness(self.target, "asan", recipe_path=recipe)
        )

    def test_a_stamped_tree_that_stops_verifying_is_rebuilt(self) -> None:
        """A content stamp cannot see the host. When an already-fresh tree stops
        producing a usable artifact — a shared dependency removed after the
        build — trusting the stamp would leave every later run unable to
        execute, so the build has to run again."""
        (self.target / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
        (self.target / "main.c").write_text("int main(void){return 0;}\n")
        recipe = self.target / ".audit" / "build.sh"
        recipe.parent.mkdir(parents=True, exist_ok=True)
        recipe.write_text(
            "#!/bin/sh\nmkdir -p \"$2\"\ncat \"$2/../.audit/generation\" > \"$2/marker\"\n"
        )
        recipe.chmod(0o755)
        (self.target / ".audit" / "generation").write_text("first\n")
        first = build_materialize.materialize(
            self.target, "asan", recipe, recipe, lambda tree: True,
        )
        self.assertEqual("built", first.status)

        # Same source, same recipe: the stamp still says fresh.
        self.assertEqual(
            "fresh", target_config.build_freshness(self.target, "asan", recipe_path=recipe)
        )
        (self.target / ".audit" / "generation").write_text("second\n")
        usable = iter([False, True])
        again = build_materialize.materialize(
            self.target, "asan", recipe, recipe, lambda tree: next(usable),
        )
        self.assertEqual("built", again.status)
        self.assertEqual("second\n", (self.target / "build-asan" / "marker").read_text())

    def test_a_rejected_stamped_tree_records_why_it_was_rebuilt(self) -> None:
        """Discarding a stamped tree costs a full rebuild, and the rebuild's own
        output is the only other thing in this log. Without the reason an
        operator cannot tell a tree that stopped working from an ordinary stale
        one, and recipe repair reads the same tail."""
        (self.target / "main.c").write_text("int main(void){return 0;}\n")
        recipe = self.target / ".audit" / "build.sh"
        recipe.parent.mkdir(parents=True, exist_ok=True)
        recipe.write_text("#!/bin/sh\nmkdir -p \"$2\"\n:\n")
        recipe.chmod(0o755)
        self.assertEqual(
            "built",
            build_materialize.materialize(
                self.target, "asan", recipe, recipe, lambda tree: True,
            ).status,
        )

        def reject(tree):
            raise RuntimeError("libwidget.so.3 vanished after the build")

        usable = iter([reject, lambda tree: True])
        again = build_materialize.materialize(
            self.target, "asan", recipe, recipe, lambda tree: next(usable)(tree),
        )
        self.assertEqual("built", again.status)
        log = (self.target / ".audit" / "build-materialize-asan.log").read_text()
        self.assertIn("stamped build rejected, rebuilding", log)
        self.assertIn("libwidget.so.3 vanished after the build", log)

    def test_a_stamped_tree_that_still_verifies_is_left_alone(self) -> None:
        """The rebuild must be specific to a tree that stopped verifying: a
        healthy fresh build is still returned untouched, or every run pays for
        a rebuild it does not need."""
        (self.target / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
        (self.target / "main.c").write_text("int main(void){return 0;}\n")
        recipe = self.target / ".audit" / "build.sh"
        recipe.parent.mkdir(parents=True, exist_ok=True)
        recipe.write_text("#!/bin/sh\nmkdir -p \"$2\"\ndate +%s%N >> \"$2/builds\"\n")
        recipe.chmod(0o755)
        self.assertEqual(
            "built",
            build_materialize.materialize(
                self.target, "asan", recipe, recipe, lambda tree: True,
            ).status,
        )
        builds = (self.target / "build-asan" / "builds").read_text()
        result = build_materialize.materialize(
            self.target, "asan", recipe, recipe, lambda tree: True,
        )
        self.assertEqual("fresh", result.status)
        self.assertEqual(builds, (self.target / "build-asan" / "builds").read_text())


_PINNER = """
import sys, time
from pathlib import Path
sys.path.insert(0, {lib!r})
import build_lease
root, signature, ready, stop = sys.argv[1:5]
build_lease.claim_source_pin(root, signature)
Path(ready).write_text("up\\n")
deadline = time.monotonic() + 60
while time.monotonic() < deadline and not Path(stop).exists():
    time.sleep(0.02)
"""


class SourcePinTests(unittest.TestCase):
    """A checkout-level pin catches what a build lease cannot: two runs reading
    one working tree at different source states, whatever their builds are."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pin-"))
        self.target = self.tmp / "target"
        self.target.mkdir(parents=True)
        self.holders: list[subprocess.Popen] = []

    def tearDown(self) -> None:
        for holder in self.holders:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=10)
            for stream in (holder.stdout, holder.stderr):
                if stream is not None:
                    stream.close()
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def _start_pinner(self, signature: str) -> subprocess.Popen:
        ready = self.tmp / f"ready-{len(self.holders)}"
        holder = subprocess.Popen(
            [sys.executable, "-c", _PINNER.format(lib=str(ROOT / "lib")),
             str(self.target), signature, str(ready), str(self.tmp / "stop")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.holders.append(holder)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not ready.exists():
            if holder.poll() is not None:
                self.fail(f"pinner exited early: {holder.communicate()[1].decode()}")
            time.sleep(0.02)
        self.assertTrue(ready.exists(), "pinner never wrote its pin")
        return holder

    def test_no_conflict_when_peers_agree(self) -> None:
        self._start_pinner("sig-a")
        self.assertEqual([], build_lease.claim_source_pin(self.target, "sig-a"))

    def test_conflict_when_a_peer_pinned_another_state(self) -> None:
        self._start_pinner("sig-a")
        self.assertEqual(1, len(build_lease.claim_source_pin(self.target, "sig-b")))

    def test_our_own_pin_is_never_a_conflict(self) -> None:
        self.assertEqual([], build_lease.claim_source_pin(self.target, "sig-mine"))
        self.assertEqual([], build_lease.claim_source_pin(self.target, "sig-mine"))

    def test_a_dead_peers_pin_is_reaped_not_believed(self) -> None:
        holder = self._start_pinner("sig-a")
        self.assertTrue(build_lease.claim_source_pin(self.target, "sig-b"))
        holder.kill()
        holder.wait(timeout=10)
        self.assertEqual([], build_lease.claim_source_pin(self.target, "sig-b"))

    def test_an_unknown_signature_pins_nothing(self) -> None:
        """A target the VCS cannot answer for must not pin, or every later run
        would read it as a conflict."""
        self.assertEqual([], build_lease.claim_source_pin(self.target, ""))
        self.assertEqual([], build_lease.claim_source_pin(self.target, "sig-a"))

    def test_a_rejected_claim_publishes_nothing(self) -> None:
        """A run that was refused must not leave a pin behind, or it would
        conflict with the run that legitimately holds the checkout."""
        self._start_pinner("sig-a")
        self.assertTrue(build_lease.claim_source_pin(self.target, "sig-b"))
        pins = list((self.target / ".audit" / "source-pins").glob("*.pin"))
        self.assertEqual(1, len(pins), pins)

    def test_a_concurrent_scan_cannot_reap_a_pin_being_published(self) -> None:
        """Publishing under the registry lock is what stops a scanner from
        seeing a pin before its owner locked it and deleting it as dead."""
        for _ in range(20):
            self.assertEqual([], build_lease.claim_source_pin(self.target, "sig-x"))
        self._start_pinner("sig-x")
        self.assertEqual([], build_lease.claim_source_pin(self.target, "sig-x"))
        self.assertTrue(
            list((self.target / ".audit" / "source-pins").glob("*.pin")),
            "the live pin must survive concurrent scanning",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
