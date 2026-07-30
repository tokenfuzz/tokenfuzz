#!/usr/bin/env python3
"""Target overlay loading and effective-slug regressions."""

from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import target_profile


class TargetProfileTests(unittest.TestCase):
    def overlay_root(self) -> Path:
        """A harness root carrying the committed overlays and no targets."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / "lib").mkdir()
        shutil.copytree(
            ROOT / "lib" / "target-overlays", root / "lib" / "target-overlays"
        )
        return root

    def test_committed_chromium_profile_selects_nested_source(self) -> None:
        profile = target_profile.load(ROOT, "chromium")
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile.checkout, "gclient")
        self.assertEqual(profile.build_recipe, "chromium-build.sh")
        self.assertTrue(profile.browser_bin)
        self.assertTrue(profile.browser)
        self.assertEqual(
            target_profile.load(ROOT, "chrome"),
            target_profile.load(ROOT, "chromium"),
        )
        self.assertIsNone(target_profile.load(ROOT, "Chromium"))
        workspace, nested_profile = target_profile.resolve(
            ROOT, "chromium/src"
        )
        self.assertEqual(workspace, "chromium")
        self.assertEqual(nested_profile, profile)
        self.assertEqual(
            target_profile.resolve(ROOT, "samples/sampleproj"),
            ("samples/sampleproj", None),
        )

    def seed_config(self, root: Path, slug: str) -> None:
        config = root / "output" / slug / "target.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(f'target = "{slug}"\n', encoding="utf-8")

    def test_slug_yields_to_an_ordinary_target_of_the_same_name(self) -> None:
        root = self.overlay_root()
        # Nothing set up yet: resolve the way setup will create it.
        self.assertEqual(
            target_profile.effective_slug(root, "chromium"), "chromium/src"
        )
        self.assertEqual(
            target_profile.effective_slug(root, "chromium/src"), "chromium/src"
        )
        self.assertEqual(
            target_profile.effective_slug(root, "sampleproj"), "sampleproj"
        )
        # A target already registered under the bare name keeps its identity.
        self.seed_config(root, "chromium")
        self.assertEqual(
            target_profile.effective_slug(root, "chromium"), "chromium"
        )
        self.assertEqual(
            target_profile.resolve(root, "chromium"), ("chromium", None)
        )
        self.assertEqual(target_profile.effective_slug(root, "chrome"), "chrome/src")
        # An explicit bare target remains unambiguous even if both exist.
        self.seed_config(root, "chromium/src")
        self.assertEqual(
            target_profile.effective_slug(root, "chromium"), "chromium"
        )

    def test_slug_uses_the_selected_output_root_as_its_identity_anchor(self) -> None:
        root = self.overlay_root()
        alternate = root / "alternate-output"
        config = alternate / "chromium" / "target.toml"
        config.parent.mkdir(parents=True)
        config.write_text('target = "chromium"\n', encoding="utf-8")

        self.assertEqual(
            target_profile.effective_slug(
                root, "chromium", output_root=alternate
            ),
            "chromium",
        )

    def test_invalid_source_subdir_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            overlays = root / "lib" / "target-overlays"
            overlays.mkdir(parents=True)
            (overlays / "bad.toml").write_text(
                'source_subdir = "../escape"\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "stay below"):
                target_profile.load(root, "bad")
            (overlays / "bad.toml").write_text(
                'source_subdir = "src"\n'
                'browser_bin_linux = "../escape"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "build directory"):
                target_profile.load(root, "bad")


if __name__ == "__main__":
    unittest.main()
