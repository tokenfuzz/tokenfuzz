#!/usr/bin/env python3
"""Validate lib/cvss4.py against the official FIRST v4.0 reference calculator.

The anchor scores below were produced by the FIRST reference implementation
(github.com/FIRSTdotorg/cvss-v4-calculator) — the normative definition of
CVSS 4.0. They span every rating band, the no-impact 0.0 shortcut, the 10.0
maximum, and two of the floating-point knife-edge vectors where Red Hat's
re-derivation diverges from FIRST by 0.1 (we follow FIRST, the standard).

Regenerate with the reference calculator if the vendored tables are ever
updated; do not hand-tune expected values to make the port pass.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import cvss4  # noqa: E402

# (vector, FIRST-reference score)
ANCHORS = [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N", 8.8),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 6.9),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", 8.7),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5),
    ("CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 1.0),
    ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:N/VI:H/VA:L/SC:N/SI:N/SA:L", 5.6),
    ("CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H", 4.9),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 6.9),
]

# (score, expected rating band) — spec §6 boundaries.
RATINGS = [
    (0.0, "None"), (0.1, "Low"), (3.9, "Low"), (4.0, "Medium"),
    (6.9, "Medium"), (7.0, "High"), (8.9, "High"), (9.0, "Critical"),
    (10.0, "Critical"),
]


def _base(vec: str) -> dict:
    parts = dict(p.split(":") for p in vec.split("/")[1:])
    return {k: parts[k] for k in cvss4.BASE_METRICS}


def main() -> int:
    failures = []

    for vec, expected in ANCHORS:
        base = _base(vec)
        got = cvss4.score(base)
        if abs(got - expected) > 1e-9:
            failures.append(f"score {vec}: expected {expected}, got {got}")
        # vector() must round-trip the canonical string.
        if cvss4.vector(base) != vec:
            failures.append(f"vector {vec}: round-trip got {cvss4.vector(base)}")

    for sc, band in RATINGS:
        got = cvss4.rating(sc)
        if got != band:
            failures.append(f"rating {sc}: expected {band}, got {got}")

    # Validation rejects illegal / missing metrics.
    for bad in ({}, {**_base(ANCHORS[0][0]), "AV": "X"},
                {**_base(ANCHORS[0][0]), "UI": "R"},  # UI:R is a v3.1 value
                {**_base(ANCHORS[0][0]), "ZZ": "H"}):
        try:
            cvss4.score(bad)
        except ValueError:
            pass
        else:
            failures.append(f"validate: accepted illegal metrics {bad}")

    # Threat and Environmental metrics are first-class CVSS v4.0 inputs.
    base = _base(ANCHORS[1][0])
    bte = {**base, "E": "P", "CR": "H", "IR": "H", "AR": "H"}
    if cvss4.nomenclature(bte) != "CVSS-BTE":
        failures.append(f"nomenclature: expected CVSS-BTE, got {cvss4.nomenclature(bte)}")
    if cvss4.vector(bte) != ANCHORS[1][0] + "/E:P/CR:H/IR:H/AR:H":
        failures.append(f"vector: optional metric order wrong: {cvss4.vector(bte)}")
    if cvss4.score(bte) != 8.9:
        failures.append(f"score: BTE network UAF expected 8.9, got {cvss4.score(bte)}")

    # X / omitted optionals are Not Defined and score like the Base vector.
    defaulted = {**base, "E": "X", "CR": "X", "IR": "X", "AR": "X"}
    if cvss4.vector(defaulted) != ANCHORS[1][0]:
        failures.append(f"vector: X optionals should be omitted: {cvss4.vector(defaulted)}")
    if cvss4.score(defaulted) != cvss4.score(base):
        failures.append("score: X optionals did not default to Base score")

    bt = {**base, "E": "P"}
    be = {**base, "MAT": "P", "MVA": "L"}
    if cvss4.nomenclature(bt) != "CVSS-BT":
        failures.append(f"nomenclature: expected CVSS-BT, got {cvss4.nomenclature(bt)}")
    if cvss4.nomenclature(be) != "CVSS-BE":
        failures.append(f"nomenclature: expected CVSS-BE, got {cvss4.nomenclature(be)}")
    if set(cvss4.base_metrics(bte)) != set(cvss4.BASE_METRICS):
        failures.append("base_metrics: optional metrics leaked into Base view")

    # Determinism: same input twice → identical score.
    if cvss4.score(_base(ANCHORS[1][0])) != cvss4.score(_base(ANCHORS[1][0])):
        failures.append("score is not deterministic")

    if failures:
        print(f"FAIL ({len(failures)})")
        for f in failures:
            print("  -", f)
        return 1
    print(f"ok — {len(ANCHORS)} anchors, {len(RATINGS)} rating bands, "
          f"validation + determinism")
    return 0


if __name__ == "__main__":
    sys.exit(main())
