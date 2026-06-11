"""CVSS v4.0 scoring — faithful port of the official FIRST
reference implementation (github.com/FIRSTdotorg/cvss-v4-calculator,
BSD-2-Clause, Copyright FIRST, Red Hat, and contributors).

The harness scores severity with CVSS v4.0 and nothing else. This module
holds the standard's machinery only — no harness policy, no field
derivation. Callers hand it the eleven base metrics, plus optional Threat
and Environmental metrics, and get back the official score:

    >>> import cvss4
    >>> m = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    ...      "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N"}
    >>> cvss4.score(m)
    9.3
    >>> cvss4.vector(m)
    'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
    >>> cvss4.nomenclature({**m, "E": "P", "CR": "M", "IR": "M", "AR": "M"})
    'CVSS-BTE'
    >>> cvss4.rating(9.3)
    'Critical'

Scoring follows the v4.0 specification (§8.2): the eleven metrics select a
six-digit MacroVector; the published lookup table gives that equivalence
class's score; the final score interpolates toward the next-lower
MacroVector by the vector's severity distance from its class's highest
vectors. Missing or explicit Not Defined (X) Threat/Environmental metrics
take the specification defaults used by the reference implementation
(E:A, CR/IR/AR:H, modified metrics inherit the corresponding Base value).

The three data tables (_LOOKUP, _MAX_COMPOSED, _MAX_SEVERITY) are vendored
verbatim from the reference implementation; tests/test_cvss4_py.py validates
the port against reference vectors. Do not hand-edit the tables.
"""

from __future__ import annotations

import math

#: The eleven CVSS-B metrics in canonical vector order, with their legal
#: values. Also the validation contract for callers.
BASE_METRICS: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
}

THREAT_METRICS: dict[str, tuple[str, ...]] = {
    "E": ("X", "A", "P", "U"),
}

ENVIRONMENTAL_METRICS: dict[str, tuple[str, ...]] = {
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "N", "L", "H"),
    "MVI": ("X", "N", "L", "H"),
    "MVA": ("X", "N", "L", "H"),
    "MSC": ("X", "N", "L", "H"),
    "MSI": ("X", "N", "L", "H", "S"),
    "MSA": ("X", "N", "L", "H", "S"),
}

OPTIONAL_METRICS: dict[str, tuple[str, ...]] = {
    **THREAT_METRICS,
    **ENVIRONMENTAL_METRICS,
}

OPTIONAL_METRIC_ORDER = tuple(OPTIONAL_METRICS)

_MODIFIED_FOR = {
    "AV": "MAV", "AC": "MAC", "AT": "MAT", "PR": "MPR", "UI": "MUI",
    "VC": "MVC", "VI": "MVI", "VA": "MVA",
    "SC": "MSC", "SI": "MSI", "SA": "MSA",
}

# Worst-case defaults the reference implementation substitutes for
# not-defined threat/environmental metrics when scoring CVSS-B.
_DEFAULTS = {"E": "A", "CR": "H", "IR": "H", "AR": "H"}

# Metric-level indices used for severity distances (cvss_score.js).
_LEVELS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

# max_composed.js — highest-severity vectors per equivalence class.
_MAX_COMPOSED: dict[str, dict] = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        0: ["AC:L/AT:N/"],
        1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        0: {0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},
        1: {0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            1: ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},
        2: {1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        0: ["E:A/"],
        1: ["E:P/"],
        2: ["E:U/"],
    },
}

# max_severity.js — max severity distances within each MacroVector (×0.1).
_MAX_SEVERITY: dict[str, dict] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

# cvss_lookup.js — MacroVector → score. Vendored verbatim; injected below.
_LOOKUP: dict[str, float] = {}  # populated at the bottom of this module


def _m(metrics: dict[str, str], name: str) -> str:
    """Effective value of `name`.

    Base metrics can be overridden by their Environmental "Modified" metric
    counterpart. Threat/environmental requirement metrics use the spec's
    worst-case default when omitted or explicitly Not Defined (X).
    """
    mod = _MODIFIED_FOR.get(name)
    if mod is not None:
        mv = metrics.get(mod)
        if mv and mv != "X":
            return mv
    v = metrics.get(name)
    if name in _DEFAULTS and (v is None or v == "X"):
        return _DEFAULTS[name]
    return v or ""


def validate(metrics: dict[str, str]) -> None:
    """Raise ValueError unless `metrics` carries legal CVSS v4.0 values.

    All eleven Base metrics are required. Threat and Environmental metrics
    are optional; when supplied, they must use the v4.0 value set.
    """
    for name, legal in BASE_METRICS.items():
        v = metrics.get(name)
        if v not in legal:
            raise ValueError(f"CVSS-B metric {name}={v!r} not in {legal}")
    known = set(BASE_METRICS) | set(OPTIONAL_METRICS)
    for name, v in metrics.items():
        if name not in known:
            raise ValueError(f"unknown CVSS v4.0 metric {name!r}")
        if name in OPTIONAL_METRICS and v not in OPTIONAL_METRICS[name]:
            raise ValueError(f"CVSS v4.0 metric {name}={v!r} not in {OPTIONAL_METRICS[name]}")


def vector(metrics: dict[str, str]) -> str:
    """Canonical CVSS:4.0 vector string.

    Base metrics are always emitted. Optional Threat/Environmental metrics are
    emitted in spec order only when supplied and not Not Defined (X).
    """
    validate(metrics)
    parts = [f"{k}:{metrics[k]}" for k in BASE_METRICS]
    for k in OPTIONAL_METRIC_ORDER:
        v = metrics.get(k)
        if v and v != "X":
            parts.append(f"{k}:{v}")
    return "CVSS:4.0/" + "/".join(parts)


def base_metrics(metrics: dict[str, str]) -> dict[str, str]:
    """Return only the eleven Base metrics, preserving canonical order."""
    validate(metrics)
    return {k: metrics[k] for k in BASE_METRICS}


def nomenclature(metrics: dict[str, str]) -> str:
    """CVSS score nomenclature for the metric groups used."""
    validate(metrics)
    has_t = any(metrics.get(k) not in (None, "", "X") for k in THREAT_METRICS)
    has_e = any(metrics.get(k) not in (None, "", "X") for k in ENVIRONMENTAL_METRICS)
    if has_t and has_e:
        return "CVSS-BTE"
    if has_t:
        return "CVSS-BT"
    if has_e:
        return "CVSS-BE"
    return "CVSS-B"


def rating(score_value: float) -> str:
    """Official qualitative rating bands (spec §6)."""
    if score_value <= 0:
        return "None"
    if score_value < 4.0:
        return "Low"
    if score_value < 7.0:
        return "Medium"
    if score_value < 9.0:
        return "High"
    return "Critical"


def macro_vector(metrics: dict[str, str]) -> str:
    """Six-digit MacroVector (EQ1..EQ6) per spec §8.2 / macroVector()."""
    av, pr, ui = _m(metrics, "AV"), _m(metrics, "PR"), _m(metrics, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2

    eq2 = 0 if (_m(metrics, "AC") == "L" and _m(metrics, "AT") == "N") else 1

    vc, vi, va = _m(metrics, "VC"), _m(metrics, "VI"), _m(metrics, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    if _m(metrics, "SI") == "S" or _m(metrics, "SA") == "S":
        eq4 = 0
    elif _m(metrics, "SC") == "H" or _m(metrics, "SI") == "H" or _m(metrics, "SA") == "H":
        eq4 = 1
    else:
        eq4 = 2

    e = _m(metrics, "E")
    eq5 = {"A": 0, "P": 1, "U": 2}[e]

    cr, ir, ar = _m(metrics, "CR"), _m(metrics, "IR"), _m(metrics, "AR")
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = 0
    else:
        eq6 = 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _parse_max_vector(mv: str) -> dict[str, str]:
    return dict(part.split(":") for part in mv.strip("/").split("/"))


def score(metrics: dict[str, str]) -> float:
    """Official CVSS v4.0 score, one decimal. Port of cvss_score.js."""
    validate(metrics)

    # No impact on either system → 0.0 (shortcut in the reference impl).
    if all(_m(metrics, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    mv = macro_vector(metrics)
    value = _LOOKUP[mv]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in mv)

    # Next-lower MacroVector score per EQ (None when out of range).
    lower1 = _LOOKUP.get(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}")
    lower2 = _LOOKUP.get(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}")
    if eq3 == 0 and eq6 == 0:
        # Two lower paths (01 and 10) — the reference takes the higher score.
        cands = [s for s in (_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"),
                             _LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"))
                 if s is not None]
        lower36 = max(cands) if cands else None
    elif eq3 == 1 and eq6 == 0:
        lower36 = _LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    else:
        # (0,1) → (1,1); (1,1) → (2,1); (2,1) → off the table.
        lower36 = _LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    lower4 = _LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
    lower5 = _LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

    # Highest-severity vectors of this MacroVector, composed across EQs.
    eq36_maxes = _MAX_COMPOSED["eq3"][eq3][eq6]
    distances: dict[str, float] = {}
    for c1 in _MAX_COMPOSED["eq1"][eq1]:
        for c2 in _MAX_COMPOSED["eq2"][eq2]:
            for c36 in eq36_maxes:
                for c4 in _MAX_COMPOSED["eq4"][eq4]:
                    for c5 in _MAX_COMPOSED["eq5"][eq5]:
                        ref = _parse_max_vector(c1 + c2 + c36 + c4 + c5)
                        d = {k: _LEVELS[k][_m(metrics, k)] - _LEVELS[k][ref[k]]
                             for k in _LEVELS}
                        if all(v >= 0 for v in d.values()):
                            distances = d
                            break
                    if distances:
                        break
                if distances:
                    break
            if distances:
                break
        if distances:
            break

    dist1 = distances["AV"] + distances["PR"] + distances["UI"]
    dist2 = distances["AC"] + distances["AT"]
    dist36 = (distances["VC"] + distances["VI"] + distances["VA"]
              + distances["CR"] + distances["IR"] + distances["AR"])
    dist4 = distances["SC"] + distances["SI"] + distances["SA"]

    step = 0.1
    msev1 = _MAX_SEVERITY["eq1"][eq1] * step
    msev2 = _MAX_SEVERITY["eq2"][eq2] * step
    msev36 = _MAX_SEVERITY["eq3eq6"][eq3][eq6] * step
    msev4 = _MAX_SEVERITY["eq4"][eq4] * step

    n_lower = 0
    normalized = 0.0
    for lower, dist, msev in (
        (lower1, dist1, msev1),
        (lower2, dist2, msev2),
        (lower36, dist36, msev36),
        (lower4, dist4, msev4),
        (lower5, 0.0, 1.0),   # eq5 proportion is always 0 in the reference
    ):
        if lower is not None:
            n_lower += 1
            normalized += (value - lower) * (dist / msev)

    if n_lower:
        value -= normalized / n_lower
    value = min(10.0, max(0.0, value))
    # JS Math.round (half away from zero for positives), one decimal.
    return math.floor(value * 10 + 0.5) / 10


# ── Vendored MacroVector score table (cvss_lookup.js, 270 entries) ────────
_LOOKUP.update({
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
    "000100": 10.0, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8.0, "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5.0,
    "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9.0,
    "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3, "011010": 9.2,
    "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
    "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4, "011201": 7.0, "011210": 7.1,
    "011211": 5.2, "011220": 5.0, "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7.0, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5, "110001": 9.0, "110010": 8.8,
    "110011": 7.6, "110020": 7.6, "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
    "110211": 5.9, "110220": 5.2, "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7,
    "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3.0,
    "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0, "200220": 4.0, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3, "210101": 5.5, "210110": 5.9,
    "210111": 4.0, "210120": 4.1, "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8,
    "211011": 4.5, "211020": 4.0, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7,
    "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0, "212211": 0.3, "212221": 0.1,
})
