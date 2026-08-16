#!/usr/bin/env python3
"""The strategy registry: which methods exist, and how a report names one.

Four places used to answer this independently — the audit runner's CLI choices,
the prompt's playbook table, and the two cluster extractors plus the reproducer
exporter, each with its own copy of a token regex and its own hardcoded
exclusion. They drifted: activating S4 meant finding all of them, and the two
cluster extractors were missed, so a strategy that was assignable, promptable,
and attributable in reports still scored zero in every ROI table.

One list, one matcher, one normaliser. A strategy is added or retired here.
"""

from __future__ import annotations

import re

#: Every assignable strategy, in canonical numbering order. The numbering is an
#: identifier, not a ranking — `workqueue.expected_yield_rank` orders by yield.
ACTIVE: "tuple[str, ...]" = ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8")

#: Attribution tokens a report may carry: an active strategy, or the shared
#: pattern library used alongside one.
ATTRIBUTABLE: "tuple[str, ...]" = ACTIVE + ("REF",)

#: Placeholder values agents write when they have nothing to attribute.
EMPTY_VALUES = frozenset({"", "—", "-", "TBD", "?", "N/A", "n/a"})

_TOKEN_RE = re.compile(
    r"\b(" + "|".join(ATTRIBUTABLE) + r")\b", re.IGNORECASE)


def normalize(value: str) -> str:
    """Reduce a free-form Strategy field to its canonical token.

    Agents type this flag themselves and write `S2`, `s2`,
    `S2-invariant-negation`, or `S5 (lifetime & state)`. Returns the bare
    token, or the input unchanged when it carries no recognised one — a
    label nobody can parse is still better evidence than a blank.
    """
    text = (value or "").strip()
    if not text or text in EMPTY_VALUES:
        return ""
    match = _TOKEN_RE.search(text)
    return match.group(1).upper() if match else text
