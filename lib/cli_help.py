#!/usr/bin/env python3
"""Shared argparse help formatting for the operator commands."""

from __future__ import annotations

import argparse


class DefaultsHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    """Append ``(default: ...)`` only where the default carries information.

    The stock formatter also prints ``None``, empty strings and lists, and the
    ``False`` behind every ``store_true`` flag, which buries the defaults an operator
    needs among noise. A ``--flag/--no-flag`` pair keeps its default because
    the reader cannot tell it from the option names.
    """

    def _get_help_string(self, action: argparse.Action) -> str | None:
        default = action.default
        if isinstance(action, argparse.BooleanOptionalAction):
            informative = default is not None
        else:
            informative = not (
                default is None
                or default is argparse.SUPPRESS
                or default == ""
                or default == []
                or isinstance(default, bool)
            )
        if informative:
            return super()._get_help_string(action)
        return action.help
