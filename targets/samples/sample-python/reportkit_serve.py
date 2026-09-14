#!/usr/bin/env python3
"""reportkit_serve — run the reportkit HTTP service.

    reportkit_serve.py [port]

Listens on 127.0.0.1 and answers every route in ``reportkit_service`` until
stopped. ``reportkit_cli.py`` drives the same routes from a job file with its
``request`` operation, which is the scripted way to exercise them.
"""
from __future__ import annotations

import sys

import reportkit_service


def main(argv: list[str]) -> int:
    port = int(argv[1]) if len(argv) > 1 else 8474
    reportkit_service.serve(port=port)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
