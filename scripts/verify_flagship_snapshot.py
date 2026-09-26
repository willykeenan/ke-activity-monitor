#!/usr/bin/env python3
"""Verify a saved flagship snapshot or the built-in contract-only snapshot."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from flagship_acceptance import acceptance_summary  # noqa: E402
from flagship_capabilities import FlagshipCapabilityService  # noqa: E402
from flagship_sources import feature_signals  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print("usage: verify_flagship_snapshot.py [snapshot.json]", file=sys.stderr)
        return 2
    if len(argv) == 2:
        try:
            payload = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            print(f"FLAGSHIP_CAPABILITIES_INVALID unable to read snapshot: {error}", file=sys.stderr)
            return 1
    else:
        payload = FlagshipCapabilityService().snapshot(feature_signals({}))
    result = acceptance_summary(payload)
    if not result["ok"]:
        print("FLAGSHIP_CAPABILITIES_INVALID " + "; ".join(result["errors"]), file=sys.stderr)
        return 1
    print("FLAGSHIP_CAPABILITIES_OK 30+1 CURRENT_ORDER_PRESERVED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
