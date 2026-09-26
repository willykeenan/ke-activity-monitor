#!/usr/bin/env python3
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
result = subprocess.run(
    [sys.executable, "-m", "unittest", "tests.test_network_ui", "-v"],
    cwd=ROOT,
    text=True,
)
if result.returncode != 0:
    raise SystemExit(result.returncode)
print("LANE_OK network-fabric-ui")
