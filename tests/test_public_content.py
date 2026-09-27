"""Nothing private ships in this public repository.

The words are split so this file does not match itself.
"""
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PRIVATE = (
    "jar" + "vis",
    "william" + "keenan",
    "heat" + "wake",
    "hs" + "bc",
    "office" + "job",
    "back" + "rooms",
    ".ts" + ".net",
)
SKIP_DIRS = {".git", "__pycache__", "build", "dist", ".venv", "node_modules"}


def text_files():
    for folder, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = Path(folder) / name
            try:
                yield path, path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue  # images and other binaries


class PublicContent(unittest.TestCase):
    def test_no_private_names_ship(self):
        hits = []
        for path, text in text_files():
            lowered = text.lower()
            for word in PRIVATE:
                if word in lowered:
                    hits.append(f"{path.relative_to(ROOT)}: {word}")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
