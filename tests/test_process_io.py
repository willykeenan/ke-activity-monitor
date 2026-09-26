import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import process_io  # noqa: E402


@unittest.skipUnless(sys.platform == "darwin", "macOS rusage only")
class ProcessIoTests(unittest.TestCase):
    def test_own_process_reports_disk_bytes_and_counts_a_write(self):
        self.assertTrue(process_io.available())
        before = process_io.disk_bytes(os.getpid())
        self.assertIsNotNone(before)
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(os.urandom(4 * 1024 * 1024))
            handle.flush()
            os.fsync(handle.fileno())
            name = handle.name
        try:
            after = process_io.disk_bytes(os.getpid())
            self.assertGreaterEqual(after[1] - before[1], 4 * 1024 * 1024)
        finally:
            os.unlink(name)

    def test_other_users_and_invalid_pids_are_unavailable_not_zero(self):
        self.assertIsNone(process_io.disk_bytes(1))  # launchd belongs to root
        self.assertIsNone(process_io.disk_bytes(0))
        self.assertIsNone(process_io.disk_bytes(-5))
        self.assertIsNone(process_io.disk_bytes("12"))


if __name__ == "__main__":
    unittest.main()
