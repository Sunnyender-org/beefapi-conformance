import errno
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from beefapi_conformance.runner import _remove_owned_workspace


class RootTeardownTests(unittest.TestCase):
    def test_missing_child_with_existing_root_never_reports_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "owned"
            root.mkdir()
            with (
                patch(
                    "beefapi_conformance.runner.shutil.rmtree",
                    side_effect=FileNotFoundError(errno.ENOENT, "child disappeared"),
                ),
                patch("beefapi_conformance.runner.time.sleep"),
                self.assertRaises(FileNotFoundError),
            ):
                _remove_owned_workspace(str(root))
            self.assertTrue(root.exists())

    def test_missing_root_is_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            _remove_owned_workspace(str(Path(tmp) / "missing"))


if __name__ == "__main__":
    unittest.main()
