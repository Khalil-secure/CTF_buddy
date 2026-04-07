import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1] / "CTF_buddy"
sys.path.insert(0, str(PROJECT_ROOT))

from validator import find_flag, find_hash  # noqa: E402


class ValidatorTests(unittest.TestCase):
    def test_find_ctf_flag_pattern(self):
        self.assertEqual(find_flag("result: CTF{network_win}"), "CTF{network_win}")

    def test_find_flag_from_json_password_field(self):
        text = '{"password": "Tigre", "error": null}'
        self.assertEqual(find_flag(text), "Tigre")

    def test_find_hash_md5(self):
        self.assertEqual(find_hash("098f6bcd4621d373cade4e832627b4f6"), "098f6bcd4621d373cade4e832627b4f6")


if __name__ == "__main__":
    unittest.main()
