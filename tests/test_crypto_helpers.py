import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1] / "CTF_buddy"
sys.path.insert(0, str(PROJECT_ROOT))

from tools.crypto import base64_decode, caesar_crack, decode_credentials  # noqa: E402


class CryptoHelperTests(unittest.TestCase):
    def test_base64_decode(self):
        result = base64_decode("YWRtaW46c2VjcmV0")
        self.assertEqual(result["decoded"], "admin:secret")

    def test_decode_credentials_extracts_user_and_password(self):
        result = decode_credentials("Basic YWRtaW46c2VjcmV0")
        self.assertEqual(result["username"], "admin")
        self.assertEqual(result["password"], "secret")

    def test_caesar_crack_with_specific_shift(self):
        result = caesar_crack("uryyb", shift=13)
        self.assertEqual(result["best_guess"]["text"], "hello")


if __name__ == "__main__":
    unittest.main()
