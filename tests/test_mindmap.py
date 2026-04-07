import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1] / "CTF_buddy"
sys.path.insert(0, str(PROJECT_ROOT))

from mindmap import classify  # noqa: E402


class MindmapTests(unittest.TestCase):
    def test_classify_ntlm_keywords(self):
        results = classify("windows authentication capture with ntlmv2 challenge response")
        self.assertTrue(results)
        self.assertEqual(results[0]["type"], "ntlm")

    def test_classify_dns_keywords(self):
        results = classify("dns zone transfer against a nameserver with txt record")
        self.assertTrue(results)
        self.assertEqual(results[0]["type"], "dns")


if __name__ == "__main__":
    unittest.main()
