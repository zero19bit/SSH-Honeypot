"""Integrity detects edits, reordering and missing lines in emitted JSONL."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from honeypot.logger import JsonEventLogger
from honeypot.security.integrity import HashChain
from honeypot.session import SessionState
from tools.analyze_log import analyze, main
from unittest.mock import patch


class SecurityTests(unittest.TestCase):
    def test_hash_chain_and_common_log_envelope(self):
        stream = io.StringIO()
        logger = JsonEventLogger(stream, asynchronous=False)
        session = SessionState("192.0.2.1", 77)
        logger.emit("connection_open", session)
        logger.command(session, "uname -a", "/root", 0, {"risk_score": 15, "threat": {"level": "LOW"}, "detections": [], "indicators": {}})
        logger.disconnect(session, "end")
        lines = [json.loads(line) for line in stream.getvalue().splitlines()]
        verifier = HashChain()
        for line in lines:
            self.assertTrue(verifier.verify(line))
            self.assertTrue({"timestamp", "event", "session_id", "attacker_ip", "threat", "detections", "ioc", "integrity"} <= line.keys())
        self.assertEqual(analyze(io.StringIO(stream.getvalue()))["integrity"], "VERIFIED")
        modified = [dict(line) for line in lines]
        modified[1] = {**modified[1], "exit_status": 2}
        self.assertFalse(HashChain().verify(modified[1]))
        self.assertEqual(analyze(io.StringIO("\n".join(json.dumps(line) for line in lines[1:])))["integrity"], "FAILED")
        self.assertEqual(analyze(io.StringIO("\n".join(json.dumps(line) for line in reversed(lines))))["integrity"], "FAILED")
        self.assertEqual(analyze(io.StringIO(stream.getvalue()))["top_commands"], [("uname", 1)])

    def test_disabled_hashing_and_cli_malformed_line(self):
        stream = io.StringIO()
        logger = JsonEventLogger(stream, log_hashing=False, asynchronous=False)
        logger.emit("test")
        self.assertEqual(analyze(io.StringIO(stream.getvalue()))["integrity"], "UNVERIFIED")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(stream.getvalue(), encoding="utf-8")
            with patch("sys.stdout", new_callable=io.StringIO) as out:
                self.assertEqual(main([str(path)]), 0)
                self.assertIn("Top Attackers", out.getvalue())
            path.write_text(stream.getvalue() + "not json\n", encoding="utf-8")
            with patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(main([str(path)]), 2)

    def test_async_writer_chains_in_output_order(self):
        stream = io.StringIO()
        logger = JsonEventLogger(stream, queue_size=100, asynchronous=True)
        for index in range(50):
            logger.emit("test", index=index)
        self.assertTrue(logger.flush(2))
        logger.close()
        rows = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual([row["index"] for row in rows], list(range(50)))
        self.assertEqual(analyze(io.StringIO(stream.getvalue()))["integrity"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
