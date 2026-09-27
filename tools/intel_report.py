"""Offline ingestion and reporting for the honeypot's JSONL logs.

This analyst-run tool is separate from the SSH runtime. By default it drops
passwords and raw commands while keeping searchable intelligence fields.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable


MAX_LINE_CHARS = 131072
EVENT_TYPES = frozenset({"connection_open", "authentication", "command", "intelligence_alert", "disconnect"})
SAFE_ID = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")


def _safe_id(value: Any) -> str:
    return value if isinstance(value, str) and SAFE_ID.fullmatch(value) else ""


def _safe_text(value: Any, length: int) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(c for c in value[:length] if c.isprintable())


def _safe_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) else ""
    except ValueError:
        return ""


def connect_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, 3):
        connection.close()
        raise ValueError(f"unsupported database schema version: {version}")
    with connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS intel_events (
                source_id TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL,
                session_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                category TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                primary_rule TEXT NOT NULL,
                matched_rules TEXT NOT NULL,
                indicators TEXT NOT NULL,
                raw_command TEXT,
                exit_status INTEGER,
                PRIMARY KEY (source_id, line_number)
            );
            CREATE INDEX IF NOT EXISTS intel_events_ip_time ON intel_events (ip, timestamp);
            CREATE INDEX IF NOT EXISTS intel_events_event_risk ON intel_events (event, risk_score);
            PRAGMA user_version=3;
            """
        )
    return connection


def _row(record: Any, source_id: str, line_number: int, include_commands: bool) -> tuple[Any, ...] | None:
    if not isinstance(record, dict) or record.get("event") not in EVENT_TYPES:
        return None
    event = record["event"]
    analysis = record.get("analysis", {}) if event == "command" else record
    if not isinstance(analysis, dict):
        analysis = {}
    risk_value = analysis.get("risk_score", 0)
    risk = min(1000, max(0, risk_value)) if type(risk_value) is int else 0
    rules = analysis.get("matched_rules", [])
    rules = [rule for rule in rules[:32] if _safe_id(rule)] if isinstance(rules, list) else []
    indicator_data = analysis.get("indicators", {})
    indicators: dict[str, list[str]] = {key: [] for key in ("hosts", "ips", "artifacts", "domains", "urls", "md5", "sha256", "files")}
    if isinstance(indicator_data, dict):
        for key in indicators:
            values = indicator_data.get(key, [])
            if isinstance(values, list):
                indicators[key] = [_safe_text(value, 253) for value in values[:8] if _safe_text(value, 253)]
    status = record.get("exit_status")
    return (
        source_id,
        line_number,
        _safe_text(record.get("timestamp"), 64),
        event,
        _safe_text(record.get("session_id"), 64),
        _safe_ip(record.get("ip")),
        _safe_id(analysis.get("category")),
        risk,
        _safe_id(analysis.get("primary_rule")),
        json.dumps(rules, separators=(",", ":")),
        json.dumps(indicators, separators=(",", ":")),
        _safe_text(record.get("command"), 4096) if event == "command" and include_commands else None,
        status if type(status) is int and -1 <= status <= 255 else None,
    )


def ingest_lines(
    connection: sqlite3.Connection,
    lines: Iterable[str],
    source_id: str,
    *,
    include_commands: bool = False,
) -> dict[str, int]:
    added = duplicates = skipped = 0
    statement = """INSERT OR IGNORE INTO intel_events
        (source_id,line_number,timestamp,event,session_id,ip,category,risk_score,
         primary_rule,matched_rules,indicators,raw_command,exit_status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    with connection:
        for line_number, line in enumerate(lines, start=1):
            if len(line) > MAX_LINE_CHARS:
                skipped += 1
                continue
            try:
                record = json.loads(line)
            except (ValueError, TypeError):
                skipped += 1
                continue
            row = _row(record, source_id, line_number, include_commands)
            if row is None:
                skipped += 1
                continue
            cursor = connection.execute(statement, row)
            if cursor.rowcount:
                added += 1
            else:
                duplicates += 1
    return {"added": added, "duplicates": duplicates, "skipped": skipped}


def build_report(connection: sqlite3.Connection, limit: int = 10) -> dict[str, object]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    total, commands, alerts, sessions, first, last = connection.execute(
        """SELECT COUNT(*), SUM(event='command'), SUM(event='intelligence_alert'),
           COUNT(DISTINCT NULLIF(session_id,'')), MIN(NULLIF(timestamp,'')), MAX(timestamp)
           FROM intel_events"""
    ).fetchone()
    sources = connection.execute(
        """SELECT ip, SUM(event='command') AS commands, SUM(event='intelligence_alert') AS alerts,
           MAX(risk_score) AS highest_risk
           FROM intel_events WHERE ip != '' GROUP BY ip
           ORDER BY highest_risk DESC, commands DESC, ip ASC LIMIT ?""",
        (limit,),
    ).fetchall()
    categories = connection.execute(
        """SELECT category, COUNT(*) FROM intel_events
           WHERE event='command' AND category != '' GROUP BY category
           ORDER BY COUNT(*) DESC, category ASC"""
    ).fetchall()
    rules = connection.execute(
        """SELECT primary_rule, COUNT(*) FROM intel_events
           WHERE event='command' AND primary_rule != '' GROUP BY primary_rule
           ORDER BY COUNT(*) DESC, primary_rule ASC LIMIT ?""",
        (limit,),
    ).fetchall()
    return {
        "total_events": total,
        "commands": commands or 0,
        "alerts": alerts or 0,
        "sessions": sessions,
        "first_seen": first,
        "last_seen": last,
        "top_sources": [dict(zip(("ip", "commands", "alerts", "highest_risk"), row)) for row in sources],
        "categories": dict(categories),
        "top_primary_rules": dict(rules),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline SQLite intelligence for honeypot JSONL")
    commands = parser.add_subparsers(dest="operation", required=True)
    ingest = commands.add_parser("ingest", help="import JSONL; passwords are never saved")
    ingest.add_argument("log", type=Path, help="JSONL log path")
    ingest.add_argument("--db", type=Path, required=True)
    ingest.add_argument("--source-id", help="stable identifier for this input; default is its absolute path")
    ingest.add_argument("--include-commands", action="store_true", help="also store raw command text (sensitive)")
    report = commands.add_parser("report", help="show aggregate behavior")
    report.add_argument("--db", type=Path, required=True)
    report.add_argument("--limit", type=int, default=10)
    report.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.operation == "report" and not args.db.is_file():
            raise ValueError(f"database does not exist: {args.db}")
        db = connect_database(args.db)
        with db:
            if args.operation == "ingest":
                with args.log.open("r", encoding="utf-8", errors="replace") as stream:
                    result = ingest_lines(
                        db, stream, args.source_id or str(args.log.resolve()),
                        include_commands=args.include_commands,
                    )
                print(json.dumps(result))
            else:
                result = build_report(db, args.limit)
                if args.json:
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                else:
                    print(f"Events: {result['total_events']}  Sessions: {result['sessions']}  Commands: {result['commands']}  Alerts: {result['alerts']}")
                    print(f"Period: {result['first_seen'] or '-'} to {result['last_seen'] or '-'}")
                    for item in result["top_sources"]:
                        print(f"{item['ip']}  commands={item['commands']} alerts={item['alerts']} max_risk={item['highest_risk']}")
    except (OSError, sqlite3.Error, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    finally:
        if "db" in locals():
            db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
