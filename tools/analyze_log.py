"""Stream a JSONL log into a bounded, credential-free terminal summary."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from collections import Counter
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from honeypot.security.integrity import HashChain, GENESIS  # noqa: E402

MAX_LINE = 256_000
MAX_DISTINCT = 10_000


def _add(counter: Counter[str], name: str) -> None:
    if name in counter or len(counter) < MAX_DISTINCT:
        counter[name] += 1


def _program(value: object) -> str:
    if not isinstance(value, str):
        return "unknown"
    try:
        words = shlex.split(value[:4096])
    except ValueError:
        return "unknown"
    # Report the command name only, never credentials, arguments or URLs.
    return words[0].rsplit("/", 1)[-1][:64] if words else "unknown"


def analyze(lines: object) -> dict[str, object]:
    attackers: Counter[str] = Counter()
    programs: Counter[str] = Counter()
    levels: Counter[str] = Counter()
    events = commands = unsigned = invalid = 0
    chain = HashChain()
    for line in lines:
        if len(line) > MAX_LINE:
            invalid += 1
            continue
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            invalid += 1
            continue
        if not isinstance(record, dict):
            invalid += 1
            continue
        if "integrity" in record:
            if not chain.verify(record):
                invalid += 1
        else:
            unsigned += 1
        events += 1
        if record.get("event") != "command":
            continue
        commands += 1
        ip = record.get("attacker_ip") or record.get("ip")
        if isinstance(ip, str) and len(ip) <= 64:
            _add(attackers, ip)
        _add(programs, _program(record.get("command")))
        threat = record.get("threat") or {}
        if isinstance(threat, dict) and isinstance(threat.get("severity"), str):
            _add(levels, threat["severity"].upper()[:16])
        elif isinstance(record.get("analysis"), dict):
            _add(levels, str(record["analysis"].get("risk_level", "none")).upper()[:16])
    return {
        "events": events, "commands": commands,
        "integrity": "FAILED" if invalid else ("UNVERIFIED" if unsigned or chain.previous == GENESIS else "VERIFIED"),
        "invalid_lines": invalid, "unsigned_lines": unsigned,
        "top_attackers": attackers.most_common(10),
        "top_commands": programs.most_common(10),
        "threat_summary": dict(sorted(levels.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read honeypot JSONL; never print command arguments")
    parser.add_argument("log", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        with args.log.open("r", encoding="utf-8", errors="replace") as stream:
            result = analyze(stream)
    except OSError as exc:
        parser.exit(2, f"cannot read log: {exc}\n")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Events: {result['events']}  Commands: {result['commands']}  Integrity: {result['integrity']}")
        for label, key in (("Top Attackers", "top_attackers"), ("Top Commands", "top_commands")):
            print(f"{label}:")
            for name, count in result[key]:
                print(f"  {name}: {count}")
        print("Threat Summary:")
        for level, count in result["threat_summary"].items():
            print(f"  {level}: {count}")
    return 2 if result["integrity"] == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
