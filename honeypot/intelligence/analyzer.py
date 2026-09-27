"""Bounded, per-session analysis of commands accepted by the fake terminal."""

from __future__ import annotations

import itertools
import re
import shlex
from collections import Counter, deque
from dataclasses import dataclass, field

from .cache import AnalysisCache
from .indicators import download_artifacts, empty_indicators, executed_artifacts, extract_indicators
from .rules import RULES, Invocation, Rule
from .threat_score import confidence_level, score_detections


MAX_ANALYSIS_CHARS = 65536
MAX_TOKENS = 2048
OPERATORS = frozenset({";", "&&", "||", "|", "&"})
MAX_RECENT_ARTIFACTS = 16
MAX_RECENT_HOSTS = 16
MAX_STAGES = 16
_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]{0,256}\x07)?")
_CONTROL = dict.fromkeys(list(range(0, 32)) + list(range(127, 160)), " ")
STAGES = {
    "reconnaissance": "discovery",
    "discovery": "discovery",
    "credential_access": "credential_access",
    "delivery": "delivery",
    "execution": "execution",
    "persistence": "persistence",
    "privilege_escalation": "privilege_escalation",
    "defense_evasion": "defense_evasion",
    "impact": "impact",
    "resource_abuse": "resource_abuse",
    "exfiltration": "exfiltration",
}


@dataclass(frozen=True, slots=True)
class Analysis:
    category: str = "other"
    categories: tuple[str, ...] = ()
    risk_score: int = 0
    risk_level: str = "none"
    matched_rules: tuple[str, ...] = ()
    primary_rule: str = "none"
    stages: tuple[str, ...] = ()
    indicators: dict[str, list[str]] = field(default_factory=empty_indicators)
    detections: tuple[dict[str, object], ...] = ()
    threat: dict[str, int | str] = field(default_factory=lambda: {"score": 0, "level": "NONE"})
    parse_error: bool = False
    truncated: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "categories": list(self.categories),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "matched_rules": list(self.matched_rules),
            "primary_rule": self.primary_rule,
            "stages": list(self.stages),
            "indicators": {key: list(value) for key, value in self.indicators.items()},
            "detections": [dict(item) for item in self.detections],
            "threat": dict(self.threat),
            "parse_error": self.parse_error,
            "truncated": self.truncated,
        }


def sanitize_command(command: str, limit: int = MAX_ANALYSIS_CHARS) -> str:
    """Remove terminal control sequences before parsing, simulating and logging."""
    return _ESCAPE.sub("", command[:limit]).translate(_CONTROL).strip()


def _invocations(command: str) -> tuple[tuple[Invocation, ...], bool, bool]:
    limited = command[:MAX_ANALYSIS_CHARS]
    truncated = len(command) > MAX_ANALYSIS_CHARS
    lexer = shlex.shlex(limited, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = ""  # The fake command parser also keeps '#'.
    try:
        tokens = list(itertools.islice(lexer, MAX_TOKENS + 1))
    except ValueError:
        return (), True, truncated
    if len(tokens) > MAX_TOKENS:
        tokens = tokens[:MAX_TOKENS]
        truncated = True
    invocations: list[Invocation] = []
    current: list[str] = []
    connector = ";"
    for token in tokens:
        if token in OPERATORS:
            if current:
                invocations.append(Invocation(tuple(current), connector))
                current = []
            connector = token
        else:
            current.append(token)
    if current:
        invocations.append(Invocation(tuple(current), connector))
    return tuple(invocations), False, truncated


@dataclass(frozen=True, slots=True)
class _StaticAnalysis:
    matches: tuple[Rule, ...]
    indicators: dict[str, list[str]]
    actions: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]
    parse_error: bool
    truncated: bool


_CORRELATED = Rule("download_then_execute", (), "string", 90, "CRITICAL", "execution", "", 0.95, "Executed a previously downloaded artifact")


@dataclass(slots=True)
class Analyzer:
    """Keep bounded session context without retaining command text or URLs."""

    commands_analyzed: int = 0
    highest_risk_score: int = 0
    category_counts: Counter[str] = field(default_factory=Counter)
    recent_artifacts: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_RECENT_ARTIFACTS))
    recent_hosts: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_RECENT_HOSTS))
    stage_sequence: list[str] = field(default_factory=list)
    alerted_rules: set[str] = field(default_factory=set)
    alerts_emitted: int = 0
    enabled: bool = True
    ioc_enabled: bool = True
    max_score: int = 1000
    cache: AnalysisCache = field(default_factory=AnalysisCache)

    def analyze(self, command: str) -> Analysis:
        if not self.enabled:
            self.commands_analyzed += 1
            return Analysis()
        safe_command = sanitize_command(command)
        static = self.cache.get(safe_command)
        if static is None:
            invocations, parse_error, truncated = _invocations(safe_command)
            static = _StaticAnalysis(
                tuple(rule for rule in RULES if rule.matches(invocations)),
                extract_indicators(invocations) if self.ioc_enabled else empty_indicators(),
                tuple((executed_artifacts(item), download_artifacts(item)) for item in invocations),
                parse_error,
                truncated or len(command) > MAX_ANALYSIS_CHARS,
            )
            self.cache.put(safe_command, static)
        matches = list(static.matches)
        indicators = {key: list(value) for key, value in static.indicators.items()}

        available = set(self.recent_artifacts)
        new_artifacts: list[str] = []
        correlated = False
        for executed, downloaded in static.actions:
            if available.intersection(executed):
                correlated = True
            for artifact in downloaded:
                available.add(artifact)
                if artifact not in new_artifacts:
                    new_artifacts.append(artifact)
        if correlated:
            matches.append(_CORRELATED)
        for artifact in new_artifacts:
            if artifact in self.recent_artifacts:
                self.recent_artifacts.remove(artifact)
            self.recent_artifacts.append(artifact)

        categories = tuple(dict.fromkeys(rule.category for rule in matches))
        detections = tuple({"rule": rule.name, "score": rule.score, "confidence": rule.confidence,
                            "confidence_score": rule.confidence, "confidence_level": confidence_level(rule.confidence), "severity": rule.severity,
                            "category": rule.category, "mitre": rule.mitre, "description": rule.description}
                           for rule in matches)
        threat = score_detections(detections, self.max_score)
        score = threat["score"]
        level = (
            "critical" if score >= 90 else
            "high" if score >= 65 else
            "medium" if score >= 35 else
            "low" if score > 0 else "none"
        )
        top = max(matches, key=lambda rule: rule.score) if matches else None
        primary_rule, primary = (top.name, top.category) if top else ("none", "other")
        stages = tuple(dict.fromkeys(STAGES[category] for category in categories))
        result = Analysis(
            category=primary,
            categories=categories,
            risk_score=score,
            risk_level=level,
            matched_rules=tuple(rule.name for rule in matches),
            primary_rule=primary_rule,
            stages=stages,
            indicators=indicators,
            detections=detections,
            threat=threat,
            parse_error=static.parse_error,
            truncated=static.truncated or len(command) > MAX_ANALYSIS_CHARS,
        )
        self.commands_analyzed += 1
        self.highest_risk_score = max(self.highest_risk_score, score)
        for category in categories:
            self.category_counts[category] += 1
        for stage in stages:
            if len(self.stage_sequence) < MAX_STAGES and (not self.stage_sequence or self.stage_sequence[-1] != stage):
                self.stage_sequence.append(stage)
        for host in indicators["hosts"] + indicators["ips"]:
            if host in self.recent_hosts:
                self.recent_hosts.remove(host)
            self.recent_hosts.append(host)
        return result

    def claim_alert(self, analysis: Analysis, min_risk_score: int) -> bool:
        """Deduplicate an alert by its strongest rule within this session."""
        rule_id = analysis.primary_rule
        if analysis.risk_score < min_risk_score or rule_id == "none" or rule_id in self.alerted_rules:
            return False
        self.alerted_rules.add(rule_id)
        self.alerts_emitted += 1
        return True

    def summary(self) -> dict[str, object]:
        return {
            "commands_analyzed": self.commands_analyzed,
            "highest_risk_score": self.highest_risk_score,
            "category_counts": dict(sorted(self.category_counts.items())),
            "stage_sequence": list(self.stage_sequence),
            "recent_hosts": list(self.recent_hosts),
            "alerts_emitted": self.alerts_emitted,
            "cache_hits": self.cache.hits,
            "cache_misses": self.cache.misses,
        }
