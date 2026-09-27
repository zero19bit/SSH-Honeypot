"""Deterministic scoring, independent of parsing and session state."""

from __future__ import annotations

from typing import Mapping, Any


def confidence_level(confidence: float) -> str:
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
    return "HIGH" if confidence >= 0.7 else "MEDIUM" if confidence >= 0.3 else "LOW"


def threat_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "NONE"


def score_detections(detections: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...], max_score: int = 1000) -> dict[str, int | str]:
    """Strongest rule plus ten per additional category; repeated rules add nothing."""
    if max_score < 1:
        raise ValueError("max_score must be positive")
    unique: dict[str, Mapping[str, Any]] = {}
    for detection in detections:
        name = detection.get("rule")
        score = detection.get("score")
        if not isinstance(name, str) or type(score) is not int or not 0 <= score <= max_score:
            continue
        if name not in unique or score > unique[name]["score"]:
            unique[name] = detection
    categories = {d.get("category") for d in unique.values() if isinstance(d.get("category"), str)}
    score = min(max_score, max((d["score"] for d in unique.values()), default=0) + 10 * max(0, len(categories) - 1))
    return {"score": score, "level": threat_level(score)}
