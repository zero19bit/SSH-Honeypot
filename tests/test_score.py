"""Stable score boundaries and confidence bands."""

import unittest
from honeypot.intelligence.threat_score import confidence_level, score_detections, threat_level


class ScoreTests(unittest.TestCase):
    def test_boundaries(self):
        for score, expected in ((0, "NONE"), (9, "NONE"), (10, "LOW"), (29, "LOW"), (30, "MEDIUM"), (59, "MEDIUM"), (60, "HIGH"), (89, "HIGH"), (90, "CRITICAL")):
            self.assertEqual(threat_level(score), expected)
        for value, expected in ((0.0, "LOW"), (0.3, "MEDIUM"), (0.7, "HIGH"), (1.0, "HIGH")):
            self.assertEqual(confidence_level(value), expected)

    def test_deduplication_bonuses_and_cap(self):
        detections = [{"rule": "a", "score": 90, "category": "execution"}, {"rule": "b", "score": 80, "category": "delivery"}, {"rule": "c", "score": 15, "category": "reconnaissance"}, {"rule": "d", "score": 40, "category": "impact"}]
        self.assertEqual(score_detections(detections), {"score": 120, "level": "CRITICAL"})
        self.assertEqual(score_detections(detections + detections), score_detections(detections))
        self.assertEqual(score_detections(detections, 100), {"score": 100, "level": "CRITICAL"})


if __name__ == "__main__":
    unittest.main()
