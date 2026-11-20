import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.ingress.classifier import ThreatClassifier
from proto import fedconsensus_pb2 as pb2


class TestThreatClassifier(unittest.TestCase):
    def setUp(self):
        self.classifier = ThreatClassifier(velocity_window_seconds=10, burst_threshold=5)

    def test_benign_post(self):
        benign_post = {
            "actor": "https://friendly-instance.social/users/alice",
            "object": {"type": "Note", "content": "Hello Fediverse, excited to be here!"},
        }
        assessment = self.classifier.analyze("friendly-instance.social", benign_post)
        self.assertFalse(assessment.is_threat)
        self.assertLess(assessment.score, 0.60)

    def test_phishing_keywords(self):
        phishing_post = {
            "actor": "https://phish-origin.com/users/spammer",
            "object": {
                "type": "Note",
                "content": "Urgent security update: Please verify your account immediately!",
            },
        }
        assessment = self.classifier.analyze("phish-origin.com", phishing_post)
        self.assertGreaterEqual(assessment.score, 0.60)
        self.assertTrue(assessment.is_threat)
        self.assertEqual(assessment.dominant_reason_code, pb2.REASON_PHISHING)

    def test_malicious_executable_attachment(self):
        malware_post = {
            "actor": "https://malware-host.net/users/attacker",
            "object": {
                "type": "Note",
                "content": "Check out this game installer",
                "attachment": [{"type": "Document", "url": "http://evil.com/patch.exe"}],
            },
        }
        assessment = self.classifier.analyze("malware-host.net", malware_post)
        self.assertGreaterEqual(assessment.score, 0.60)
        self.assertTrue(assessment.is_threat)
        self.assertEqual(assessment.dominant_reason_code, pb2.REASON_MALICIOUS_FILES)

    def test_velocity_burst_detection(self):
        bot_domain = "spambot-army.org"
        rapid_post = {
            "actor": "https://spambot-army.org/users/bot",
            "object": {"type": "Note", "content": "Normal looking message"},
        }
        assessment = None
        for _ in range(5):
            assessment = self.classifier.analyze(bot_domain, rapid_post)
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.dominant_reason_code, pb2.REASON_BOTNET)


if __name__ == "__main__":
    unittest.main()
