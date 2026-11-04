import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.ingress.classifier import ThreatClassifier
from proto import fedconsensus_pb2 as pb2


def test_threat_classifier_features():
    """Verify velocity burst detection, phishing keywords, and malware attachments."""
    classifier = ThreatClassifier(velocity_window_seconds=10, burst_threshold=5)

    # 1. Benign post check
    benign_post = {
        "actor": "https://friendly-instance.social/users/alice",
        "object": {
            "type": "Note",
            "content": "Hello Fediverse, excited to be here!"
        }
    }
    assessment = classifier.analyze("friendly-instance.social", benign_post)
    assert assessment.is_threat is False
    assert assessment.score < 0.60
    print(f"  [PASS] 1. Benign post passed with low score: {assessment.score}")

    # 2. Phishing keyword detection
    phishing_post = {
        "actor": "https://phish-origin.com/users/spammer",
        "object": {
            "type": "Note",
            "content": "Urgent security update: Please verify your account immediately!"
        }
    }
    assessment = classifier.analyze("phish-origin.com", phishing_post)
    assert assessment.score >= 0.60
    assert assessment.is_threat is True
    assert assessment.dominant_reason_code == pb2.REASON_PHISHING
    print(f"  [PASS] 2. Phishing keywords detected (Score: {assessment.score}, Reason: PHISHING)")

    # 3. Malicious binary attachment detection (.exe)
    malware_post = {
        "actor": "https://malware-host.net/users/attacker",
        "object": {
            "type": "Note",
            "content": "Check out this game installer",
            "attachment": [{"type": "Document", "url": "http://evil.com/patch.exe"}]
        }
    }
    assessment = classifier.analyze("malware-host.net", malware_post)
    assert assessment.score >= 0.60
    assert assessment.is_threat is True
    assert assessment.dominant_reason_code == pb2.REASON_MALICIOUS_FILES
    print(f"  [PASS] 3. Malicious executable attachment detected (Score: {assessment.score}, Reason: MALICIOUS_FILES)")

    # 4. Bot velocity burst detection (5 requests in rapid succession)
    bot_domain = "spambot-army.org"
    rapid_post = {
        "actor": "https://spambot-army.org/users/bot",
        "object": {"type": "Note", "content": "Normal looking message"}
    }
    bot_assessment = None
    for _ in range(5):
        bot_assessment = classifier.analyze(bot_domain, rapid_post)
    assert bot_assessment is not None
    assert bot_assessment.dominant_reason_code == pb2.REASON_BOTNET
    print(f"  [PASS] 4. Bot flood velocity burst detected (Reason: BOTNET)")


if __name__ == "__main__":
    print("\n=======================================================")
    print("   PHASE 2 FACTOR: MULTI-FEATURE THREAT CLASSIFIER    ")
    print("=======================================================")
    test_threat_classifier_features()
    print("=======================================================")
    print("   ALL CLASSIFIER MODULES PASS 100%!                   ")
    print("=======================================================\n")
