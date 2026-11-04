import os
import sys
import shutil
import tempfile

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.storage.database import Database
from node.ingress.firewall import FirewallFilter
from node.ingress.classifier import ThreatClassifier
from node.ingress.activitypub import ActivityPubInbox


def test_activitypub_inbox_pipeline():
    """Verify origin extraction, perimeter drops, benign acceptance, and threat escalation."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "inbox_test.db")
    try:
        db = Database(db_path)
        fw = FirewallFilter(db)
        tc = ThreatClassifier()

        escalated_threats = []
        def mock_escalation_callback(domain, payload, assessment):
            escalated_threats.append((domain, assessment))

        inbox = ActivityPubInbox(fw, tc, on_threat_detected=mock_escalation_callback)

        # 1. Domain extraction
        domain = inbox.extract_origin_domain({"actor": "https://mastodon.social/users/alice"})
        assert domain == "mastodon.social"
        print("  [PASS] 1. ActivityStreams actor URI parsed into domain cleanly")

        # 2. Benign post accepted (HTTP 202)
        benign_post = {
            "actor": "https://mastodon.social/users/alice",
            "object": {"content": "Hello from Mastodon!"}
        }
        code, res = inbox.process_inbox_post(benign_post)
        assert code == 202
        assert res["status"] == "ACCEPTED"
        print(f"  [PASS] 2. Benign post accepted with HTTP {code} ACCEPTED")

        # 3. Malicious post flagged and escalated (HTTP 403 FLAGGED_FOR_CONSENSUS)
        phish_post = {
            "actor": "https://malicious-node.org/users/spammer",
            "object": {"content": "Urgent security update: Please verify your account now!"}
        }
        code, res = inbox.process_inbox_post(phish_post)
        assert code == 403
        assert res["status"] == "FLAGGED_FOR_CONSENSUS"
        assert len(escalated_threats) == 1
        assert escalated_threats[0][0] == "malicious-node.org"
        print(f"  [PASS] 3. Malicious post intercepted with HTTP {code} and escalated to consensus")

        # 4. Firewall drops banned domains immediately before running classifier (HTTP 403 BLOCKED)
        fw.block_domain("malicious-node.org")
        code, res = inbox.process_inbox_post(phish_post)
        assert code == 403
        assert res["status"] == "BLOCKED"
        print(f"  [PASS] 4. Perimeter firewall blocked previously defederated domain immediately")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    print("\n=======================================================")
    print("   PHASE 2 FACTOR: ACTIVITYPUB INGRESS ENDPOINT        ")
    print("=======================================================")
    test_activitypub_inbox_pipeline()
    print("=======================================================")
    print("   ALL INGRESS ENDPOINT MODULES PASS 100%!             ")
    print("=======================================================\n")
