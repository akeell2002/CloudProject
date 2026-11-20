import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.ingress.activitypub import ActivityPubInbox
from node.ingress.classifier import ThreatClassifier
from node.ingress.firewall import FirewallFilter
from node.storage.database import Database


class TestActivityPubInbox(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.temp_dir, "inbox_test.db"))
        self.fw = FirewallFilter(self.db)
        self.tc = ThreatClassifier()
        self.escalated_threats = []
        self.inbox = ActivityPubInbox(
            self.fw,
            self.tc,
            on_threat_detected=lambda domain, payload, assessment: self.escalated_threats.append((domain, assessment)),
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_inbox_pipeline(self):
        domain = self.inbox.extract_origin_domain({"actor": "https://mastodon.social/users/alice"})
        self.assertEqual(domain, "mastodon.social")

        benign_post = {
            "actor": "https://mastodon.social/users/alice",
            "object": {"content": "Hello from Mastodon!"},
        }
        code, res = self.inbox.process_inbox_post(benign_post)
        self.assertEqual(code, 202)
        self.assertEqual(res["status"], "ACCEPTED")

        phish_post = {
            "actor": "https://malicious-node.org/users/spammer",
            "object": {"content": "Urgent security update: Please verify your account now!"},
        }
        code, res = self.inbox.process_inbox_post(phish_post)
        self.assertEqual(code, 403)
        self.assertEqual(res["status"], "FLAGGED_FOR_CONSENSUS")
        self.assertEqual(len(self.escalated_threats), 1)
        self.assertEqual(self.escalated_threats[0][0], "malicious-node.org")

        self.fw.block_domain("malicious-node.org")
        code, res = self.inbox.process_inbox_post(phish_post)
        self.assertEqual(code, 403)
        self.assertEqual(res["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
