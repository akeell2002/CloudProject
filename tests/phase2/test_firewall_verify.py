import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.ingress.firewall import FirewallFilter
from node.storage.database import Database
from proto import fedconsensus_pb2 as pb2


class TestFirewallFilter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.temp_dir, "firewall_test.db"))
        self.fw = FirewallFilter(self.db)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_blocking_normalization_and_reload(self):
        self.assertEqual(self.fw.count(), 0)
        self.assertFalse(self.fw.is_blocked("malware.com"))

        self.fw.block_domain("bad-actor.org")
        self.assertTrue(self.fw.is_blocked("bad-actor.org"))
        self.assertTrue(self.fw.is_blocked("  BAD-ACTOR.ORG  "))
        self.assertFalse(self.fw.is_blocked("good-actor.org"))
        self.assertEqual(self.fw.count(), 1)

        self.db.save_commit_record(
            sequence_number=1,
            epoch=1,
            target_domain="db-persisted-threat.net",
            reason=pb2.REASON_BOTNET,
            quorum_proof={"signatures": []},
        )
        self.assertFalse(self.fw.is_blocked("db-persisted-threat.net"))

        self.fw.reload_rules()
        self.assertTrue(self.fw.is_blocked("db-persisted-threat.net"))


if __name__ == "__main__":
    unittest.main()
