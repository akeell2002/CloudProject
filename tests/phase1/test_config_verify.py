import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from proto import fedconsensus_pb2 as pb2


class TestConfigAndProtobuf(unittest.TestCase):
    def test_protobuf_message_fields(self):
        req = pb2.ProposeRequest(
            proposal_id="prop-proto-1",
            sequence_number=10,
            epoch=2,
            target_domain="phishing-bank.com",
            reason=pb2.REASON_PHISHING,
            evidence_payload='{"url": "http://phishing-bank.com"}',
            threat_score=0.95,
            proposer_id="fednode-0",
        )
        self.assertEqual(req.proposal_id, "prop-proto-1")
        self.assertEqual(req.reason, pb2.REASON_PHISHING)
        self.assertEqual(req.proposer_id, "fednode-0")

    def test_node_config_quorum_and_keys(self):
        cfg = NodeConfig()
        self.assertEqual(cfg.total_nodes, 5)
        self.assertEqual(cfg.max_byzantine_faults, 1)
        self.assertEqual(cfg.quorum_size, 4)
        self.assertEqual(len(cfg.public_key_hex), 64)
        self.assertEqual(len(cfg.private_key_hex), 64)


if __name__ == "__main__":
    unittest.main()
