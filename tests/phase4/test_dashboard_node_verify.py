"""Exercise real node HTTP telemetry and vote observations; requires node dependencies."""
import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import json
import gc
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from node.main import FedNodeRunner
from node.crypto.ed25519 import generate_keypair, sign_message
from proto import fedconsensus_pb2 as pb2


class NodeTelemetryTests(unittest.TestCase):
    def test_inbox_votes_commit_and_redacted_http_snapshot(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {
            "DATA_DIR": temp, "NODE_ID": "fednode-0", "HTTP_PORT": "0",
            "GRPC_PORT": "0", "BYZANTINE_MODE": "NONE", "QUORUM_MODE": "STRICT",
            "PEER_ADDRESSES": ",".join(f"localhost:{50051 + i}" for i in range(5)),
        }):
            runner = FedNodeRunner()
            runner.start()
            opener = build_opener(ProxyHandler({}))
            base = f"http://127.0.0.1:{runner.http_server.server_port}"

            def snapshot():
                with opener.open(base + "/telemetry", timeout=3) as response:
                    return json.load(response)

            def post(domain, content):
                body = json.dumps({"actor": f"https://{domain}/actor",
                                   "object": {"content": content}}).encode()
                return opener.open(Request(base + "/inbox", body,
                                           {"Content-Type": "application/json"}), timeout=3)

            try:
                with post("community.example", "Hello community") as response:
                    self.assertEqual(response.status, 202)
                with patch.object(runner, "_broadcast_proposal"):
                    with self.assertRaises(HTTPError) as caught:
                        post("attack.example", "Download update.exe")
                    self.assertEqual(caught.exception.code, 403)
                    caught.exception.close()
                initial = snapshot()
                self.assertEqual(initial["proposals"][0]["approvals"], ["fednode-0"])
                self.assertTrue(any(e["kind"] == "threat" for e in initial["events"]))
                self.assertTrue(any(e["source"] == "community.example" for e in initial["events"]))
                proposal_id, proposal = next(iter(runner.consensus.active_proposals.items()))
                for i in range(1, 4):
                    private, public = generate_keypair()
                    peer = f"fednode-{i}"
                    runner.consensus.register_peer_key(peer, public)
                    meta = {"proposal_id": proposal_id, "sequence_number": proposal.sequence_number,
                            "epoch": proposal.epoch, "target_domain": proposal.target_domain,
                            "decision": "APPROVE"}
                    vote = pb2.VoteRequest(
                        proposal_id=proposal_id, sequence_number=proposal.sequence_number,
                        epoch=proposal.epoch, target_domain=proposal.target_domain,
                        voter_id=peer, decision=pb2.VOTE_APPROVE, voter_signature="forged",
                    )
                    if i == 1:
                        runner.service.CastVote(vote, None)
                    vote.voter_signature = sign_message(private, meta)
                    runner.service.CastVote(vote, None)
                final = snapshot()
                self.assertEqual(final["blocked_domains"], ["attack.example"])
                self.assertTrue(final["proposals"][0]["committed"])
                self.assertEqual(len(final["proposals"][0]["approvals"]), 4)
                self.assertTrue(any(e.get("decision") == "INVALID" for e in final["events"]))
                self.assertTrue(any(e["kind"] == "commit" for e in final["events"]))
                encoded = json.dumps(final)
                self.assertNotIn(runner.config.private_key_hex, encoded)
                self.assertNotIn("voter_signature", encoded)
                self.assertNotIn("evidence_payload", encoded)
            finally:
                runner.stop()
                runner.http_server.server_close()
                gc.collect()


if __name__ == "__main__":
    unittest.main()
