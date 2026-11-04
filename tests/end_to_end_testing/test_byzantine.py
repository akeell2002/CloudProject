"""
Automated Verification Suite for Byzantine Fault Resilience (Milestone 4.4 - Part 2)
Tests:
  1. Byzantine LIAR Fault Masking (1 liar voting REJECT cannot prevent Q=4 commit)
  2. Byzantine FORGER Detection & Reputation Penalty (-40 points & ballot dropped)
  3. Combined Multi-Fault Safety (Cluster stalls safely when honest quorum < Q)
"""
import os
import sys
import shutil
import tempfile
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.engine.consensus import ConsensusEngine
from node.crypto.ed25519 import generate_keypair, sign_message


def test_byzantine_liar_fault_masking():
    """
    Proves that 1 Byzantine LIAR voting REJECT on confirmed malware cannot
    prevent the remaining 4 honest nodes from reaching Q=4 and committing the ban.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        db = Database(os.path.join(temp_dir, "byzantine_liar.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        cfg = NodeConfig()
        cfg.node_id = "fednode-0"

        engine = ConsensusEngine(cfg, db, fw, rep)

        # Setup 5 nodes
        keys = {"fednode-0": (cfg.private_key_hex, cfg.public_key_hex)}
        for i in range(1, 5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            engine.register_peer_key(nid, pub)

        # Leader creates proposal (Leader vote = 1/4)
        prop = engine.create_proposal(
            target_domain="stealer-trojan.com",
            reason=pb2.REASON_MALICIOUS_FILES,
            evidence_payload='{"actor": "https://stealer-trojan.com/bot"}',
            origin_http_signature="",
            threat_score=0.95
        )

        # Node 1 is a BYZANTINE LIAR -> casts VOTE_REJECT!
        liar_meta = {
            "proposal_id": prop.proposal_id,
            "sequence_number": prop.sequence_number,
            "epoch": prop.epoch,
            "target_domain": prop.target_domain,
            "decision": "REJECT"
        }
        liar_vote = pb2.VoteRequest(
            proposal_id=prop.proposal_id,
            sequence_number=prop.sequence_number,
            epoch=prop.epoch,
            target_domain=prop.target_domain,
            voter_id="fednode-1",
            decision=pb2.VOTE_REJECT,
            voter_signature=sign_message(keys["fednode-1"][0], liar_meta),
            timestamp=int(time.time() * 1000)
        )
        qc_after_liar = engine.handle_vote(liar_vote)
        assert qc_after_liar is None, "QC must not be minted on a REJECT ballot!"

        # Honest Nodes 2, 3, 4 all cast VOTE_APPROVE
        for i in [2, 3, 4]:
            nid = f"fednode-{i}"
            meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": prop.target_domain,
                "decision": "APPROVE"
            }
            vote = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=prop.target_domain,
                voter_id=nid,
                decision=pb2.VOTE_APPROVE,
                voter_signature=sign_message(keys[nid][0], meta),
                timestamp=int(time.time() * 1000)
            )
            qc = engine.handle_vote(vote)

        # Quorum (Q=4) must be reached despite Node 1 lying!
        assert qc is not None, "Honest majority of 4 nodes must reach quorum!"
        assert len(qc.signatures) == 4
        # Verify Node 1 (liar) is NOT in the Quorum Certificate
        voter_ids = [s.voter_id for s in qc.signatures]
        assert "fednode-1" not in voter_ids
        assert set(voter_ids) == {"fednode-0", "fednode-2", "fednode-3", "fednode-4"}

        # Commit ban
        engine.commit_defederation(qc)
        assert fw.is_blocked("stealer-trojan.com") is True

        print("  [PASS] 1. Byzantine LIAR fault masked: 1 liar isolated, honest majority reached Q=4 and banned malware!")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_byzantine_forger_reputation_penalty():
    """
    Proves that a node submitting a forged signature has its ballot dropped
    and is penalized by -40 trust points in the Reputation Ledger.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        db = Database(os.path.join(temp_dir, "byzantine_forger.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        cfg = NodeConfig()
        cfg.node_id = "fednode-0"

        engine = ConsensusEngine(cfg, db, fw, rep)

        # Register Node 2
        priv_2, pub_2 = generate_keypair()
        engine.register_peer_key("fednode-2", pub_2)

        # Initial reputation is 100
        initial_score = next((r["trust_score"] for r in rep.get_ledger() if r["peer_id"] == "fednode-2"), 100)
        assert initial_score == 100

        prop = engine.create_proposal(
            target_domain="phish-bank.com",
            reason=pb2.REASON_PHISHING,
            evidence_payload='{}',
            origin_http_signature="",
            threat_score=0.89
        )

        # Node 2 submits a forged signature (bogus signature bytes)
        forged_vote = pb2.VoteRequest(
            proposal_id=prop.proposal_id,
            sequence_number=prop.sequence_number,
            epoch=prop.epoch,
            target_domain=prop.target_domain,
            voter_id="fednode-2",
            decision=pb2.VOTE_APPROVE,
            voter_signature="bad_signature_000000000000000000000000000000000000000000000000",
            timestamp=int(time.time() * 1000)
        )

        qc = engine.handle_vote(forged_vote)
        assert qc is None

        # Verify ballot was NOT added to the proposal
        p_state = engine.active_proposals[prop.proposal_id]
        assert "fednode-2" not in p_state.approved_votes

        # Verify reputation penalized by -40 points
        penalized_score = next(r["trust_score"] for r in rep.get_ledger() if r["peer_id"] == "fednode-2")
        assert penalized_score == 60, f"Expected trust score 60, got {penalized_score}"

        print("  [PASS] 2. Byzantine FORGER detected: ballot dropped, signature audit failed, docked 40 trust points!")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_safety_under_excessive_faults():
    """
    Proves that if faults exceed f (e.g. 1 Liar + 1 Silent node = only 3 active voters),
    the cluster safely halts/stalls without making an unverified commit.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        db = Database(os.path.join(temp_dir, "excessive_faults.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        cfg = NodeConfig()
        cfg.node_id = "fednode-0"

        engine = ConsensusEngine(cfg, db, fw, rep)

        # Register 5 nodes
        keys = {"fednode-0": (cfg.private_key_hex, cfg.public_key_hex)}
        for i in range(1, 5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            engine.register_peer_key(nid, pub)

        prop = engine.create_proposal(
            target_domain="suspicious-domain.net",
            reason=pb2.REASON_SPAM,
            evidence_payload='{}',
            origin_http_signature="",
            threat_score=0.75
        )

        # Only 2 followers vote (Node 1 votes APPROVE, Node 2 votes APPROVE)
        # Node 3 is SILENT (crashed), Node 4 is a LIAR (votes REJECT)
        for i in [1, 2]:
            nid = f"fednode-{i}"
            meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": prop.target_domain,
                "decision": "APPROVE"
            }
            vote = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=prop.target_domain,
                voter_id=nid,
                decision=pb2.VOTE_APPROVE,
                voter_signature=sign_message(keys[nid][0], meta),
                timestamp=int(time.time() * 1000)
            )
            qc = engine.handle_vote(vote)

        # Total approve votes = 3 (Leader + Node 1 + Node 2) < Q=4
        assert qc is None, "Cluster must NOT commit when total approve votes < Q=4!"
        assert fw.is_blocked("suspicious-domain.net") is False

        print("  [PASS] 3. Safety preserved under excessive faults: cluster safely stalls without illegal commits!")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def run_all_byzantine_tests():
    print("\n=======================================================")
    print("   FEDCONSENSUS: BYZANTINE FAULT MASKING VERIFICATION  ")
    print("=======================================================")
    test_byzantine_liar_fault_masking()
    test_byzantine_forger_reputation_penalty()
    test_safety_under_excessive_faults()
    print("=======================================================")
    print("   ALL BYZANTINE FAULT RESILIENCE PROOFS PASS 100%!   ")
    print("=======================================================\n")


if __name__ == "__main__":
    run_all_byzantine_tests()
