"""
Automated Verification Suite for End-to-End Chaos Scenarios
Tests:
  1. Complete Ingress-to-Commit Lifecycle (Benign Post -> Attack -> Quorum -> Firewall Block)
  2. Crash & Self-Healing Catch-up Replay across container lifecycles
  3. Anti-Framing Defense against fabricated evidence
"""
import os
import sys
import json
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
from node.ingress.classifier import ThreatClassifier
from node.ingress.activitypub import ActivityPubInbox
from node.engine.consensus import ConsensusEngine
from node.engine.catchup import CatchupEngine
from node.crypto.ed25519 import generate_keypair, sign_message
from node.crypto.http_sig import create_origin_http_signature, verify_origin_http_signature


def test_scenario_end_to_end_moderation_lifecycle():
    """
    Simulates:
    1. Benign post arrives -> Accepted (HTTP 202)
    2. Malicious phishing post arrives -> Classifier triggers automated BFT proposal
    3. 4 honest nodes vote -> Quorum Proof minted -> Ban committed to WAL & Firewall
    4. Attacker tries again -> In-memory firewall drops immediately (HTTP 403)
    """
    temp_dir = tempfile.mkdtemp()
    try:
        db = Database(os.path.join(temp_dir, "scenario_lifecycle.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        classifier = ThreatClassifier()
        consensus = ConsensusEngine(cfg, db, fw, rep)

        # Setup 5 nodes
        keys = {"fednode-0": (cfg.private_key_hex, cfg.public_key_hex)}
        for i in range(1, 5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            consensus.register_peer_key(nid, pub)

        # Wire ActivityPub inbox with 3-parameter callback
        proposals_triggered = []
        def on_threat(domain, payload, assessment):
            prop = consensus.create_proposal(
                target_domain=domain,
                reason=assessment.dominant_reason_code,
                evidence_payload=json.dumps(payload),
                origin_http_signature="",
                threat_score=assessment.score
            )
            proposals_triggered.append(prop)

        inbox = ActivityPubInbox(firewall=fw, classifier=classifier, on_threat_detected=on_threat)

        # 1. Benign Post arrives from innocent user
        benign_json = json.dumps({
            "actor": "https://happy-community.org/users/alice",
            "object": {"content": "Hello friends! Beautiful sunny day today in Glasgow."}
        })
        status, resp = inbox.process_inbox_post(benign_json)
        assert status == 202
        assert resp["status"] == "ACCEPTED"
        assert len(proposals_triggered) == 0

        # 2. Attack arrives: Phishing + Malware payload
        attack_json = json.dumps({
            "actor": "https://evil-phish.net/users/scammer",
            "object": {
                "content": "urgent security update: verify your account immediately at http://evil-phish.net",
                "attachment": [{"url": "https://evil-phish.net/malware.exe"}]
            }
        })
        status, resp = inbox.process_inbox_post(attack_json)
        assert status == 403
        assert resp["status"] == "FLAGGED_FOR_CONSENSUS"
        assert len(proposals_triggered) == 1

        # 3. Complete BFT voting round
        prop = proposals_triggered[0]
        for i in range(1, 4):
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
            qc = consensus.handle_vote(vote)

        assert qc is not None, "Quorum Certificate must be minted!"
        consensus.commit_defederation(qc)

        # 4. Attacker attempts to send another post 1 second later -> Dropped by Firewall in RAM!
        status_subsequent, resp_subsequent = inbox.process_inbox_post(attack_json)
        assert status_subsequent == 403
        assert resp_subsequent["status"] == "BLOCKED"

        print("  [PASS] 1. Complete Moderation Lifecycle verified: Ingress -> Detection -> BFT Vote -> Firewall Drop!")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_scenario_crash_and_self_healing_catchup():
    """
    Simulates node crash, state divergence while offline, and cryptographic catch-up recovery.
    """
    temp_dir_cluster = tempfile.mkdtemp()
    temp_dir_crashed = tempfile.mkdtemp()
    try:
        # Healthy cluster database
        db_cluster = Database(os.path.join(temp_dir_cluster, "cluster.db"))
        fw_cluster = FirewallFilter(db_cluster)
        cfg_cluster = NodeConfig()
        cfg_cluster.node_id = "fednode-0"
        engine_cluster = CatchupEngine(cfg_cluster, db_cluster, fw_cluster)

        # Keys
        keys = {}
        for i in range(5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            engine_cluster.register_peer_key(nid, pub)

        # Cluster commits 2 bans
        for seq, domain in [(1, "spam-1.net"), (2, "malware-2.org")]:
            sigs = []
            for nid, (priv, _) in list(keys.items())[:4]:
                meta = {
                    "proposal_id": f"prop-1-{seq}-{domain}",
                    "sequence_number": seq,
                    "epoch": 1,
                    "target_domain": domain,
                    "decision": "APPROVE"
                }
                sigs.append({"voter_id": nid, "signature": sign_message(priv, meta), "timestamp": 1000})

            db_cluster.save_commit_record(
                sequence_number=seq,
                epoch=1,
                target_domain=domain,
                reason=pb2.REASON_BOTNET,
                quorum_proof={"proposal_id": f"prop-1-{seq}-{domain}", "signatures": sigs, "finalized_at": 1000}
            )

        # Crashed node wakes up (starts empty at seq 0)
        db_crashed = Database(os.path.join(temp_dir_crashed, "crashed.db"))
        fw_crashed = FirewallFilter(db_crashed)
        cfg_crashed = NodeConfig()
        cfg_crashed.node_id = "fednode-4"
        engine_crashed = CatchupEngine(cfg_crashed, db_crashed, fw_crashed)

        for nid, (_, pub) in keys.items():
            engine_crashed.register_peer_key(nid, pub)

        assert db_crashed.get_latest_sequence_number() == 0
        assert fw_crashed.is_blocked("malware-2.org") is False

        # Waking node calls CatchupRequest
        req = pb2.CatchupRequest(node_id="fednode-4", from_sequence_number=1)
        res = engine_cluster.handle_catchup_request(req)
        assert len(res.records) == 2

        # Replay records locally
        replayed = engine_crashed.replay_records(list(res.records))
        assert replayed == 2
        assert db_crashed.get_latest_sequence_number() == 2
        assert fw_crashed.is_blocked("spam-1.net") is True
        assert fw_crashed.is_blocked("malware-2.org") is True

        print("  [PASS] 2. Crash & Self-Healing Catch-up verified: 2 missed bans audited and replayed into SQLite WAL & RAM!")

    finally:
        shutil.rmtree(temp_dir_cluster, ignore_errors=True)
        shutil.rmtree(temp_dir_crashed, ignore_errors=True)


def test_scenario_anti_framing_protection():
    """
    Proves that a rogue node trying to frame an innocent server is thwarted
    because it cannot forge the accused server's origin HTTP signature.
    """
    innocent_priv, innocent_pub = generate_keypair()
    known_pubkeys = {"innocent-community.org": innocent_pub}

    # 1. Genuine Post from innocent server
    genuine_payload = {"actor": "https://innocent-community.org/users/bob", "content": "Good morning everyone!"}
    genuine_sig = create_origin_http_signature("innocent-community.org", genuine_payload, innocent_priv)

    is_valid = verify_origin_http_signature(
        accused_domain="innocent-community.org",
        evidence_payload_json=json.dumps(genuine_payload),
        origin_signature_info=genuine_sig,
        known_domain_public_keys=known_pubkeys
    )
    assert is_valid is True, "Genuine signature must verify!"

    # 2. Rogue Leader fabricates a fake abusive payload and attributes it to innocent-community.org
    rogue_priv, _ = generate_keypair()
    fake_abusive_payload = {
        "actor": "https://innocent-community.org/users/bob",
        "content": "CLICK HERE FOR FREE BITCOIN SCAM LINK"
    }
    # Rogue node signs with its OWN key (it doesn't have innocent_priv)
    fake_sig = create_origin_http_signature("innocent-community.org", fake_abusive_payload, rogue_priv)

    framing_detected = verify_origin_http_signature(
        accused_domain="innocent-community.org",
        evidence_payload_json=json.dumps(fake_abusive_payload),
        origin_signature_info=fake_sig,
        known_domain_public_keys=known_pubkeys
    )
    assert framing_detected is False, "Framing attack must be detected and rejected!"

    print("  [PASS] 3. Anti-Framing Defense verified: fabricated evidence rejected by origin signature audit!")


def run_all_scenarios():
    print("\n=======================================================")
    print("   FEDCONSENSUS: END-TO-END SCENARIOS VERIFICATION    ")
    print("=======================================================")
    test_scenario_end_to_end_moderation_lifecycle()
    test_scenario_crash_and_self_healing_catchup()
    test_scenario_anti_framing_protection()
    print("=======================================================")
    print("   ALL END-TO-END SCENARIO CHAOS TESTS PASS 100%!     ")
    print("=======================================================\n")


if __name__ == "__main__":
    run_all_scenarios()