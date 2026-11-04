"""
FedConsensus Operator CLI (fedctl)
Terminal management tool for cluster diagnostics, reputation inspection, and manual proposals.
"""
import sys
import argparse
import grpc
from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc


def get_stub(target: str = "localhost:50051"):
    """Creates a gRPC channel and client stub to the target node."""
    channel = grpc.insecure_channel(target)
    return pb2_grpc.FedConsensusServiceStub(channel)


def cmd_status(args):
    """Queries and displays node health, role, epoch, and blocked domain count."""
    stub = get_stub(args.target)
    try:
        res = stub.GetStatus(pb2.StatusRequest(caller_id="fedctl"), timeout=args.timeout)
        print("=======================================================")
        print(f"   FEDNODE TELEMETRY: {res.node_id}")
        print("=======================================================")
        print(f"  Role / State:        {res.state}")
        print(f"  Current Epoch:       {res.current_epoch}")
        print(f"  Last Committed Seq:  {res.last_committed_seq}")
        print(f"  Blocked Domains:     {res.blocked_domains_count}")
        print(f"  Operational Mode:    {res.operational_mode}")
        print("=======================================================\n")
        return 0
    except grpc.RpcError as e:
        print(f"[ERROR] Failed to reach node at {args.target}: {e.details() or e.code()}", file=sys.stderr)
        return 1


def cmd_peers(args):
    """Displays the peer trust scores and quarantine status in a formatted table."""
    stub = get_stub(args.target)
    try:
        res = stub.GetStatus(pb2.StatusRequest(caller_id="fedctl"), timeout=args.timeout)
        print("=========================================================================")
        print(f"   PEER REPUTATION LEDGER (Audited by {res.node_id})")
        print("=========================================================================")
        print(f"{'Peer ID':<15} | {'Trust Score':<12} | {'Violations':<12} | {'Status':<15}")
        print("-" * 73)

        if not res.reputations:
            print("  (No peer reputation records found)")
        else:
            for p in res.reputations:
                status = "QUARANTINED" if p.trust_score < 30 else ("ACTIVE" if p.is_active else "SUSPENDED")
                print(f"{p.peer_id:<15} | {p.trust_score:<12} | {p.violations_count:<12} | {status:<15}")
        print("=========================================================================\n")
        return 0
    except grpc.RpcError as e:
        print(f"[ERROR] Failed to reach node at {args.target}: {e.details() or e.code()}", file=sys.stderr)
        return 1


def cmd_propose(args):
    """Manually broadcasts a ban proposal against a malicious domain."""
    import time
    from node.crypto.ed25519 import generate_keypair, sign_message

    stub = get_stub(args.target)
    reason_code = getattr(pb2, f"REASON_{args.reason.upper()}", pb2.REASON_BOTNET)

    # Generate a temporary operator key to sign the manual proposal
    priv, pub = generate_keypair()
    now = int(time.time() * 1000)
    proposal_id = f"prop-manual-{args.domain}-{now}"

    meta = {
        "proposal_id": proposal_id,
        "sequence_number": 999,
        "epoch": 1,
        "target_domain": args.domain,
        "reason": reason_code,
        "threat_score": 0.95
    }
    signature = sign_message(priv, meta)

    req = pb2.ProposeRequest(
        proposal_id=proposal_id,
        sequence_number=999,
        epoch=1,
        target_domain=args.domain,
        reason=reason_code,
        evidence_payload=f'{{"reason": "{args.reason}", "operator": "fedctl"}}',
        threat_score=0.95,
        proposer_id="operator-fedctl",
        proposer_signature=signature,
        timestamp=now
    )

    try:
        res = stub.ProposeDefederation(req, timeout=args.timeout)
        print(f"[fedctl] Proposal dispatched to {args.target}: Accepted={res.accepted} (Reason: '{res.reason}')")
        return 0 if res.accepted else 1
    except grpc.RpcError as e:
        print(f"[ERROR] Propose failed on {args.target}: {e.details() or e.code()}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(prog="fedctl", description="FedConsensus Cluster Administrative CLI")
    parser.add_argument("--target", default="localhost:50051", help="Target node gRPC address (default: localhost:50051)")
    parser.add_argument("--timeout", type=float, default=3.0, help="RPC timeout in seconds")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: status
    subparsers.add_parser("status", help="Get node status and telemetry")

    # Command: peers
    subparsers.add_parser("peers", help="Inspect peer reputation ledger")

    # Command: propose
    prop_parser = subparsers.add_parser("propose", help="Manually propose defederation against a domain")
    prop_parser.add_argument("domain", help="Target domain to ban (e.g., spam-bot.net)")
    prop_parser.add_argument("--reason", default="BOTNET", choices=["SPAM", "BOTNET", "PHISHING", "MALICIOUS_FILES"], help="Violation category")

    args = parser.parse_args()

    if args.command == "status":
        sys.exit(cmd_status(args))
    elif args.command == "peers":
        sys.exit(cmd_peers(args))
    elif args.command == "propose":
        sys.exit(cmd_propose(args))


if __name__ == "__main__":
    main()
