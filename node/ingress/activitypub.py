import json
from urllib.parse import urlparse
from typing import Dict, Any, Tuple, Optional, Callable
from node.ingress.firewall import FirewallFilter
from node.ingress.classifier import ThreatClassifier, ThreatAssessment


class ActivityPubInbox:
    """
    W3C ActivityPub /inbox Middleware (Section 2 of Specification):
    Ingests and parses standard ActivityStreams JSON-LD payloads.
    Enforces perimeter firewall filtering, threat scoring, and automated
    escalation to the BFT consensus engine.
    """
    def __init__(
        self,
        firewall: FirewallFilter,
        classifier: ThreatClassifier,
        on_threat_detected: Optional[Callable[[str, Dict[str, Any], ThreatAssessment], None]] = None
    ):
        self.firewall = firewall
        self.classifier = classifier
        self.on_threat_detected = on_threat_detected

    def extract_origin_domain(self, payload: Dict[str, Any]) -> str:
        """
        Extracts the origin domain from ActivityStreams 'actor' or 'id' URI.
        Example: 'https://spam-botnet.net/users/bot1' -> 'spam-botnet.net'
        """
        actor_uri = str(payload.get("actor", "") or payload.get("id", ""))
        if actor_uri.startswith("http"):
            parsed = urlparse(actor_uri)
            if parsed.netloc:
                return parsed.netloc.lower()
        
        # Fallback to direct 'origin_domain' field if present
        return str(payload.get("origin_domain", "unknown-domain")).lower()

    def process_inbox_post(self, raw_json_str: str) -> Tuple[int, Dict[str, Any]]:
        """
        Main ingress pipeline processing incoming /inbox traffic:
        Returns: (HTTP_STATUS_CODE, RESPONSE_JSON)
        """
        try:
            payload = json.loads(raw_json_str) if isinstance(raw_json_str, str) else raw_json_str
        except Exception:
            return 400, {"error": "Invalid ActivityStreams JSON payload"}

        # 1. Extract Sender Domain
        domain = self.extract_origin_domain(payload)

        # 2. Perimeter Firewall Lookup (Sub-microsecond O(1))
        if self.firewall.is_blocked(domain):
            return 403, {
                "error": "Forbidden: Domain has been defederated by cluster consensus",
                "domain": domain,
                "status": "BLOCKED"
            }

        # 3. Multi-Feature Threat Classifier Analysis
        assessment = self.classifier.analyze(domain, payload)

        # 4. Automated Escalation Trigger (Score >= 0.60)
        if assessment.is_threat:
            # Trigger callback to BFT Consensus Engine if configured
            if self.on_threat_detected:
                self.on_threat_detected(domain, payload, assessment)

            return 403, {
                "status": "FLAGGED_FOR_CONSENSUS",
                "domain": domain,
                "threat_score": assessment.score,
                "dominant_reason_code": assessment.dominant_reason_code,
                "reasons": assessment.reasons
            }

        # 5. Safe Traffic Delivery
        return 202, {
            "status": "ACCEPTED",
            "domain": domain,
            "threat_score": assessment.score,
            "message": "Activity accepted and queued for social feed"
        }
