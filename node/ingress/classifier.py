import re
import time
from typing import Dict, Any, List
from collections import defaultdict


class ThreatAssessment:
    """Encapsulates the evaluation result of an incoming ActivityPub post."""
    def __init__(self, score: float, reasons: List[str], dominant_reason_code: int):
        self.score = round(score, 3)
        self.reasons = reasons
        self.dominant_reason_code = dominant_reason_code
        self.is_threat = self.score >= 0.60

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "is_threat": self.is_threat,
            "reasons": self.reasons,
            "dominant_reason_code": self.dominant_reason_code
        }


class ThreatClassifier:
    """
    Multi-Feature Threat Classifier (Section 2 of Specification):
    Analyzes incoming ActivityPub traffic for burst velocity, malicious extensions,
    and phishing language. Triggers consensus escalation if threat score >= 0.60.
    """
    MALICIOUS_EXTENSIONS_REGEX = re.compile(
        r'\b[\w-]+\.(exe|scr|apk|zip|bat|cmd|vbs|ps1|msi)\b', 
        re.IGNORECASE
    )

    PHISHING_KEYWORDS = [
        "verify your account", "confirm password", "urgent security update",
        "billing suspension", "login here to avoid ban", "unauthorized access detected",
        "claim your reward immediately", "reset password link", "update payment details"
    ]

    def __init__(self, velocity_window_seconds: int = 10, burst_threshold: int = 5):
        self.window_seconds = velocity_window_seconds
        self.burst_threshold = burst_threshold
        # origin_domain -> list of request timestamps
        self._traffic_history: Dict[str, List[float]] = defaultdict(list)

    def analyze(self, domain: str, activity_payload: Dict[str, Any]) -> ThreatAssessment:
        now = time.time()
        reasons = []
        scores = []
        dominant_code = 1  # Default REASON_SPAM

        # 1. Message Velocity / Burst Rate (Bot detection)
        history = self._traffic_history[domain]
        # Prune timestamps older than our sliding window
        history = [t for t in history if now - t <= self.window_seconds]
        history.append(now)
        self._traffic_history[domain] = history

        burst_count = len(history)
        if burst_count >= self.burst_threshold:
            velocity_score = min(1.0, 0.40 + (burst_count - self.burst_threshold) * 0.15)
            scores.append(velocity_score)
            reasons.append(f"Bot flood detected: {burst_count} requests in {self.window_seconds}s")
            dominant_code = 2  # REASON_BOTNET

        # 2. Extract Text & Attachments from ActivityStreams JSON-LD
        text_content = ""
        attachment_urls = []

        obj = activity_payload.get("object", {})
        if isinstance(obj, dict):
            text_content = str(obj.get("content", "")) + " " + str(obj.get("summary", ""))
            attachments = obj.get("attachment", [])
            if isinstance(attachments, list):
                for att in attachments:
                    if isinstance(att, dict) and "url" in att:
                        attachment_urls.append(str(att["url"]))
        elif isinstance(obj, str):
            text_content = obj

        full_inspect_text = f"{text_content} {' '.join(attachment_urls)}"

        # 3. Malicious Executable / Archive Extension Check
        malicious_files = self.MALICIOUS_EXTENSIONS_REGEX.findall(full_inspect_text)
        if malicious_files:
            file_score = 0.85
            scores.append(file_score)
            reasons.append(f"Malicious executable/archive extension found: {', '.join(set(malicious_files))}")
            dominant_code = 4  # REASON_MALICIOUS_FILES

        # 4. Phishing / Credential Theft Language Check
        lower_text = full_inspect_text.lower()
        phishing_hits = [kw for kw in self.PHISHING_KEYWORDS if kw in lower_text]
        if phishing_hits:
            phishing_score = min(0.95, 0.50 + len(phishing_hits) * 0.20)
            scores.append(phishing_score)
            reasons.append(f"Phishing language detected: {', '.join(phishing_hits)}")
            dominant_code = 3  # REASON_PHISHING

        # Calculate final threat score
        final_score = max(scores) if scores else 0.05
        return ThreatAssessment(final_score, reasons, dominant_code)