import threading
from typing import Set
from node.storage.database import Database


class FirewallFilter:
    """
    Perimeter Firewall Filtering (Section 2 of Specification):
    Sub-microsecond in-memory lookup to instantly drop traffic from previously
    banned domains with HTTP 403 before executing application logic.
    """
    def __init__(self, db: Database):
        self.db = db
        self._lock = threading.Lock()
        self._blocked_domains: Set[str] = set()
        self.reload_rules()

    def reload_rules(self):
        """Loads all committed bans from SQLite into the in-memory lookup table."""
        with self._lock:
            self._blocked_domains = self.db.get_all_blocked_domains()

    def is_blocked(self, domain: str) -> bool:
        """
        Sub-microsecond O(1) in-memory check.
        Normalizes domain string (strips whitespace and converts to lowercase).
        """
        clean_domain = domain.strip().lower()
        with self._lock:
            return clean_domain in self._blocked_domains

    def block_domain(self, domain: str):
        """Immediately adds domain to in-memory filter without waiting for reboot."""
        clean_domain = domain.strip().lower()
        with self._lock:
            self._blocked_domains.add(clean_domain)

    def get_blocked_domains(self) -> Set[str]:
        """Returns a snapshot copy of all currently blocked domains."""
        with self._lock:
            return set(self._blocked_domains)

    def count(self) -> int:
        """Returns total count of actively blocked domains."""
        with self._lock:
            return len(self._blocked_domains)
