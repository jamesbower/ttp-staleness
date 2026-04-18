from __future__ import annotations

from datetime import UTC, datetime

from .models import AttackIndex


def build_index(domain: str, ttl_hours: int) -> AttackIndex:
    """Fetch and index an ATT&CK domain bundle.

    Stub: real implementation will use mitreattack-python + DiskCache. The
    signature and return type are stable.
    """
    _ = (domain, ttl_hours)
    return AttackIndex(fetched_at=datetime(1970, 1, 1, tzinfo=UTC))
