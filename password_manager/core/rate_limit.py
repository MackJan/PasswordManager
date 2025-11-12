"""Utility helpers for enforcing application-specific rate limits."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional, Tuple

from django.core.cache import cache


@dataclass
class RateLimitResult:
    """Represents the outcome of a rate limiting check."""

    allowed: bool
    remaining: Optional[int]
    retry_after: int
    blocked: bool
    limit: int
    count: int
    identifier: str


class RateLimitScenario:
    """Canonical identifiers for rate limited actions."""

    LOGIN_IP = "auth:login:ip"
    LOGIN_EMAIL = "auth:login:email"
    PASSWORD_RESET_IP = "auth:password-reset:ip"
    PASSWORD_RESET_EMAIL = "auth:password-reset:email"
    RECOVERY_CODE_IP = "auth:recovery:ip"
    RECOVERY_CODE_EMAIL = "auth:recovery:email"
    MALICIOUS_TRAFFIC_IP = "security:malicious:ip"


def _cache_keys(scenario: str, identifier: str) -> Tuple[str, str]:
    """Return the cache keys for the counter and block flag."""

    base_key = f"rate-limit:{scenario}:{identifier}"
    return base_key, f"{base_key}:blocked"


def _normalize_identifier(identifier: Optional[str]) -> Optional[str]:
    """Ensure identifiers are cache friendly and non-empty."""

    if not identifier:
        return None
    value = identifier.strip()
    if not value:
        return None
    return value.lower()


def is_rate_limited(scenario: str, identifier: Optional[str]) -> RateLimitResult:
    """Check whether the identifier is currently blocked for the scenario."""

    normalized = _normalize_identifier(identifier)
    if not normalized:
        return RateLimitResult(True, None, 0, False, 0, 0, identifier or "")

    _, block_key = _cache_keys(scenario, normalized)
    block_until = cache.get(block_key)
    now = time.time()
    if block_until and block_until > now:
        retry_after = max(int(block_until - now), 0)
        return RateLimitResult(False, 0, retry_after, True, 0, 0, normalized)

    return RateLimitResult(True, None, 0, False, 0, 0, normalized)


def increment_rate_limit(
    scenario: str,
    identifier: Optional[str],
    *,
    limit: int,
    window: int,
    block: Optional[int] = None,
) -> RateLimitResult:
    """Increment the rate limit counter for the identifier."""

    normalized = _normalize_identifier(identifier)
    if not normalized:
        return RateLimitResult(True, None, 0, False, limit, 0, identifier or "")

    key, block_key = _cache_keys(scenario, normalized)
    now = time.time()

    block_until = cache.get(block_key)
    if block_until and block_until > now:
        retry_after = max(int(block_until - now), 0)
        return RateLimitResult(False, 0, retry_after, True, limit, limit, normalized)

    data = cache.get(key)
    if not data or now >= data.get("expires_at", 0):
        count = 0
        expires_at = now + window
    else:
        count = int(data.get("count", 0))
        expires_at = float(data.get("expires_at", now + window))

    if count >= limit:
        block_for = block or window
        block_until = now + block_for
        cache.set(block_key, block_until, timeout=max(int(block_for), 1))
        cache.delete(key)
        retry_after = max(int(block_until - now), 0)
        return RateLimitResult(False, 0, retry_after, True, limit, count, normalized)

    count += 1
    ttl = max(int(expires_at - now), 1)
    cache.set(key, {"count": count, "expires_at": expires_at}, timeout=ttl)
    remaining = max(limit - count, 0)
    retry_after = max(int(expires_at - now), 0)
    return RateLimitResult(True, remaining, retry_after, False, limit, count, normalized)


def reset_rate_limit(scenario: str, identifier: Optional[str]) -> None:
    """Clear counters and block state for the identifier."""

    normalized = _normalize_identifier(identifier)
    if not normalized:
        return
    key, block_key = _cache_keys(scenario, normalized)
    cache.delete(key)
    cache.delete(block_key)


def get_rate_limit_state(scenario: str, identifier: Optional[str]) -> RateLimitResult:
    """Return the current state without incrementing counters."""

    normalized = _normalize_identifier(identifier)
    if not normalized:
        return RateLimitResult(True, None, 0, False, 0, 0, identifier or "")

    key, block_key = _cache_keys(scenario, normalized)
    now = time.time()

    block_until = cache.get(block_key)
    if block_until and block_until > now:
        retry_after = max(int(block_until - now), 0)
        return RateLimitResult(False, 0, retry_after, True, 0, 0, normalized)

    data = cache.get(key)
    if not data:
        return RateLimitResult(True, None, 0, False, 0, 0, normalized)

    count = int(data.get("count", 0))
    expires_at = float(data.get("expires_at", now))
    remaining_time = max(int(expires_at - now), 0)
    return RateLimitResult(True, None, remaining_time, False, 0, count, normalized)


__all__ = [
    "RateLimitResult",
    "RateLimitScenario",
    "increment_rate_limit",
    "is_rate_limited",
    "reset_rate_limit",
    "get_rate_limit_state",
]
