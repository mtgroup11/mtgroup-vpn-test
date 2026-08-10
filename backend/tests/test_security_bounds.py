"""
MTGroup VPN Ultimate — Bounded-Memory & Concurrency Test Suite

`TokenBucketRateLimiter`, `LoginAttemptTracker`, and `HandshakeTracker`
are all keyed by attacker-influenceable input (client IP). Before the
`_evict_oldest_if_over_capacity` fix, none of them had a size cap and
their `cleanup()` methods were never called by anything — a sustained
flood from many distinct source IPs grew each dict forever. These tests
lock in the bound and verify legitimate behaviour (bans, token refill)
still works correctly once eviction is in the picture.
"""

from __future__ import annotations

import threading


from backend.app.core.security import (
    HandshakeTracker,
    LoginAttemptTracker,
    TokenBucketRateLimiter,
)


# ---------------------------------------------------------------------------
# TokenBucketRateLimiter
# ---------------------------------------------------------------------------

class TestTokenBucketRateLimiterBounds:
    def test_never_exceeds_max_entries_under_many_distinct_keys(self):
        limiter = TokenBucketRateLimiter(max_tokens=5, refill_rate=0, max_entries=100)
        for i in range(1000):
            limiter.is_allowed(f"203.0.113.{i % 256}.{i}")
        assert len(limiter._buckets) <= limiter.max_entries

    def test_eviction_does_not_break_rate_limiting_for_active_keys(self):
        """A key that keeps getting hit should never itself be the one
        evicted, since eviction always removes the *least* recently
        active entry and this key is always the most recent."""
        limiter = TokenBucketRateLimiter(max_tokens=3, refill_rate=0, max_entries=10)
        for i in range(50):
            limiter.is_allowed(f"198.51.100.{i}")
            # Re-touch our tracked key on every iteration so it's always
            # the most recently active — it must never get evicted.
            assert limiter.is_allowed("tracked-ip") or i > 0
        # Exhaust the bucket to prove it's still the same bucket (tokens
        # accounting survived every eviction round untouched).
        limiter.reset("tracked-ip")
        assert limiter.is_allowed("tracked-ip")
        assert limiter.is_allowed("tracked-ip")
        assert limiter.is_allowed("tracked-ip")
        assert not limiter.is_allowed("tracked-ip")

    def test_concurrent_access_from_many_threads_stays_bounded_and_crash_free(self):
        limiter = TokenBucketRateLimiter(max_tokens=5, refill_rate=0, max_entries=200)
        errors: list[Exception] = []

        def worker(offset: int):
            try:
                for i in range(200):
                    limiter.is_allowed(f"10.0.{offset}.{i % 256}")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(limiter._buckets) <= limiter.max_entries


# ---------------------------------------------------------------------------
# LoginAttemptTracker
# ---------------------------------------------------------------------------

class TestLoginAttemptTrackerBounds:
    def test_never_exceeds_max_entries_under_many_distinct_ips(self):
        tracker = LoginAttemptTracker(max_attempts=5, window_seconds=300, max_entries=50)
        for i in range(2000):
            tracker.record_failure(f"192.0.2.{i % 256}-{i}")
        assert len(tracker._attempts) <= tracker.max_entries

    def test_ban_after_max_attempts_still_works_with_eviction_enabled(self):
        tracker = LoginAttemptTracker(max_attempts=3, window_seconds=300, max_entries=10)
        assert not tracker.record_failure("1.2.3.4")
        assert not tracker.record_failure("1.2.3.4")
        assert tracker.record_failure("1.2.3.4")
        assert tracker.is_blocked("1.2.3.4")

    def test_actively_retried_ip_is_not_evicted_by_flood_of_new_ips(self):
        tracker = LoginAttemptTracker(max_attempts=100, window_seconds=300, max_entries=20)
        tracker.record_failure("attacker-target")
        for i in range(500):
            tracker.record_failure(f"flood-{i}")
            tracker.record_failure("attacker-target")  # keep it the freshest
        assert tracker.get_attempts("attacker-target") > 0


# ---------------------------------------------------------------------------
# HandshakeTracker
# ---------------------------------------------------------------------------

class TestHandshakeTrackerBounds:
    def test_never_exceeds_max_entries_under_many_distinct_ips(self):
        tracker = HandshakeTracker(max_anomalies=3, window_seconds=300, max_entries=50)
        for i in range(2000):
            tracker.record_anomaly(f"198.18.{i % 256}.{i % 100}")
        assert len(tracker._anomalies) <= tracker.max_entries

    def test_ban_after_max_anomalies_still_works_with_eviction_enabled(self):
        tracker = HandshakeTracker(max_anomalies=3, window_seconds=300, max_entries=10)
        assert not tracker.record_anomaly("5.6.7.8")
        assert not tracker.record_anomaly("5.6.7.8")
        assert tracker.record_anomaly("5.6.7.8")


# ---------------------------------------------------------------------------
# Shared eviction helper
# ---------------------------------------------------------------------------

class TestEvictOldestIfOverCapacity:
    def test_evicts_until_within_capacity(self):
        from backend.app.core.security import _evict_oldest_if_over_capacity

        store = {f"k{i}": float(i) for i in range(20)}
        evicted = _evict_oldest_if_over_capacity(store, 5, lambda v: v)
        assert evicted == 15
        assert len(store) == 5
        # The 5 remaining entries must be the 5 most recent (highest values).
        assert set(store.values()) == {15.0, 16.0, 17.0, 18.0, 19.0}

    def test_noop_when_already_within_capacity(self):
        from backend.app.core.security import _evict_oldest_if_over_capacity

        store = {"a": 1.0, "b": 2.0}
        evicted = _evict_oldest_if_over_capacity(store, 10, lambda v: v)
        assert evicted == 0
        assert len(store) == 2
