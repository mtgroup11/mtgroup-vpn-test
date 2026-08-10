"""
MTGroup VPN Ultimate — AI Anomaly Engine Test Suite
Tests backend/app/core/ai_detector.py's LightweightRNN (pure NumPy, no
mocking needed) and AnomalyPredictor's collection/scoring/alerting logic
with a fake BCC map (no real kernel/eBPF needed) and the RNN's own
forward() monkeypatched to a fixed score where a deterministic trigger
is needed.
"""

from __future__ import annotations

import socket
import struct
from unittest.mock import AsyncMock, MagicMock

import numpy as np
import pytest

from backend.app.core.ai_detector import AnomalyPredictor, LightweightRNN


def _ip_key(ip: str):
    packed = socket.inet_aton(ip)
    value = struct.unpack("<I", packed)[0]
    return MagicMock(value=value)


def _fake_bpf_with_map(entries: dict[str, int]):
    """entries: {ip: byte_count} -> fake object with .get_table()."""
    table = [(_ip_key(ip), MagicMock(value=count)) for ip, count in entries.items()]
    bpf = MagicMock()
    bpf.get_table.return_value.items.return_value = table
    return bpf


class TestLightweightRNN:
    def test_forward_returns_value_in_sigmoid_range(self):
        rnn = LightweightRNN(input_size=2, hidden_size=8, output_size=1)
        sequence = [[float(i), float(i) * 0.5] for i in range(10)]
        score = rnn.forward(sequence)
        assert 0.0 <= score <= 1.0

    def test_forward_is_deterministic_for_fixed_weights(self):
        rnn = LightweightRNN(input_size=2, hidden_size=4, output_size=1)
        sequence = [[1.0, 2.0], [3.0, 4.0]]
        assert rnn.forward(sequence) == rnn.forward(sequence)

    def test_sigmoid_does_not_overflow_on_extreme_input(self):
        rnn = LightweightRNN(input_size=1, hidden_size=1, output_size=1)
        # Must not raise/warn on overflow — the clip(-500, 500) guard exists
        # precisely because unclipped exp() of a large negative input
        # overflows.
        result = rnn._sigmoid(np.array([[-10000.0]]))
        assert 0.0 <= result[0, 0] <= 1.0
        result2 = rnn._sigmoid(np.array([[10000.0]]))
        assert 0.0 <= result2[0, 0] <= 1.0


@pytest.fixture
def predictor():
    return AnomalyPredictor(sequence_length=3)


class TestSendTelegramAlert:
    @pytest.mark.asyncio
    async def test_noop_without_credentials(self, predictor, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_ADMIN_ID", raising=False)
        # If it tried to call httpx it would fail (no mock installed) — a
        # clean return with no exception confirms the early-exit path.
        await predictor._send_telegram_alert("203.0.113.1", 0.95)

    @pytest.mark.asyncio
    async def test_masks_last_octet(self, predictor, monkeypatch):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
        monkeypatch.setenv("TELEGRAM_ADMIN_ID", "12345")

        captured = {}

        class _FakeResponse:
            pass

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, json=None):
                captured["url"] = url
                captured["json"] = json
                return _FakeResponse()

        monkeypatch.setattr("backend.app.core.ai_detector.httpx.AsyncClient", lambda timeout=5.0: _FakeClient())

        await predictor._send_telegram_alert("203.0.113.42", 0.987)

        assert "203.0.113.xxx" in captured["json"]["text"]
        assert "203.0.113.42" not in captured["json"]["text"]

    @pytest.mark.asyncio
    async def test_send_failure_is_caught_not_raised(self, predictor, monkeypatch):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
        monkeypatch.setenv("TELEGRAM_ADMIN_ID", "12345")

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, json=None):
                raise RuntimeError("network down")

        monkeypatch.setattr("backend.app.core.ai_detector.httpx.AsyncClient", lambda timeout=5.0: _FakeClient())
        await predictor._send_telegram_alert("203.0.113.1", 0.9)  # must not raise


class TestCollectAndPredict:
    @pytest.mark.asyncio
    async def test_noop_without_bpf(self, predictor):
        predictor._bpf = None
        await predictor._collect_and_predict()  # must not raise

    @pytest.mark.asyncio
    async def test_builds_history_without_triggering_below_sequence_length(self, predictor):
        predictor._bpf = _fake_bpf_with_map({"203.0.113.1": 1000})
        await predictor._collect_and_predict()
        assert len(predictor.ip_history["203.0.113.1"]) == 1

    @pytest.mark.asyncio
    async def test_history_capped_at_sequence_length(self, predictor):
        predictor._bpf = MagicMock()
        for i in range(6):
            predictor._bpf.get_table.return_value.items.return_value = [
                (_ip_key("203.0.113.1"), MagicMock(value=1000 * (i + 1)))
            ]
            await predictor._collect_and_predict()
        assert len(predictor.ip_history["203.0.113.1"]) == predictor.sequence_length

    @pytest.mark.asyncio
    async def test_negative_delta_from_map_clear_is_treated_as_absolute(self, predictor):
        """If the kernel map was reset (e.g. process restart), byte counts
        can drop below the last-seen value — this must be treated as a
        fresh absolute count, not underflow into a huge negative delta
        that would corrupt the anomaly score."""
        predictor._bpf = MagicMock()
        predictor._bpf.get_table.return_value.items.return_value = [(_ip_key("203.0.113.1"), MagicMock(value=100000))]
        await predictor._collect_and_predict()

        predictor._bpf.get_table.return_value.items.return_value = [(_ip_key("203.0.113.1"), MagicMock(value=500))]
        await predictor._collect_and_predict()

        # delta should be 500 (absolute), not 500 - 100000 (negative)
        last_features = predictor.ip_history["203.0.113.1"][-1]
        assert last_features[0] == pytest.approx(500 / 1000.0)

    @pytest.mark.asyncio
    async def test_triggers_security_alert_when_score_exceeds_adaptive_threshold(self, predictor, monkeypatch):
        # `forward()` is only actually invoked once `ip_history` has
        # reached `sequence_length` (3 here). The EMA baseline is *set to*
        # the score on its very first computation, and the adaptive
        # threshold is 1.5x the baseline — so a constant score can never
        # trigger (the threshold jumps above it immediately after the
        # first sample). A real spike needs a low score first (to
        # establish a low baseline) followed by a high one that exceeds
        # 1.5x that baseline.
        scores = iter([0.10, 0.99])
        monkeypatch.setattr(predictor.rnn, "forward", lambda seq: next(scores))
        alert_mock = AsyncMock()
        monkeypatch.setattr("backend.app.core.ai_detector.orchestrator.handle_security_alert", alert_mock)
        monkeypatch.setattr(predictor, "_send_telegram_alert", AsyncMock())

        predictor._bpf = MagicMock()
        # Calls 1-2 just build up history (len < sequence_length, no
        # scoring yet). Call 3 is the first scoring pass (sets baseline to
        # 0.10). Call 4 is the second scoring pass (score 0.99 vs.
        # threshold max(0.80, 0.10*1.5)=0.80 -> triggers).
        for i in range(4):
            predictor._bpf.get_table.return_value.items.return_value = [
                (_ip_key("203.0.113.9"), MagicMock(value=1000 * (i + 1)))
            ]
            await predictor._collect_and_predict()

        alert_mock.assert_awaited_once()
        assert alert_mock.await_args.args[0] == "203.0.113.9"
        # State must reset after a trigger so the same burst doesn't
        # re-fire on every subsequent poll.
        assert predictor.ip_history["203.0.113.9"] == []
        assert predictor.ip_baseline["203.0.113.9"] == 0.0

    @pytest.mark.asyncio
    async def test_low_score_never_triggers_alert(self, predictor, monkeypatch):
        monkeypatch.setattr(predictor.rnn, "forward", lambda seq: 0.01)
        alert_mock = AsyncMock()
        monkeypatch.setattr("backend.app.core.ai_detector.orchestrator.handle_security_alert", alert_mock)

        predictor._bpf = MagicMock()
        for i in range(predictor.sequence_length):
            predictor._bpf.get_table.return_value.items.return_value = [
                (_ip_key("203.0.113.10"), MagicMock(value=1000 * (i + 1)))
            ]
            await predictor._collect_and_predict()

        alert_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_bpf_map_read_error_raises_runtime_error(self, predictor):
        predictor._bpf = MagicMock()
        predictor._bpf.get_table.side_effect = RuntimeError("kernel map gone")
        with pytest.raises(RuntimeError):
            await predictor._collect_and_predict()


class TestInitBcc:
    def test_noop_when_bcc_unavailable(self, predictor, monkeypatch):
        monkeypatch.setattr("backend.app.core.ai_detector.HAS_BCC", False)
        predictor._init_bcc()
        assert predictor._bpf is None


class TestMonitoringLoopBackoff:
    @pytest.mark.asyncio
    async def test_backoff_doubles_on_repeated_failure_and_resets_on_success(self, predictor, monkeypatch):
        sleep_calls = []

        async def _fake_sleep(seconds):
            sleep_calls.append(seconds)
            if len(sleep_calls) >= 4:
                predictor._is_running = False

        monkeypatch.setattr("backend.app.core.ai_detector.asyncio.sleep", _fake_sleep)

        call_count = 0

        async def _fake_collect():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise RuntimeError("boom")
            # third call succeeds, resetting backoff before the loop stops

        monkeypatch.setattr(predictor, "_collect_and_predict", _fake_collect)

        predictor._is_running = True
        import asyncio
        await asyncio.wait_for(predictor._monitoring_loop(), timeout=5.0)

        # First two failures: backoff 5.0, then 10.0. Third call succeeds
        # and sleeps the normal 5.0s cycle delay.
        assert sleep_calls[0] == 5.0
        assert sleep_calls[1] == 10.0
        assert sleep_calls[2] == 5.0


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_stop_is_clean(self, predictor, monkeypatch):
        monkeypatch.setattr("backend.app.core.ai_detector.HAS_BCC", False)
        await predictor.start()
        assert predictor._is_running is True
        await predictor.stop()
        assert predictor._is_running is False
