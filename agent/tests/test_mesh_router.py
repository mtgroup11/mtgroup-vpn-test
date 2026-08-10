"""
MTGroup VPN Ultimate — Mesh Router Packet-Loss Detection Tests
Verifies the /proc/net/snmp-based TCP retransmit packet-loss estimate
that replaced the previous hardcoded `_get_mock_packet_loss() -> 0.01`.
"""

from __future__ import annotations

from agent.mesh_router import MeshRouter


class TestReadTcpRetransCounters:
    def test_returns_none_when_proc_file_missing(self, monkeypatch):
        def _raise(*a, **kw):
            raise OSError("no such file")

        monkeypatch.setattr("builtins.open", _raise)
        assert MeshRouter._read_tcp_retrans_counters() is None

    def test_parses_well_formed_snmp_output(self, monkeypatch, tmp_path):
        snmp = tmp_path / "snmp"
        snmp.write_text(
            "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens "
            "AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs "
            "InErrs OutRsts InCsumErrors\n"
            "Tcp: 1 200 120000 -1 10 5 0 0 3 1000 900 42 0 0 0\n"
        )
        monkeypatch.setattr("agent.mesh_router._PROC_NET_SNMP", str(snmp))
        result = MeshRouter._read_tcp_retrans_counters()
        assert result == (42, 900)

    def test_returns_none_on_malformed_output(self, monkeypatch, tmp_path):
        snmp = tmp_path / "snmp"
        snmp.write_text("garbage that is not proc/net/snmp formatted\n")
        monkeypatch.setattr("agent.mesh_router._PROC_NET_SNMP", str(snmp))
        assert MeshRouter._read_tcp_retrans_counters() is None


class TestGetPacketLoss:
    def test_no_baseline_returns_zero_on_first_sample(self, monkeypatch):
        router = MeshRouter()
        monkeypatch.setattr(router, "_read_tcp_retrans_counters", lambda: (10, 1000))
        assert router._get_packet_loss() == 0.0
        # Baseline is now recorded for the next call.
        assert router._last_tcp_counters == (10, 1000)

    def test_computes_ratio_from_delta_between_polls(self, monkeypatch):
        router = MeshRouter()
        counters = [(10, 1000), (60, 1500)]  # +50 retrans over +500 sent

        def _fake():
            return counters.pop(0)

        monkeypatch.setattr(router, "_read_tcp_retrans_counters", _fake)
        router._get_packet_loss()  # establishes baseline
        loss = router._get_packet_loss()
        assert loss == 50 / 500

    def test_unavailable_platform_returns_zero_never_none(self, monkeypatch):
        router = MeshRouter()
        monkeypatch.setattr(router, "_read_tcp_retrans_counters", lambda: None)
        assert router._get_packet_loss() == 0.0

    def test_counter_reset_or_wraparound_does_not_go_negative(self, monkeypatch):
        """If the kernel counters reset (e.g. counter wraparound, though
        practically unlikely for 64-bit-ish uptimes) a negative delta must
        never be reported as loss."""
        router = MeshRouter()
        counters = [(1000, 50000), (10, 100)]  # counters went backwards

        def _fake():
            return counters.pop(0)

        monkeypatch.setattr(router, "_read_tcp_retrans_counters", _fake)
        router._get_packet_loss()
        loss = router._get_packet_loss()
        assert loss == 0.0
