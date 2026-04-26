"""
PyroWall Test Suite
Run with: python -m pytest tests/ -v
"""

import sys
import os

try:
    import pytest
except ImportError:
    pytest = None

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.firewall import Firewall
from core.packet import Packet
from core.state_table import StateTable, ConnectionState
from rules.rule_engine import RuleEngine, Rule, Action


# ================================================================== #
# Packet model tests                                                   #
# ================================================================== #

class TestPacket:
    def test_tcp_factory(self):
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 1234, 80, flags="SYN")
        assert p.protocol == "TCP"
        assert p.src_ip == "1.2.3.4"
        assert p.dst_port == 80
        assert p.is_syn()

    def test_udp_factory(self):
        p = Packet.udp("1.2.3.4", "5.6.7.8", 5353, 53)
        assert p.protocol == "UDP"
        assert p.dst_port == 53

    def test_icmp_factory(self):
        p = Packet.icmp("10.0.0.1", "10.0.0.2")
        assert p.protocol == "ICMP"

    def test_connection_key(self):
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 443)
        assert p.connection_key == ("1.1.1.1", 1000, "2.2.2.2", 443, "TCP")

    def test_reverse_key(self):
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 443)
        assert p.reverse_key == ("2.2.2.2", 443, "1.1.1.1", 1000, "TCP")

    def test_fin_flag(self):
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="FIN|ACK")
        assert p.is_fin()
        assert not p.is_syn()

    def test_rst_flag(self):
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="RST")
        assert p.is_rst()


# ================================================================== #
# Rule engine tests                                                    #
# ================================================================== #

class TestRuleEngine:
    def _engine(self):
        return RuleEngine(default_policy=Action.DENY)

    def test_allow_http(self):
        engine = self._engine()
        engine.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80)
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 80)
        action, rule = engine.evaluate(p)
        assert action == Action.ALLOW

    def test_deny_telnet(self):
        engine = self._engine()
        engine.add_rule(action=Action.DENY, protocol="TCP", dst_port=23)
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 23)
        action, _ = engine.evaluate(p)
        assert action == Action.DENY

    def test_default_deny(self):
        engine = self._engine()
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 9999)
        action, rule = engine.evaluate(p)
        assert action == Action.DENY
        assert rule is None

    def test_log_icmp(self):
        engine = self._engine()
        engine.add_rule(action=Action.LOG, protocol="ICMP")
        p = Packet.icmp("10.0.0.1", "10.0.0.2")
        action, _ = engine.evaluate(p)
        assert action == Action.LOG

    def test_cidr_match(self):
        engine = self._engine()
        engine.add_rule(action=Action.ALLOW, protocol="TCP",
                        src_network="192.168.0.0/16", dst_port=22)
        p = Packet.tcp("192.168.5.100", "10.0.0.1", 4444, 22)
        action, _ = engine.evaluate(p)
        assert action == Action.ALLOW

    def test_cidr_no_match(self):
        engine = self._engine()
        engine.add_rule(action=Action.ALLOW, protocol="TCP",
                        src_network="192.168.0.0/16", dst_port=22)
        p = Packet.tcp("10.0.0.1", "10.0.0.2", 4444, 22)
        action, _ = engine.evaluate(p)
        assert action == Action.DENY  # default

    def test_protocol_any(self):
        engine = self._engine()
        engine.add_rule(action=Action.ALLOW, protocol="ANY", dst_network="127.0.0.0/8")
        for proto in ["TCP", "UDP", "ICMP"]:
            p = Packet(src_ip="127.0.0.1", dst_ip="127.0.0.1", protocol=proto)
            action, _ = engine.evaluate(p)
            assert action == Action.ALLOW

    def test_rule_priority(self):
        engine = self._engine()
        # Lower priority number = higher precedence
        engine.add_rule(action=Action.DENY, protocol="TCP", dst_port=80, priority=50)
        engine.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80, priority=100)
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 80)
        action, _ = engine.evaluate(p)
        assert action == Action.DENY  # priority 50 wins

    def test_load_rules_file(self, tmp_path):
        rules_file = tmp_path / "test.rules"
        rules_file.write_text(
            "# comment\n"
            "ALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 443\n"
            "DENY  TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 23\n"
        )
        engine = self._engine()
        engine.load_from_file(str(rules_file))
        assert len(engine.rules) == 2


# ================================================================== #
# State table tests                                                    #
# ================================================================== #

class TestStateTable:
    def test_track_tcp(self):
        st = StateTable(cleanup_interval=999)
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN")
        conn = st.track(p)
        assert conn.state == ConnectionState.SYN_SENT

    def test_established_after_ack(self):
        st = StateTable(cleanup_interval=999)
        syn = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN")
        ack = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="ACK")
        st.track(syn)
        conn = st.track(ack)
        assert conn.state == ConnectionState.ESTABLISHED

    def test_is_established(self):
        st = StateTable(cleanup_interval=999)
        syn = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN")
        ack = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="ACK")
        st.track(syn)
        st.track(ack)
        data = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="ACK")
        assert st.is_established(data)

    def test_not_established_unknown(self):
        st = StateTable(cleanup_interval=999)
        p = Packet.tcp("9.9.9.9", "8.8.8.8", 5555, 80)
        assert not st.is_established(p)

    def test_udp_tracking(self):
        st = StateTable(cleanup_interval=999)
        p = Packet.udp("1.1.1.1", "8.8.8.8", 5353, 53)
        conn = st.track(p)
        assert conn.state == ConnectionState.UDP_ACTIVE
        assert st.is_established(p)

    def test_count(self):
        st = StateTable(cleanup_interval=999)
        for i in range(5):
            st.track(Packet.tcp(f"10.0.0.{i}", "1.1.1.1", 1000+i, 80, flags="SYN"))
        assert st.count() == 5


# ================================================================== #
# Full firewall integration tests                                      #
# ================================================================== #

class TestFirewall:
    def _fw(self):
        fw = Firewall(default_policy=Action.DENY)
        fw.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80)
        fw.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=443)
        fw.add_rule(action=Action.DENY,  protocol="TCP", dst_port=23)
        fw.add_rule(action=Action.LOG,   protocol="ICMP")
        fw.add_rule(action=Action.ALLOW, protocol="ANY", src_network="127.0.0.0/8")
        fw.start()
        return fw

    def test_allow_https(self):
        fw = self._fw()
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="SYN")
        assert fw.process(p) == Action.ALLOW

    def test_deny_telnet(self):
        fw = self._fw()
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 23, flags="SYN")
        assert fw.process(p) == Action.DENY

    def test_default_deny(self):
        fw = self._fw()
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 9999, flags="SYN")
        assert fw.process(p) == Action.DENY

    def test_icmp_logged(self):
        fw = self._fw()
        p = Packet.icmp("10.0.0.1", "192.168.1.1")
        assert fw.process(p) == Action.LOG

    def test_stateful_established(self):
        """Packet belonging to an established session should be fast-pathed."""
        fw = self._fw()
        syn = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="SYN")
        ack = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="ACK")
        fw.process(syn)  # tracked
        fw.process(ack)  # escalated to ESTABLISHED
        data = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="ACK")
        assert fw.process(data) == Action.ALLOW  # fast path

    def test_deny_hook(self):
        fw = self._fw()
        denied = []
        fw.on("deny", lambda pkt, rule: denied.append(pkt))
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 23, flags="SYN")
        fw.process(p)
        assert len(denied) == 1
        assert denied[0].dst_port == 23

    def test_stats(self):
        fw = self._fw()
        fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="SYN"))
        fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 23,  flags="SYN"))
        assert fw.stats.packets_seen == 2
        assert fw.stats.packets_allowed == 1
        assert fw.stats.packets_denied == 1

    def test_loopback_allowed(self):
        fw = self._fw()
        p = Packet.tcp("127.0.0.1", "127.0.0.1", 3000, 8080, flags="SYN")
        assert fw.process(p) == Action.ALLOW


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
