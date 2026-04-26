"""
PyroWall Comprehensive Test Suite
Run with: python -m pytest tests/ -v
"""
import sys, os, json, time, threading, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.firewall import Firewall
from core.packet import Packet
from core.state_table import StateTable, ConnectionState
from core.rate_limiter import RateLimiter
from rules.rule_engine import RuleEngine, Rule, Action
from logs.event_logger import FirewallLogger


# ====================== Packet Tests ======================

class TestPacket:
    def test_tcp_factory(self):
        p = Packet.tcp("1.2.3.4", "5.6.7.8", 1234, 80, flags="SYN")
        assert p.protocol == "TCP" and p.src_ip == "1.2.3.4" and p.dst_port == 80 and p.is_syn()

    def test_udp_factory(self):
        p = Packet.udp("1.2.3.4", "5.6.7.8", 5353, 53)
        assert p.protocol == "UDP" and p.dst_port == 53

    def test_icmp_factory(self):
        assert Packet.icmp("10.0.0.1", "10.0.0.2").protocol == "ICMP"

    def test_connection_key(self):
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 443)
        assert p.connection_key == ("1.1.1.1", 1000, "2.2.2.2", 443, "TCP")

    def test_reverse_key(self):
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 443)
        assert p.reverse_key == ("2.2.2.2", 443, "1.1.1.1", 1000, "TCP")

    def test_fin_flag(self):
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="FIN|ACK")
        assert p.is_fin() and not p.is_syn()

    def test_rst_flag(self):
        assert Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="RST").is_rst()

    def test_edge_ips(self):
        for ip in ["0.0.0.0", "255.255.255.255", "127.0.0.1"]:
            p = Packet.tcp(ip, ip, 80, 80)
            assert p.src_ip == ip


# ====================== Rule Engine Tests ======================

class TestRuleEngine:
    def _engine(self):
        return RuleEngine(default_policy=Action.DENY)

    def test_allow_http(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80)
        assert e.evaluate(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 80))[0] == Action.ALLOW

    def test_deny_telnet(self):
        e = self._engine(); e.add_rule(action=Action.DENY, protocol="TCP", dst_port=23)
        assert e.evaluate(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 23))[0] == Action.DENY

    def test_default_deny(self):
        e = self._engine()
        action, rule = e.evaluate(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 9999))
        assert action == Action.DENY and rule is None

    def test_log_icmp(self):
        e = self._engine(); e.add_rule(action=Action.LOG, protocol="ICMP")
        assert e.evaluate(Packet.icmp("10.0.0.1", "10.0.0.2"))[0] == Action.LOG

    def test_cidr_match(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", src_network="192.168.0.0/16", dst_port=22)
        assert e.evaluate(Packet.tcp("192.168.5.100", "10.0.0.1", 4444, 22))[0] == Action.ALLOW

    def test_cidr_no_match(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", src_network="192.168.0.0/16", dst_port=22)
        assert e.evaluate(Packet.tcp("10.0.0.1", "10.0.0.2", 4444, 22))[0] == Action.DENY

    def test_protocol_any(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="ANY", dst_network="127.0.0.0/8")
        for proto in ["TCP", "UDP", "ICMP"]:
            assert e.evaluate(Packet(src_ip="127.0.0.1", dst_ip="127.0.0.1", protocol=proto))[0] == Action.ALLOW

    def test_rule_priority(self):
        e = self._engine()
        e.add_rule(action=Action.DENY, protocol="TCP", dst_port=80, priority=50)
        e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80, priority=100)
        assert e.evaluate(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 80))[0] == Action.DENY

    def test_load_rules_file(self, tmp_path):
        f = tmp_path / "test.rules"
        f.write_text("# comment\nALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 443\nDENY  TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 23\n")
        e = self._engine(); e.load_from_file(str(f))
        assert len(e.rules) == 2

    # --- Port range tests ---
    def test_port_range_match(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=1024, dst_port_end=65535)
        assert e.evaluate(Packet.tcp("1.1.1.1", "2.2.2.2", 80, 8080))[0] == Action.ALLOW

    def test_port_range_no_match(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=1024, dst_port_end=65535)
        assert e.evaluate(Packet.tcp("1.1.1.1", "2.2.2.2", 80, 80))[0] == Action.DENY

    def test_port_range_boundaries(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=100, dst_port_end=200)
        assert e.evaluate(Packet.tcp("1.1.1.1", "2.2.2.2", 80, 100))[0] == Action.ALLOW
        assert e.evaluate(Packet.tcp("1.1.1.1", "2.2.2.2", 80, 200))[0] == Action.ALLOW
        assert e.evaluate(Packet.tcp("1.1.1.1", "2.2.2.2", 80, 99))[0] == Action.DENY

    def test_port_range_parse(self, tmp_path):
        f = tmp_path / "r.rules"
        f.write_text("ALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 1024-65535\n")
        e = self._engine(); e.load_from_file(str(f))
        assert e.rules[0].dst_port == 1024 and e.rules[0].dst_port_end == 65535

    # --- Hit counter tests ---
    def test_hit_counter(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80)
        for _ in range(5):
            e.evaluate(Packet.tcp("1.1.1.1", "2.2.2.2", 9999, 80))
        assert e.rules[0].hit_count == 5

    def test_rule_stats(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80)
        e.evaluate(Packet.tcp("1.1.1.1", "2.2.2.2", 9999, 80))
        stats = e.rule_stats()
        assert stats[0]["hit_count"] == 1

    def test_reset_hit_counts(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80)
        e.evaluate(Packet.tcp("1.1.1.1", "2.2.2.2", 9999, 80))
        e.reset_hit_counts()
        assert e.rules[0].hit_count == 0

    # --- Validation tests ---
    def test_invalid_port_negative(self):
        e = self._engine()
        with pytest.raises(ValueError): e.add_rule(action=Action.ALLOW, dst_port=-1)

    def test_invalid_port_overflow(self):
        e = self._engine()
        with pytest.raises(ValueError): e.add_rule(action=Action.ALLOW, dst_port=99999)

    def test_invalid_protocol(self):
        e = self._engine()
        with pytest.raises(ValueError): e.add_rule(action=Action.ALLOW, protocol="BOGUS")

    def test_invalid_network(self):
        e = self._engine()
        with pytest.raises(ValueError): e.add_rule(action=Action.ALLOW, src_network="not.an.ip")

    def test_invalid_port_range(self):
        e = self._engine()
        with pytest.raises(ValueError): e.add_rule(action=Action.ALLOW, dst_port=200, dst_port_end=100)

    def test_malformed_rules_file(self, tmp_path):
        f = tmp_path / "bad.rules"
        f.write_text("THIS IS NOT A RULE\nALLOW TCP\nALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 80\n")
        e = self._engine(); e.load_from_file(str(f))
        assert len(e.rules) == 1  # only valid rule loaded

    def test_missing_rules_file(self):
        e = self._engine()
        with pytest.raises(FileNotFoundError): e.load_from_file("nonexistent.rules")

    def test_clear_rules(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=80)
        e.clear_rules()
        assert len(e.rules) == 0

    # --- Time-based rule tests ---
    def test_schedule_parse(self, tmp_path):
        f = tmp_path / "s.rules"
        f.write_text("DENY TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 80 schedule:22:00-06:00 # night block\n")
        e = self._engine(); e.load_from_file(str(f))
        assert e.rules[0].schedule_start == "22:00" and e.rules[0].schedule_end == "06:00"

    def test_invalid_schedule(self, tmp_path):
        f = tmp_path / "bad_sched.rules"
        f.write_text("DENY TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 80 schedule:25:00-06:00\n")
        e = self._engine(); e.load_from_file(str(f))
        assert len(e.rules) == 0  # skipped

    # --- IPv6 tests ---
    def test_ipv6_wildcard(self):
        e = self._engine(); e.add_rule(action=Action.ALLOW, protocol="TCP", src_network="::/0", dst_port=80)
        p = Packet.tcp("::1", "::1", 1234, 80)
        assert e.evaluate(p)[0] == Action.ALLOW


# ====================== State Table Tests ======================

class TestStateTable:
    def test_track_tcp(self):
        st = StateTable(cleanup_interval=0)
        conn = st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN"))
        assert conn.state == ConnectionState.SYN_SENT

    def test_established_after_ack(self):
        st = StateTable(cleanup_interval=0)
        st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN"))
        conn = st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="ACK"))
        assert conn.state == ConnectionState.ESTABLISHED

    def test_is_established(self):
        st = StateTable(cleanup_interval=0)
        st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN"))
        st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="ACK"))
        assert st.is_established(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="ACK"))

    def test_not_established_unknown(self):
        st = StateTable(cleanup_interval=0)
        assert not st.is_established(Packet.tcp("9.9.9.9", "8.8.8.8", 5555, 80))

    def test_udp_tracking(self):
        st = StateTable(cleanup_interval=0)
        p = Packet.udp("1.1.1.1", "8.8.8.8", 5353, 53)
        conn = st.track(p)
        assert conn.state == ConnectionState.UDP_ACTIVE and st.is_established(p)

    def test_count(self):
        st = StateTable(cleanup_interval=0)
        for i in range(5):
            st.track(Packet.tcp(f"10.0.0.{i}", "1.1.1.1", 1000+i, 80, flags="SYN"))
        assert st.count() == 5

    # --- New tests ---
    def test_fin_to_fin_wait(self):
        st = StateTable(cleanup_interval=0)
        st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN"))
        st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="ACK"))
        conn = st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="FIN|ACK"))
        assert conn.state == ConnectionState.FIN_WAIT

    def test_rst_to_closed(self):
        st = StateTable(cleanup_interval=0)
        st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN"))
        conn = st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="RST"))
        assert conn.state == ConnectionState.CLOSED

    def test_cleanup_expired(self):
        st = StateTable(cleanup_interval=0)
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN")
        conn = st.track(p)
        conn.last_seen = time.time() - 999  # force expire
        removed = st._cleanup()
        assert removed == 1 and st.count() == 0

    def test_top_talkers(self):
        st = StateTable(cleanup_interval=0)
        p1 = Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN")
        p2 = Packet.tcp("3.3.3.3", "4.4.4.4", 2000, 443, flags="SYN")
        st.track(p1)
        c2 = st.track(p2)
        c2.byte_count = 99999
        talkers = st.top_talkers(2)
        assert talkers[0]["bytes"] == 99999

    def test_stop_cleanup_thread(self):
        st = StateTable(cleanup_interval=1)
        st.stop()
        assert st._stop_event.is_set()

    def test_reverse_key_established(self):
        st = StateTable(cleanup_interval=0)
        st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="SYN"))
        st.track(Packet.tcp("1.1.1.1", "2.2.2.2", 1000, 80, flags="ACK"))
        reply = Packet.tcp("2.2.2.2", "1.1.1.1", 80, 1000, flags="ACK")
        assert st.is_established(reply)


# ====================== Rate Limiter Tests ======================

class TestRateLimiter:
    def test_allows_under_limit(self):
        rl = RateLimiter(max_pps=10, cleanup_interval=999)
        for _ in range(10):
            assert rl.is_allowed("1.1.1.1")
        rl.stop()

    def test_blocks_over_limit(self):
        rl = RateLimiter(max_pps=5, cleanup_interval=999)
        for _ in range(5):
            rl.is_allowed("1.1.1.1")
        assert not rl.is_allowed("1.1.1.1")
        rl.stop()

    def test_different_sources_independent(self):
        rl = RateLimiter(max_pps=2, cleanup_interval=999)
        rl.is_allowed("1.1.1.1"); rl.is_allowed("1.1.1.1")
        assert not rl.is_allowed("1.1.1.1")
        assert rl.is_allowed("2.2.2.2")  # different source
        rl.stop()

    def test_blocked_sources(self):
        rl = RateLimiter(max_pps=1, cleanup_interval=999)
        rl.is_allowed("1.1.1.1")
        rl.is_allowed("1.1.1.1")  # blocked
        assert "1.1.1.1" in rl.get_blocked_sources()
        rl.stop()

    def test_reset(self):
        rl = RateLimiter(max_pps=1, cleanup_interval=999)
        rl.is_allowed("1.1.1.1")
        assert not rl.is_allowed("1.1.1.1")
        rl.reset("1.1.1.1")
        assert rl.is_allowed("1.1.1.1")
        rl.stop()

    def test_stop(self):
        rl = RateLimiter(max_pps=100, cleanup_interval=1)
        rl.stop()
        assert rl._stop_event.is_set()


# ====================== Firewall Integration Tests ======================

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
        action, rule = fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="SYN"))
        assert action == Action.ALLOW and rule is not None
        fw.stop()

    def test_deny_telnet(self):
        fw = self._fw()
        action, _ = fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 23, flags="SYN"))
        assert action == Action.DENY
        fw.stop()

    def test_default_deny(self):
        fw = self._fw()
        action, rule = fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 9999, flags="SYN"))
        assert action == Action.DENY and rule is None
        fw.stop()

    def test_icmp_logged_and_allowed(self):
        fw = self._fw()
        action, _ = fw.process(Packet.icmp("10.0.0.1", "192.168.1.1"))
        assert action == Action.LOG
        assert fw.stats.packets_logged == 1
        assert fw.stats.packets_allowed == 1  # LOG now counts as allowed
        fw.stop()

    def test_stateful_established(self):
        fw = self._fw()
        fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="SYN"))
        fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="ACK"))
        action, rule = fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="ACK"))
        assert action == Action.ALLOW and rule is None  # fast path
        fw.stop()

    def test_deny_hook(self):
        fw = self._fw()
        denied = []
        fw.on("deny", lambda pkt, rule: denied.append(pkt))
        fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 23, flags="SYN"))
        assert len(denied) == 1 and denied[0].dst_port == 23
        fw.stop()

    def test_allow_hook(self):
        fw = self._fw()
        allowed = []
        fw.on("allow", lambda pkt, rule: allowed.append(pkt))
        fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="SYN"))
        assert len(allowed) == 1
        fw.stop()

    def test_log_hook(self):
        fw = self._fw()
        logged = []
        fw.on("log", lambda pkt, rule: logged.append(pkt))
        fw.process(Packet.icmp("10.0.0.1", "10.0.0.2"))
        assert len(logged) == 1
        fw.stop()

    def test_stats(self):
        fw = self._fw()
        fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="SYN"))
        fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 23,  flags="SYN"))
        assert fw.stats.packets_seen == 2 and fw.stats.packets_allowed == 1 and fw.stats.packets_denied == 1
        fw.stop()

    def test_loopback_allowed(self):
        fw = self._fw()
        action, _ = fw.process(Packet.tcp("127.0.0.1", "127.0.0.1", 3000, 8080, flags="SYN"))
        assert action == Action.ALLOW
        fw.stop()

    def test_rate_limiting(self):
        fw = Firewall(default_policy=Action.ALLOW, rate_limit=3)
        fw.start()
        for _ in range(3):
            fw.process(Packet.tcp("1.1.1.1", "2.2.2.2", 80, 80, flags="SYN"))
        action, _ = fw.process(Packet.tcp("1.1.1.1", "2.2.2.2", 80, 80, flags="SYN"))
        assert action == Action.DENY
        assert fw.stats.packets_rate_limited >= 1
        fw.stop()

    def test_process_returns_tuple(self):
        fw = self._fw()
        result = fw.process(Packet.tcp("1.2.3.4", "5.6.7.8", 9999, 443, flags="SYN"))
        assert isinstance(result, tuple) and len(result) == 2
        fw.stop()

    def test_concurrent_processing(self):
        fw = self._fw()
        results = []
        def process_many():
            for i in range(50):
                action, _ = fw.process(Packet.tcp(f"10.0.{i%256}.1", "5.6.7.8", 1000+i, 443, flags="SYN"))
                results.append(action)
        threads = [threading.Thread(target=process_many) for _ in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert len(results) == 200
        assert all(a == Action.ALLOW for a in results)
        assert fw.stats.packets_seen == 200
        fw.stop()


# ====================== Logger Tests ======================

class TestFirewallLogger:
    def test_json_log_format(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        with FirewallLogger(log_file=log_file) as fwlog:
            p = Packet.tcp("1.1.1.1", "2.2.2.2", 80, 443, flags="SYN")
            fwlog.log_event("ALLOW", p)
        with open(log_file) as f:
            entry = json.loads(f.readline())
        assert entry["action"] == "ALLOW" and entry["proto"] == "TCP"
        assert entry["src"] == "1.1.1.1:80" and entry["dst"] == "2.2.2.2:443"

    def test_log_with_rule(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        rule = Rule(action=Action.ALLOW, protocol="TCP", src_network="0.0.0.0/0",
                     src_port=None, dst_network="0.0.0.0/0", dst_port=443, comment="HTTPS")
        with FirewallLogger(log_file=log_file) as fwlog:
            fwlog.log_event("ALLOW", Packet.tcp("1.1.1.1", "2.2.2.2", 80, 443), rule)
        with open(log_file) as f:
            entry = json.loads(f.readline())
        assert "HTTPS" in entry["rule"]

    def test_context_manager_closes(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        fwlog = FirewallLogger(log_file=log_file)
        fwlog.__enter__()
        fwlog.__exit__(None, None, None)
        assert fwlog._file_handle is None

    def test_no_file(self):
        fwlog = FirewallLogger(log_file=None)
        fwlog.log_event("ALLOW", Packet.tcp("1.1.1.1", "2.2.2.2", 80, 443))
        fwlog.close()


# ====================== Large Ruleset Performance ======================

class TestPerformance:
    def test_large_ruleset(self):
        e = RuleEngine(default_policy=Action.DENY)
        for i in range(1000):
            e.add_rule(action=Action.ALLOW, protocol="TCP", dst_port=i+1, priority=100)
        p = Packet.tcp("1.1.1.1", "2.2.2.2", 9999, 500)
        start = time.time()
        for _ in range(1000):
            e.evaluate(p)
        elapsed = time.time() - start
        assert elapsed < 5.0  # should be fast


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
