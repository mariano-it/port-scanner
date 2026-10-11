import json
import unittest

from portscan.detect.detector import DEFAULT_RULES, Rule, detect
from portscan.detect.parsers import (Event, format_eve_flow, format_kernel_line, parse_eve_line,
                                     parse_kernel_line, parse_lines)

T0 = 1_760_000_000.0


def scan_events(src, ports, rate, host="10.0.0.5", start=T0):
    return [Event(start + i / rate, src, host, p) for i, p in enumerate(ports)]


class ParserTest(unittest.TestCase):
    def test_kernel_roundtrip(self):
        ev = Event(T0, "1.2.3.4", "10.0.0.5", 443)
        parsed = parse_kernel_line(format_kernel_line(ev))
        self.assertEqual((parsed.src, parsed.dst, parsed.dport), ("1.2.3.4", "10.0.0.5", 443))
        self.assertAlmostEqual(parsed.ts, T0, places=3)

    def test_syslog_timestamp(self):
        line = ("Oct 10 21:48:01 host kernel: [UFW BLOCK] IN=lo OUT= SRC=1.1.1.1 DST=2.2.2.2 "
                "PROTO=TCP SPT=1 DPT=22 SYN URGP=0")
        ev = parse_kernel_line(line, year=2026)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.dport, 22)

    def test_ignores_non_syn_and_garbage(self):
        base = "2026-10-10T21:48:01+00:00 h kernel: SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT=22 "
        self.assertIsNone(parse_kernel_line(base + "ACK PSH"))
        self.assertIsNone(parse_kernel_line(base + "SYN ACK"))
        self.assertIsNone(parse_kernel_line("ruido cualquiera"))
        self.assertIsNone(parse_kernel_line("2026-10-10T21:48:01+00:00 SRC=1 DST=2 PROTO=ICMP"))

    def test_eve(self):
        line = json.dumps({"timestamp": "2026-10-10T21:48:01.123456+0000", "event_type": "flow",
                           "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80, "proto": "TCP"})
        ev = parse_eve_line(line)
        self.assertEqual((ev.src, ev.dport), ("1.1.1.1", 80))
        self.assertEqual(len(list(parse_lines([line, "{bad json"], "auto"))), 1)


class EveFalsePositiveTest(unittest.TestCase):
    def _browse(self, pkts):
        return [format_eve_flow(Event(T0 + i * 0.2, "192.0.2.50", f"198.18.0.{i + 1}", 443), pkts)
                for i in range(20)]

    def test_web_browsing_is_not_a_sweep(self):
        evs = list(parse_lines(self._browse(25), "eve"))
        self.assertEqual(evs, [])
        self.assertEqual(detect(evs, DEFAULT_RULES), [])

    def test_unanswered_syns_are_a_sweep(self):
        evs = list(parse_lines(self._browse(0), "eve"))
        self.assertEqual(len(evs), 20)
        self.assertEqual(detect(evs, DEFAULT_RULES)[0].kind, "horizontal")

    def test_opt_in_counts_established(self):
        evs = list(parse_lines(self._browse(25), "eve", include_established=True))
        self.assertEqual(len(evs), 20)

    def test_alerts_always_count(self):
        line = json.dumps({"timestamp": "2026-10-10T21:48:01.123456+0000", "event_type": "alert",
                           "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80,
                           "flow": {"pkts_toclient": 50}})
        self.assertIsNotNone(parse_eve_line(line))


class DetectorTest(unittest.TestCase):
    def test_fast_scan_detected(self):
        alerts = detect(scan_events("9.9.9.9", range(1, 200), 100), DEFAULT_RULES)
        fast = [a for a in alerts if a.rule == "fast"]
        self.assertEqual(len(fast), 1)
        self.assertEqual(fast[0].kind, "vertical")
        self.assertEqual(fast[0].technique, "T1046")
        self.assertLess(fast[0].time_to_detect, 1.0)

    def test_below_threshold_no_alert(self):
        self.assertEqual(detect(scan_events("9.9.9.9", range(1, 15), 100), DEFAULT_RULES), [])

    def test_repeated_same_port_is_not_scan(self):
        evs = [Event(T0 + i * 0.1, "9.9.9.9", "10.0.0.5", 22) for i in range(500)]
        self.assertEqual(detect(evs, DEFAULT_RULES), [])

    def test_slow_scan_needs_slow_rule(self):
        evs = scan_events("9.9.9.9", range(1, 101), 0.2)  # 1 cada 5 s
        self.assertEqual(detect(evs, [DEFAULT_RULES[0]]), [])
        slow = detect(evs, DEFAULT_RULES)
        self.assertEqual([a.rule for a in slow], ["slow"])

    def test_horizontal_sweep(self):
        evs = [Event(T0 + i / 50, "9.9.9.9", f"10.0.1.{i}", 22) for i in range(1, 100)]
        alerts = detect(evs, DEFAULT_RULES)
        self.assertEqual(alerts[0].kind, "horizontal")

    def test_distributed_needs_dst_rule(self):
        evs = []
        for i in range(40):
            evs += scan_events(f"8.8.{i}.1", range(i * 5 + 1, i * 5 + 6), 5, start=T0 + i * 0.1)
        self.assertEqual(detect(evs, [r for r in DEFAULT_RULES if r.group_by == "src"]), [])
        alerts = detect(evs, DEFAULT_RULES)
        self.assertEqual(alerts[0].kind, "distributed")
        self.assertGreaterEqual(len(alerts[0].srcs), 5)

    def test_allowlist(self):
        evs = scan_events("192.0.2.200", range(1, 100), 100)
        self.assertEqual(detect(evs, DEFAULT_RULES, allowlist=["192.0.2.200"]), [])

    def test_alert_not_duplicated_then_rearms(self):
        a = scan_events("9.9.9.9", range(1, 60), 100)
        b = scan_events("9.9.9.9", range(100, 160), 100, start=T0 + 1000)
        fast = [x for x in detect(a + b, [Rule("fast", 10, 15)])]
        self.assertEqual(len(fast), 2)


if __name__ == "__main__":
    unittest.main()
