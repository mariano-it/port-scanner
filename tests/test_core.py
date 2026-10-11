import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from portscan import cli
from portscan.analyze import analyze
from portscan.models import PortResult, PortState, Severity
from portscan.ports import PortSpecError, parse_ports, top_ports
from portscan.ratelimit import RateLimiter
from portscan.scanner import ScanConfig, probe_port, scan
from portscan.scope import ScopeError, parse_scope, resolve_targets


class PortsTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_ports("80,22,20-22"), [20, 21, 22, 80])
        self.assertEqual(len(parse_ports("-")), 65535)

    def test_invalid(self):
        for bad in ("0", "70000", "a", "10-5", ""):
            with self.assertRaises(PortSpecError):
                parse_ports(bad)

    def test_top_ports(self):
        top = top_ports(10)
        self.assertEqual(len(top), 10)
        self.assertEqual(len(set(top)), 10)
        self.assertIn(80, top)


class ScopeTest(unittest.TestCase):
    def setUp(self):
        self.scope = parse_scope("# lab\n127.0.0.1\n192.168.56.0/24  # red lab\n")

    def test_in_scope(self):
        hosts = resolve_targets(["192.168.56.0/30"], self.scope)
        self.assertEqual(hosts, ["192.168.56.1", "192.168.56.2"])

    def test_out_of_scope_refused(self):
        with self.assertRaises(ScopeError):
            resolve_targets(["192.168.57.1"], self.scope)
        with self.assertRaises(ScopeError):
            resolve_targets(["192.168.56.5", "10.0.0.1"], self.scope)

    def test_public_needs_flag(self):
        scope = parse_scope("8.8.8.8\n")
        with self.assertRaises(ScopeError):
            resolve_targets(["8.8.8.8"], scope)
        self.assertEqual(resolve_targets(["8.8.8.8"], scope, allow_public=True), ["8.8.8.8"])

    def test_too_broad_scope_rejected(self):
        with self.assertRaises(ScopeError):
            parse_scope("10.0.0.0/8\n")
        with self.assertRaises(ScopeError):
            parse_scope("0.0.0.0/0\n")

    def test_empty_scope_rejected(self):
        with self.assertRaises(ScopeError):
            parse_scope("# nada\n")

    def test_max_hosts(self):
        with self.assertRaises(ScopeError):
            resolve_targets(["192.168.56.0/24"], self.scope, max_hosts=10)


class RateLimiterTest(unittest.TestCase):
    def test_spacing(self):
        now = [0.0]
        slept = []

        def sleep(d):
            slept.append(d)
            now[0] += d

        rl = RateLimiter(10, clock=lambda: now[0], sleep=sleep)
        for _ in range(5):
            rl.acquire()
        self.assertAlmostEqual(now[0], 0.4, places=6)  # 5 slots a 0.1 s => 4 esperas

    def test_invalid(self):
        with self.assertRaises(ValueError):
            RateLimiter(0)


def _server(greeting: bytes | None):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                if greeting:
                    conn.sendall(greeting)
                else:
                    conn.settimeout(3)
                    conn.recv(100)
                    conn.sendall(b"HTTP/1.0 200 OK\r\nServer: nginx/1.14.0\r\n\r\n")
            except OSError:
                pass
            conn.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()

    def close():
        stop.set()
        t.join()
        srv.close()

    return srv.getsockname()[1], close


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ScannerTest(unittest.TestCase):
    def test_open_closed_and_banner(self):
        port, close = _server(b"SSH-2.0-OpenSSH_7.4\r\n")
        self.addCleanup(close)
        cfg = ScanConfig(rate=1000, timeout=1, banners=True, banner_timeout=1)
        res = probe_port("127.0.0.1", port, cfg)
        self.assertEqual(res.state, PortState.OPEN)
        self.assertEqual(res.service, "ssh")
        self.assertTrue(res.banner.startswith("SSH-2.0-OpenSSH_7.4"))
        self.assertEqual(probe_port("127.0.0.1", _closed_port(), cfg).state, PortState.CLOSED)

    def test_http_probe_on_nonstandard_port(self):
        port, close = _server(None)
        self.addCleanup(close)
        res = probe_port("127.0.0.1", port, ScanConfig(banners=True, banner_timeout=1))
        self.assertEqual(res.service, "http")
        self.assertIn("nginx/1.14.0", res.banner)

    def test_scan_collects_and_hooks(self):
        port, close = _server(b"hi\r\n")
        self.addCleanup(close)
        seen = []
        res = scan(["127.0.0.1"], [port, _closed_port()],
                   ScanConfig(rate=1000, timeout=1),
                   on_attempt=lambda ts, h, p: seen.append((h, p)))
        self.assertEqual(len(res), 2)
        self.assertEqual(len(seen), 2)
        self.assertEqual([r.state for r in res if r.port == port], [PortState.OPEN])

    def test_filtered_on_timeout(self):
        # 192.0.2.0/24 (TEST-NET-1) no enruta: timeout o "unreachable" => filtered
        res = probe_port("192.0.2.1", 81, ScanConfig(timeout=0.3))
        self.assertEqual(res.state, PortState.FILTERED)


class AnalyzeTest(unittest.TestCase):
    def _open(self, port, service="", banner="", tls=""):
        return PortResult("10.0.0.1", port, PortState.OPEN, service=service, banner=banner, tls=tls)

    def test_findings(self):
        findings = analyze([
            self._open(23, "telnet"),
            self._open(22, "ssh", "SSH-2.0-OpenSSH_7.4"),
            self._open(22022, "ssh", "SSH-2.0-OpenSSH_9.6"),
            self._open(8080, "http", "HTTP/1.1 200 OK | Server: nginx/1.14.0"),
            self._open(9999, "redis", "-NOAUTH"),
            self._open(443, "https", "", "TLSv1 ECDHE"),
        ])
        titles = [f.title for f in findings]
        self.assertIn("Telnet abierto", titles)
        self.assertIn("Versión de SSH desactualizada", titles)
        self.assertEqual(titles.count("Versión de SSH desactualizada"), 1)
        self.assertIn("Versión de servidor web expuesta", titles)
        self.assertIn("Redis expuesto", titles)
        self.assertIn("TLS obsoleto aceptado", titles)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_closed_ignored(self):
        r = PortResult("10.0.0.1", 23, PortState.CLOSED)
        self.assertEqual(analyze([r]), [])


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.scope = self.tmp / "scope.txt"
        self.scope.write_text("127.0.0.1\n")
        self.audit = self.tmp / "audit.jsonl"

    def run_cli(self, *args):
        return cli.main([*args, "--audit-log", str(self.audit)])

    def events(self):
        return [json.loads(l) for l in self.audit.read_text().splitlines()]

    def test_out_of_scope_exit_2_and_audited(self):
        code = self.run_cli("--scope", str(self.scope), "10.1.1.1", "-p", "80", "-q")
        self.assertEqual(code, cli.EXIT_SCOPE)
        self.assertEqual(self.events()[-1]["event"], "denied")

    def test_scan_writes_reports_and_audit(self):
        port, close = _server(b"SSH-2.0-OpenSSH_7.4\r\n")
        self.addCleanup(close)
        out_json, out_md = self.tmp / "r.json", self.tmp / "r.md"
        code = self.run_cli("--scope", str(self.scope), "127.0.0.1", "-p", str(port),
                            "--banners", "-q", "-o", str(out_json), "-o", str(out_md))
        self.assertEqual(code, 0)
        data = json.loads(out_json.read_text())
        self.assertEqual(data["results"][0]["data"]["ports"][0]["port"], port)
        self.assertEqual(data["summary"]["medium"], 1)
        self.assertIn("Versión de SSH desactualizada", out_md.read_text())
        self.assertEqual([e["event"] for e in self.events()], ["start", "end"])

    def test_bad_rate_and_ports(self):
        self.assertEqual(self.run_cli("--scope", str(self.scope), "127.0.0.1", "--rate", "0"),
                         cli.EXIT_ERROR)
        self.assertEqual(self.run_cli("--scope", str(self.scope), "127.0.0.1", "-p", "99999"),
                         cli.EXIT_ERROR)

    def test_missing_scope_file(self):
        code = self.run_cli("--scope", str(self.tmp / "nope.txt"), "127.0.0.1")
        self.assertEqual(code, cli.EXIT_SCOPE)


class InteractiveTest(unittest.TestCase):
    def test_check_target(self):
        from portscan.interactive import _check_target
        hosts, public = _check_target("127.0.0.1")
        self.assertEqual((hosts, public), (["127.0.0.1"], False))
        self.assertTrue(_check_target("8.8.8.8")[1])
        with self.assertRaises(ScopeError):
            _check_target("10.0.0.0/8")


class BannerEncodingTest(unittest.TestCase):
    def test_utf8_banner(self):
        from portscan.scanner import _http_server_line
        raw = "HTTP/1.0 400 Petición incorrecta\r\nServer: x/1\r\n\r\n".encode()
        self.assertIn("Petición", _http_server_line(raw))


if __name__ == "__main__":
    unittest.main()
