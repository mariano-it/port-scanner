import errno
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

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

    def _fake_socket(self, outcome):
        class Fake:
            def __init__(self, *a, **k):
                pass

            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

            def close(self):
                pass

        return mock.patch("portscan.scanner.socket.socket", Fake)

    def test_state_classification_without_network(self):
        cfg = ScanConfig()
        cases = [
            (errno.ETIMEDOUT, PortState.FILTERED),
            (errno.EHOSTUNREACH, PortState.FILTERED),
            (errno.ECONNREFUSED, PortState.CLOSED),
            (0, PortState.OPEN),
            (socket.timeout(), PortState.FILTERED),
            (OSError(errno.ENETUNREACH, "x"), PortState.FILTERED),
        ]
        for outcome, expected in cases:
            with self._fake_socket(outcome):
                self.assertEqual(probe_port("192.0.2.1", 81, cfg).state, expected, outcome)


class AnalyzeTest(unittest.TestCase):
    def _open(self, port, service="", banner="", tls=""):
        return PortResult("10.0.0.1", port, PortState.OPEN, service=service, banner=banner, tls=tls)

    def test_findings(self):
        findings = analyze([
            self._open(23, "telnet"),
            self._open(22, "ssh", "SSH-2.0-OpenSSH_7.4"),
            self._open(22022, "ssh", "SSH-2.0-OpenSSH_9.6"),
            self._open(8080, "http", "HTTP/1.1 200 OK | Server: nginx/1.14.0"),
            self._open(9999, "redis", "-NOAUTH Authentication required."),
            self._open(9998, "redis", "-ERR unknown command 'HEAD'"),
            PortResult("10.0.0.1", 443, PortState.OPEN, service="https",
                       tls="TLSv1.3 X", tls_legacy=["TLSv1"]),
        ])
        titles = [f.title for f in findings]
        self.assertIn("Telnet abierto", titles)
        self.assertIn("Versión de SSH desactualizada", titles)
        self.assertEqual(titles.count("Versión de SSH desactualizada"), 1)
        self.assertIn("Versión de servidor web expuesta", titles)
        self.assertIn("Redis expuesto (autenticación activa)", titles)
        self.assertIn("Redis sin autenticación", titles)
        sev = {f.title: f.severity for f in findings}
        self.assertEqual(sev["Redis sin autenticación"], Severity.HIGH)
        self.assertEqual(sev["Redis expuesto (autenticación activa)"], Severity.MEDIUM)
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

    def test_top_ports_zero_is_error(self):
        self.assertEqual(self.run_cli("--scope", str(self.scope), "127.0.0.1", "--top-ports", "0"),
                         cli.EXIT_ERROR)

    def test_reports_are_private(self):
        out = self.tmp / "r.json"
        self.run_cli("--scope", str(self.scope), "127.0.0.1", "-p", str(_closed_port()),
                     "-q", "-o", str(out))
        self.assertEqual(oct(out.stat().st_mode & 0o777), "0o600")

    def test_missing_scope_file(self):
        code = self.run_cli("--scope", str(self.tmp / "nope.txt"), "127.0.0.1")
        self.assertEqual(code, cli.EXIT_SCOPE)


class LargeNetworkTest(unittest.TestCase):
    def test_pairs_is_lazy(self):
        from portscan.scanner import _pairs
        gen = _pairs([f"10.0.{i // 250}.{i % 250}" for i in range(65000)], list(range(1, 101)), False)
        self.assertEqual(next(gen), ("10.0.0.0", 1))   # no materializa 6,5 M de pares
        self.assertEqual(sum(1 for _ in zip(range(1000), gen)), 1000)

    def test_discovery_counts_rst_as_alive(self):
        from portscan.scanner import discover
        port, close = _server(b"x\r\n")
        self.addCleanup(close)
        seen = []
        alive = discover(["127.0.0.1", "127.0.0.2"], ScanConfig(rate=1000, timeout=0.5, workers=4),
                         [_closed_port(), port], on_host=lambda h, up: seen.append((h, up)))
        # 127.0.0.2 no escucha en `port` pero responde RST: sigue siendo un host vivo
        self.assertEqual(alive, ["127.0.0.1", "127.0.0.2"])
        self.assertEqual(len(seen), 2)

    def test_discovery_filtered_host_is_not_alive(self):
        from portscan.scanner import discover

        class Fake:
            def __init__(self, *a, **k):
                pass

            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                return errno.ETIMEDOUT

            def close(self):
                pass

        with mock.patch("portscan.scanner.socket.socket", Fake):
            self.assertEqual(discover(["192.0.2.1"], ScanConfig(rate=1000), [22, 80]), [])

    def test_keep_only_open_but_count_everything(self):
        from collections import Counter
        port, close = _server(b"hi\r\n")
        self.addCleanup(close)
        stats = Counter()
        res = scan(["127.0.0.1"], [port, _closed_port(), _closed_port()],
                   ScanConfig(rate=1000, timeout=1), keep_all=False, stats=stats)
        self.assertEqual([r.port for r in res], [port])
        self.assertEqual(sum(stats.values()), 3)
        self.assertEqual(stats["open"], 1)

    def test_diagnose(self):
        from collections import Counter
        from portscan.cli import _diagnose
        self.assertIn("filtered", _diagnose(Counter(filtered=100), None, False)[0])
        self.assertIn("closed", _diagnose(Counter(closed=100), None, False)[0])
        self.assertTrue(any("descubrimiento" in t.lower() for t in _diagnose(Counter(filtered=5), 0, True)))

    def test_slash_16_needs_max_hosts(self):
        scope = parse_scope("10.20.0.0/16\n")
        with self.assertRaises(ScopeError):
            resolve_targets(["10.20.0.0/16"], scope)            # default 1024
        hosts = resolve_targets(["10.20.0.0/16"], scope, max_hosts=65536)
        self.assertEqual(len(hosts), 65534)

    def test_host_sort_is_numeric(self):
        from portscan.scanner import _host_key
        hosts = ["10.0.200.9", "10.0.5.7", "10.0.255.254"]
        self.assertEqual(sorted(hosts, key=_host_key), ["10.0.5.7", "10.0.200.9", "10.0.255.254"])

    def test_cli_discover_only(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "s.txt").write_text("127.0.0.0/30\n")
        out = tmp / "r.json"
        code = cli.main(["--scope", str(tmp / "s.txt"), "127.0.0.0/30", "--discover-only",
                         "--discovery-ports", str(_closed_port()), "-q", "-o", str(out),
                         "--audit-log", str(tmp / "a.jsonl"), "--timeout", "0.5"])
        self.assertEqual(code, 0)
        data = json.loads(out.read_text())["results"][0]["data"]
        self.assertEqual(data["alive_hosts"], ["127.0.0.1", "127.0.0.2"])


class ScopeSizeTest(unittest.TestCase):
    def test_huge_ranges_rejected_without_expanding(self):
        import time
        scope = parse_scope("192.168.56.0/24\n")
        t0 = time.time()
        for big in ("10.0.0.0/8", "10.0.0.0/12", "2001:db8::/64", "0.0.0.0/1"):
            with self.assertRaises(ScopeError):
                resolve_targets([big], scope)
        self.assertLess(time.time() - t0, 0.5)

    def test_subnet_in_scope_accepted(self):
        scope = parse_scope("192.168.56.0/24\n")
        self.assertEqual(len(resolve_targets(["192.168.56.0/25"], scope)), 126)

    def test_union_of_scope_entries_covers_target(self):
        scope = parse_scope("192.168.56.0/25\n192.168.56.128/25\n")
        self.assertEqual(len(resolve_targets(["192.168.56.0/24"], scope)), 254)

    def test_cumulative_max_hosts(self):
        scope = parse_scope("192.168.56.0/24\n")
        with self.assertRaises(ScopeError):
            resolve_targets(["192.168.56.0/25", "192.168.56.128/25"], scope, max_hosts=200)


class MarkdownEscapeTest(unittest.TestCase):
    def test_banner_cannot_break_out(self):
        from portscan.models import ModuleResult, Report
        from portscan.report.markdown_report import render_markdown
        evil = "x` [click](http://evil.example) `` <img src=x> | col"
        res = PortResult("10.0.0.1", 80, PortState.OPEN, service="http", banner=evil)
        from portscan.models import Finding
        report = Report("10.0.0.1", [ModuleResult(
            "portscan", "10.0.0.1",
            data={"meta": {}, "ports": [res.to_dict()]},
            findings=[Finding("t", Severity.LOW, "d", "r", evidence=evil)])])
        md = render_markdown(report)
        for line in md.splitlines():
            if "evil.example" in line:
                # todo el contenido hostil debe estar dentro de un code span cuyo
                # delimitador (``` ) es más largo que cualquier racha interna
                self.assertIn("```", line)
                inner = line.split("```", 1)[1]
                self.assertIn("evil.example", inner.rsplit("```", 1)[0])


class AuditChainTest(unittest.TestCase):
    def test_tamper_detected(self):
        from portscan.audit import AuditLog
        tmp = Path(tempfile.mkdtemp()) / "a.jsonl"
        log = AuditLog(tmp)
        for i in range(3):
            log.write("start", f"id{i}", n=i)
        self.assertEqual(log.verify()[:2], (True, 3))
        lines = tmp.read_text().splitlines()
        tmp.write_text("\n".join([lines[0], lines[2]]) + "\n")  # borra la intermedia
        self.assertFalse(log.verify()[0])
        self.assertEqual(oct(tmp.stat().st_mode & 0o777), "0o600")


class TlsLegacyTest(unittest.TestCase):
    """Servidor TLS local real: cada versión se sondea por separado."""

    def _server(self, minv, maxv):
        import shutil
        import subprocess
        import ssl as _ssl
        import warnings
        if not shutil.which("openssl"):
            self.skipTest("openssl no disponible")
        d = Path(tempfile.mkdtemp())
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"), "-days", "1",
                        "-subj", "/CN=localhost"], check=True, capture_output=True)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.minimum_version = minv
            ctx.maximum_version = maxv
        ctx.load_cert_chain(str(d / "c.pem"), str(d / "k.pem"))
        srv = socket.socket()
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
                    ctx.wrap_socket(conn, server_side=True).close()
                except OSError:
                    conn.close()

        t = threading.Thread(target=loop, daemon=True)
        t.start()

        def close():
            stop.set()
            t.join()
            srv.close()

        self.addCleanup(close)
        return srv.getsockname()[1]

    def test_modern_only_server_reports_no_legacy(self):
        import ssl as _ssl
        from portscan.scanner import probe_legacy_tls
        port = self._server(_ssl.TLSVersion.TLSv1_2, _ssl.TLSVersion.TLSv1_3)
        self.assertEqual(probe_legacy_tls("127.0.0.1", port, 2), [])

    def test_legacy_server_detected(self):
        import ssl as _ssl
        from portscan.scanner import probe_legacy_tls
        port = self._server(_ssl.TLSVersion.TLSv1, _ssl.TLSVersion.TLSv1_3)
        got = probe_legacy_tls("127.0.0.1", port, 2)
        if not got:
            self.skipTest("este OpenSSL no puede negociar TLS 1.0/1.1 (política del sistema)")
        self.assertIn("TLSv1", got)


class InteractiveTest(unittest.TestCase):
    def test_authorization_is_separate_and_not_automatic(self):
        import portscan.interactive as it
        tmp = Path(tempfile.mkdtemp())
        patcher = mock.patch.object(it, "_scope_path", lambda: tmp / "scope.txt")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.assertFalse(it._in_scope("10.77.0.9"))   # sin scope.txt: nada autorizado
        self.assertFalse((tmp / "scope.txt").exists())  # y consultar no escribe
        with mock.patch.object(it, "_ask", return_value=""):
            self.assertFalse(it._authorize("10.77.0.9"))
        self.assertFalse((tmp / "scope.txt").exists())
        with mock.patch.object(it, "_ask", return_value="AUTORIZO"):
            self.assertTrue(it._authorize("10.77.0.9"))
        self.assertTrue(it._in_scope("10.77.0.9"))
        self.assertFalse(it._in_scope("10.77.0.10"))   # solo lo autorizado

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
