#!/usr/bin/env python3
"""Servicios falsos en localhost para probar el scanner sin tocar nada real.

Uso: python3 lab/fake_services.py [--host 127.0.0.1]
Levanta puertos con banners tipo SSH viejo, Telnet, Apache 2.2 y Redis.
"""

from __future__ import annotations

import argparse
import socketserver
import threading

SERVICES = {
    2222: b"SSH-2.0-OpenSSH_7.4\r\n",
    2323: b"login: ",
    8089: None,  # HTTP: responde tras recibir la petición
    6380: None,  # Redis: responde a cualquier comando
}


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        port = self.server.server_address[1]
        greeting = SERVICES[port]
        try:
            if greeting is not None:
                self.request.sendall(greeting)
                return
            self.request.settimeout(2)
            data = self.request.recv(1024)
            if port == 8089 and data:
                self.request.sendall(
                    b"HTTP/1.0 200 OK\r\nServer: Apache/2.2.15 (CentOS)\r\n\r\n")
            elif port == 6380:
                self.request.sendall(b"-NOAUTH Authentication required.\r\n")
        except OSError:
            pass


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(host: str = "127.0.0.1", ports=None) -> list[_Server]:
    servers = []
    for port in ports or SERVICES:
        srv = _Server((host, port), _Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    servers = start(args.host)
    print(f"Escuchando en {args.host}: {sorted(SERVICES)}  (Ctrl+C para salir)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for s in servers:
            s.shutdown()


if __name__ == "__main__":
    main()
