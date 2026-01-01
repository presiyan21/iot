# src/scanner/port_scanner.py
from __future__ import annotations

import socket
import time
import concurrent.futures
from typing import List, Dict, Tuple, Optional, Any

from ..utils import helpers, logger


# Common IoT / embedded ports worth checking by default
DEFAULT_PORTS = [
    21, 22, 23, 53, 80, 88, 110, 111,
    123, 135, 139, 143, 161, 443,
    554, 8080, 8883
]

DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_WORKERS = 50
DEFAULT_ALLOW_PUBLIC = False

_HTTP_PORTS = {80, 8080}
# Legacy plaintext services often abused in IoT environments
_HIGH_RISK_PORTS = {21, 23, 2323}


def _safe_close(sock: Optional[socket.socket]) -> None:
    # Close socket quietly to avoid masking scan results 
    if sock:
        try:
            sock.close()
        except Exception:
            pass


def _read_banner(sock: socket.socket, timeout: float) -> str:
    # Best-effort banner grab: many services send a greeting on connect
    try:
        sock.settimeout(timeout)
        data = sock.recv(1024)
        return data.decode("utf-8", errors="ignore").strip() if data else ""
    except Exception:
        return ""


def _http_probe(sock: socket.socket, host: str) -> str:
    # Send a HEAD request to coax a response from quiet web servers
    try:
        req = (
            f"HEAD / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: IoT-Scanner\r\n\r\n"
        ).encode("ascii", "ignore")
        sock.sendall(req)
        return _read_banner(sock, timeout=0.5)
    except Exception:
        return ""


def _classify_risk(port: int, banner: str) -> str:
    # Very rough signal to help users 
    banner_l = banner.lower()
    if port in _HIGH_RISK_PORTS or "telnet" in banner_l:
        return "high"
    if port in (22, 443):
        return "medium"
    return "low"


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, str, float]:
    start = time.time()
    sock: Optional[socket.socket] = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex avoids raising and gives a consistent error
        result = sock.connect_ex((host, int(port)))
        if result != 0:
            return port, False, "", round(time.time() - start, 3)

        banner = _read_banner(sock, timeout=0.5)

        # If the service stays silent, try a gentle HTTP nudge
        if not banner and port in _HTTP_PORTS:
            banner = _http_probe(sock, host)

        return port, True, banner, round(time.time() - start, 3)

    except Exception:
        return port, False, "", round(time.time() - start, 3)

    finally:
        _safe_close(sock)


def scan_ports(
    host: Optional[str] = None,
    *,
    target: Optional[str] = None,
    ports: Optional[List[int]] = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    timeout: float = DEFAULT_TIMEOUT,
    allow_public: bool = DEFAULT_ALLOW_PUBLIC,
) -> List[Dict[str, Any]]:

    # Accept either name for compatibility with older callers/tests
    target_host = target or host
    if not target_host:
        raise ValueError("host or target must be provided")

    # Safety guard: default to private/LAN scanning only
    if not allow_public and not helpers.is_private_host(target_host):
        raise ValueError("Refusing to scan non-private host without permission.")

    safe_ports = helpers.validate_ports(ports, default=DEFAULT_PORTS, max_ports=500)
    if not safe_ports:
        return []

    # Cap worker count to avoid overwhelming the system or target
    worker_count = min(max(1, max_workers), len(safe_ports), 100)

    try:
        logger.log({
            "event": "port_scan_start",
            "target": target_host,
            "ports_count": len(safe_ports)
        })
    except Exception:
        pass

    results: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(scan_port, target_host, p, timeout): p
            for p in safe_ports
        }

        for future in concurrent.futures.as_completed(futures):
            p = futures[future]
            try:
                port, is_open, banner, latency = future.result()
                risk = _classify_risk(port, banner)
            except Exception:
                port, is_open, banner, latency, risk = p, False, "", 0.0, "unknown"

            results.append({
                "port": port,
                "open": is_open,
                "banner": banner,
                "risk": risk,
                "latency": latency
            })

    # Sort for stable, readable output
    results.sort(key=lambda r: r["port"])

    try:
        logger.log({
            "event": "port_scan_finish",
            "target": target_host,
            "ports_scanned": len(results),
            "open_ports": sum(1 for r in results if r["open"])
        })
    except Exception:
        pass

    return results
