# src/scanner/iot_fingerprint.py
from __future__ import annotations

import socket
import ssl
import http.client
import hashlib
from urllib.parse import urlparse
from typing import Dict, Optional, Any


def _short(text: Optional[str], n: int = 200) -> str:
    # keep report output compact
    if not text:
        return ""
    return (text[:n] + "...") if len(text) > n else text


def http_probe(url: str, timeout: float = 2.0) -> Dict[str, Any]:
    # light HTTP touch to collect headers and a hint of the body
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or parsed.path
    port = parsed.port or (443 if scheme == "https" else 80)

    result: Dict[str, Any] = {
        "url": url,
        "status": None,
        "headers": {},
        "server": None,
        "body_snippet": "",
        "redirects": [],
    }

    conn = None
    try:
        conn = (
            http.client.HTTPSConnection(host, port, timeout=timeout)
            if scheme == "https"
            else http.client.HTTPConnection(host, port, timeout=timeout)
        )

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        conn.request("GET", path, headers={"User-Agent": "IoT-Fingerprint/1.0"})
        resp = conn.getresponse()

        result["status"] = resp.status
        headers = dict(resp.getheaders())
        result["headers"] = headers
        result["server"] = headers.get("Server") or headers.get("server")

        if resp.status in (301, 302, 303, 307, 308) and headers.get("Location"):
            result["redirects"].append(headers.get("Location"))

        try:
            body = resp.read(2048)
            result["body_snippet"] = _short(
                body.decode("utf-8", errors="ignore"), 500
            )
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return result


def tcp_banner(host: str, port: int, timeout: float = 1.0) -> str:
    # banner grab for services that talk first
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(0.5)
        try:
            return s.recv(1024).decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception:
        return ""


def _favicon_hash(
    host: str, port: int, scheme: str = "http", timeout: float = 2.0
) -> Optional[str]:
    # favicon hashes are often stable across device models
    conn = None
    try:
        conn = (
            http.client.HTTPSConnection(host, port, timeout=timeout)
            if scheme == "https"
            else http.client.HTTPConnection(host, port, timeout=timeout)
        )
        conn.request(
            "GET",
            "/favicon.ico",
            headers={"User-Agent": "IoT-Fingerprint/1.0"},
        )
        r = conn.getresponse()
        if r.status == 200:
            return hashlib.sha256(r.read()).hexdigest()
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return None


def _get_tls_info(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    # collect protocol and cert details without trust checks
    out: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                try:
                    cert = ss.getpeercert()
                    out["tls_version"] = ss.version()
                    c = ss.cipher()
                    out["cipher"] = c[0] if c else None
                    out["certificate"] = cert
                    sans = (
                        cert.get("subjectAltName", ())
                        if isinstance(cert, dict)
                        else ()
                    )
                    out["subject_alt_names"] = [v for (_, v) in sans] if sans else []
                except Exception:
                    pass
    except Exception:
        pass

    return out


def heuristic_classify(probe_results: Dict) -> str:
    # rule-of-thumb labels from headers and banners
    server = (probe_results.get("server") or "").lower()
    banner = (probe_results.get("banner") or "").lower()
    headers = probe_results.get("headers") or {}
    xpb = (
        headers.get("X-Powered-By")
        or headers.get("x-powered-by")
        or ""
    ).lower()

    if "lighttpd" in server or "boa" in server or "goahead" in banner:
        return "embedded-web-server"
    if "esp8266" in banner or "esp32" in banner or "esp" in banner:
        return "esp-device"
    if "openwrt" in server or "luci" in banner:
        return "router"
    if "mosquitto" in banner or "mqtt" in banner:
        return "mqtt-broker"
    if "nginx" in server:
        return "nginx"
    if "apache" in server or "httpd" in server:
        return "apache"
    if "uhttpd" in server or "busybox" in banner:
        return "small-linux"
    if "arduino" in banner or "avr" in banner:
        return "arduino-like"
    if xpb and "php" in xpb:
        return "php-based"

    return "unknown"


def fingerprint_http_target(url: str) -> Dict[str, Any]:
    # merge several weak signals into one profile
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or parsed.path
    port = parsed.port or (443 if scheme == "https" else 80)

    result = http_probe(url)
    banner = tcp_banner(host, port)
    result["banner"] = banner

    result["device_type"] = heuristic_classify({
        "server": result.get("server", ""),
        "banner": banner,
        "headers": result.get("headers", {}),
    })

    result["favicon_hash"] = _favicon_hash(host, port, scheme=scheme)

    if scheme == "https":
        result.update(_get_tls_info(host, port))

    return result


if __name__ == "__main__":
    # quick run for local probing
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:80"
    print(json.dumps(fingerprint_http_target(target), indent=2))
