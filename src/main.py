# src/main.py

from __future__ import annotations
import argparse
import json
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.scanner.port_scanner import scan_ports
from src.scanner.vuln_scanner import match_vulns_to_scan, load_known_vulns
from src.scanner.iot_fingerprint import fingerprint_http_target
from src.scanner.reporting import create_full_report, generate_html_report

from src.auditing.config_auditor import audit_config
from src.pentesting.exploit_simulator import simulate_reflected_xss, simulate_insecure_update
from src.pentesting.brute_force import brute_force_http_login

from src.utils.logger import log
from src.utils.helpers import is_private_host

ART_DIR = Path(__file__).resolve().parents[1] / "artifacts"
ART_DIR.mkdir(parents=True, exist_ok=True)


def _build_base_url(host: str, port: Optional[int], scheme: str = "http") -> str:
    # Construct URL with port if non-standard
    if port is None:
        return f"{scheme}://{host}"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _parse_target(target: str) -> Tuple[str, Optional[int], str]:
    # Extract host, port, and scheme from target string
    t = target.strip()
    scheme = "http"
    if "://" in t:
        scheme, t = t.split("://", 1)
    host_part = t.split("/")[0]
    if ":" in host_part:
        host, port_s = host_part.split(":", 1)
        try:
            port = int(port_s)
        except Exception:
            port = None
    else:
        host = host_part
        port = None
    return host, port, scheme


def _normalize_allowed_hosts(allowed: Optional[List[str]]) -> List[str]:
    # Clean empty entries and whitespace
    return [h.strip() for h in (allowed or []) if h and h.strip()]


def run_full_audit(target: str,
                   ports: Optional[List[int]] = None,
                   allowed_hosts: Optional[List[str]] = None,
                   run_pentest: bool = True,
                   preferred_port: Optional[int] = None) -> Dict:
    # Main audit sequence
    host, target_port, target_scheme = _parse_target(target)
    allowed_hosts = _normalize_allowed_hosts(allowed_hosts)

    # skip targets not allowed
    if allowed_hosts and host not in allowed_hosts:
        return {"error": "target_not_allowed", "detail": f"{host} not in allowed_hosts. Aborting."}
    if not is_private_host(host) and not allowed_hosts:
        return {"error": "target_not_private", "detail": f"{host} is not private/local. Aborting."}

    log({"event": "audit_started", "target": host})

    # scan ports
    ports_to_scan = ports or [22, 80, 443, 8080]
    ps = scan_ports(target=host, ports=ports_to_scan)
    log({"event": "port_scan", "target": host, "ports_scanned": [p.get("port") for p in ps]})

    # match known vulnerabilities
    kv = load_known_vulns()
    vulns = match_vulns_to_scan(ps, kv)
    log({"event": "vuln_matching", "target": host, "matches": len(vulns)})

    # select a port for HTTP interaction
    open_ports = [p.get("port") for p in ps if p.get("open")]
    chosen_port: Optional[int] = None
    if preferred_port and preferred_port in open_ports:
        chosen_port = preferred_port
    else:
        for p in (8080, 80, 443):
            if p in open_ports:
                chosen_port = p
                break
        if not chosen_port and open_ports:
            chosen_port = open_ports[0]

    fingerprint = {}
    if chosen_port:
        scheme = "https" if chosen_port == 443 else "http"
        base = _build_base_url(host, chosen_port, scheme=scheme)
        try:
            fingerprint = fingerprint_http_target(base)
        except Exception as e:
            fingerprint = {"error": str(e)}
        log({"event": "fingerprint", "target": host, "port": chosen_port})

    # configuration audit
    audits = []
    try:
        import requests
        cfg_port = chosen_port or target_port or 80
        cfg_scheme = "https" if cfg_port == 443 else "http"
        cfg_url = _build_base_url(host, cfg_port, scheme=cfg_scheme) + "/config.json"
        s = requests.Session()
        r = s.get(cfg_url, timeout=2)
        if r.status_code == 200:
            cfg = r.json()
            audits = audit_config(cfg)
            log({"event": "config_audit", "target": host, "findings": len(audits)})
    except Exception:
        pass  

    # pentest simulations 
    pentest_results = []
    if run_pentest:
        base_scheme = "https" if chosen_port == 443 else "http"
        base = _build_base_url(host, chosen_port or target_port, scheme=base_scheme)
        pentest_results.append(simulate_reflected_xss(f"{base}/search"))
        pentest_results.append(simulate_insecure_update(base))
        try:
            bf = brute_force_http_login(f"{base}/login", username="admin", passwords=None, stop_on_success=True)
            pentest_results.append(bf)
        except Exception as e:
            pentest_results.append({"test": "brute_force", "error": str(e)})

    report = create_full_report(host, ps, vulns, fingerprint, audits, pentest_results)
    log({"event": "report_written", "target": host, "path": str(ART_DIR / 'full_report.json')})
    return report


def demo_start_simulated_device(port: int = 8080):
    # Launch a lightweight simulated IoT device for testing
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json

    class SimDeviceHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/config.json"):
                cfg = {
                    "telnet": True,
                    "admin_http": True,
                    "debug": True,
                    "open_ports": [23, port],
                    "firmware": {"version": "1.0.0", "signed": False, "sha256": "a" * 64}
                }
                data = json.dumps(cfg).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            if self.path.startswith("/search"):
                content = f"<html><body>{self.path}</body></html>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(content)
                return

            if self.path.startswith("/.well-known/firmware"):
                content = json.dumps({"latest": "1.0.1", "signed": False}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(content)
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if self.path.startswith("/login"):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode()
                if "username=admin" in body and "password=admin" in body:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Welcome admin")
                else:
                    self.send_response(401)
                    self.end_headers()

    server = HTTPServer(("127.0.0.1", port), SimDeviceHandler)
    print(f"[Demo Device] Running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--demo-port", type=int, default=8080)
    parser.add_argument("--target", type=str, help="target host (defaults to 127.0.0.1 when --demo)")
    parser.add_argument("--no-pentest", action="store_true")
    parser.add_argument("--output-html", action="store_true")
    parser.add_argument("--allowed-hosts", type=str, default="127.0.0.1,localhost")

    args = parser.parse_args()
    allowed_hosts = [h.strip() for h in (args.allowed_hosts or "").split(",") if h.strip()]

    # start demo device if requested
    if args.demo:
        t = threading.Thread(target=demo_start_simulated_device, args=(args.demo_port,), daemon=True)
        t.start()
        time.sleep(0.5)

    target = args.target or ("127.0.0.1" if args.demo else None)
    if not target:
        parser.print_help()
        return

    # run audit
    report = run_full_audit(target,
                            ports=[22, 80, 8080, 23],
                            allowed_hosts=allowed_hosts,
                            run_pentest=(not args.no_pentest),
                            preferred_port=(args.demo_port if args.demo else None))
    print(json.dumps(report, indent=2))

    if args.output_html:
        try:
            html_path = generate_html_report(report)
            print(f"[*] HTML report written to {html_path}")
        except Exception as e:
            print("[!] Failed to write HTML report:", e)

    # keep demo running
    if args.demo:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()