# src/auditing/encryption_checker.py
import ssl
import socket
from typing import Dict, Any


def check_tls(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    # this is for inspection, not trust decisions
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result = {"host": host, "port": port}

    try:
        # open a raw socket, then layer TLS on top
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result.update({
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "certificate": ssock.getpeercert(),
                })
    except Exception as e:
        # network or handshake issues land here
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    # manual probe from the shell
    import sys
    import json

    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(json.dumps(check_tls(host), indent=2))
