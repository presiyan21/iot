# src/utils/helpers.py

from __future__ import annotations
from typing import Iterable, List
import ipaddress
import socket


def is_private_host(host: str) -> bool:
    # Returns True for loopback or private IPs, including resolved hostnames
    if not host:
        return False

    # Check if host is a direct IP
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass

    # Resolve hostname and check first resolved address
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            sockaddr = info[-1]
            candidate = sockaddr[0]
            try:
                cip = ipaddress.ip_address(candidate)
                if cip.is_private or cip.is_loopback:
                    return True
            except ValueError:
                continue
        return False
    except Exception:
        # DNS failed or other network issue: treat as public
        return False


def validate_ports(ports: Iterable[int] | None, *, default: List[int] | None = None,
                   max_ports: int = 200) -> List[int]:
    # Clean, deduplicate, and cap port list; fallback to default if empty
    if ports is None:
        return list(default) if default else []

    cleaned = []
    for p in ports:
        if isinstance(p, int):
            candidate = p
        else:
            # accept numeric strings
            try:
                candidate = int(str(p).strip())
            except Exception:
                raise ValueError(f"Invalid port value: {p!r}")
        if 1 <= candidate <= 65535:
            cleaned.append(candidate)

    unique = sorted(set(cleaned))

    if len(unique) > max_ports:
        unique = unique[:max_ports]

    if not unique and default:
        return list(default)
    return unique


def normalize_url(url: str) -> str:
    # Prepend http:// if scheme missing
    if not url:
        return url
    if not url.startswith("http://") and not url.startswith("https://"):
        return "http://" + url
    return url
