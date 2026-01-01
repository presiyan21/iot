# tests/port_scanner_test.py

import pytest
from unittest.mock import patch, MagicMock

from src.scanner.port_scanner import scan_ports


def mock_socket_open_port(port_banner: bytes):
    # Socket connects and returns a banner
    m = MagicMock()
    m.connect_ex.return_value = 0
    m.recv.return_value = port_banner
    return m


def mock_socket_closed_port():
    # Socket fails to connect (closed port)
    m = MagicMock()
    m.connect_ex.return_value = 1
    m.recv.return_value = b""
    return m


@patch("socket.socket")
def test_scan_ports_mixed_open_and_closed(mock_socket_class):
    # Scenario with two open ports (22, 80) and one closed (9999)
    test_ports = [22, 80, 9999]

    socket_instances = [
        mock_socket_open_port(b"OpenSSH_7.9p1 Debian"),
        mock_socket_open_port(b"Apache/2.4.25 (Debian)"),
        mock_socket_closed_port(),
    ]
    mock_socket_class.side_effect = socket_instances

    results = scan_ports(
        target="192.168.1.10",
        ports=test_ports,
        timeout=1,
        max_workers=3
    )

    assert isinstance(results, list)
    assert len(results) == len(test_ports)

    results_by_port = {r["port"]: r for r in results}

    # SSH port open and banner contains OpenSSH
    assert results_by_port[22]["open"] is True
    assert "OpenSSH" in results_by_port[22]["banner"]

    # HTTP port open and banner contains Apache
    assert results_by_port[80]["open"] is True
    assert "Apache" in results_by_port[80]["banner"]

    # Closed port with empty banner
    assert results_by_port[9999]["open"] is False
    assert results_by_port[9999]["banner"] == ""

