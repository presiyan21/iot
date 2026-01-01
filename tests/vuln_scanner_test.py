# tests/vuln_scanner_test.py

from src.scanner.vuln_scanner import match_vulns_to_scan

def test_match_generic_embedded_server():
    scan_results = [
        {"port": 8080, "open": True, "banner": "GenericEmbeddedServer v1.2 (lighttpd)"},
        {"port": 1883, "open": True, "banner": "MQTT Broker (mosquitto)"},
        {"port": 9999, "open": False, "banner": ""},
    ]

    # Explicit known_vulns for this test
    known_vulns = {
        "GenericEmbeddedServer": {
            "signatures": ["lighttpd", "GenericEmbeddedServer"],
            "ports": [8080],
            "confidence": "high",
            "vulnerabilities": [
                {"id": "CVE-XXXX-0001", "base_score": 7.5, "desc": "Example RCE in web UI"}
            ]
        },
        "GenericMQTT": {
            "signatures": ["mosquitto"],
            "ports": [1883],
            "confidence": "medium",
            "vulnerabilities": [
                {"id": "CVE-XXXX-0002", "base_score": 5.0, "desc": "Example auth bypass"}
            ]
        }
    }

    matches = match_vulns_to_scan(scan_results, known_vulns)

    # Assertions
    assert isinstance(matches, list)
    vendors = {m["vendor"] for m in matches}
    assert "GenericEmbeddedServer" in vendors

    gen = next(m for m in matches if m["vendor"] == "GenericEmbeddedServer")
    assert gen["port"] == 8080
    assert isinstance(gen["score"], float)
    assert gen["score"] >= 1.0
    assert isinstance(gen["vulns"], list)
    assert any(v.get("id") == "CVE-XXXX-0001" for v in gen["vulns"])
