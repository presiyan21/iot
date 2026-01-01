# src/scanner/vuln_scanner.py

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Data directory for known vendor vulnerabilities
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
KNOWN_VULN_FILE = DATA_DIR / "known_vulnerabilities.json"

# Scoring weights
_PORT_WEIGHT = 1.0
_SIG_WEIGHT = 3.0
_EVIDENCE_BONUS = 0.5
_CONF_WEIGHT = {"high": 2.0, "medium": 1.0, "low": 0.5}


def load_known_vulns(path: Path | str = KNOWN_VULN_FILE) -> Dict[str, Any]:
    # Read the JSON of known vulnerabilities
    p = Path(path)
    try:
        if not p.exists():
            return {}
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _snippet(text: str, span: Optional[Tuple[int, int]]) -> str:
    # Grab a short piece around the match for context
    if not text:
        return ""
    if not span:
        return text[:100]
    s, e = span
    s = max(0, s - 20)
    e = min(len(text), e + 20)
    return text[s:e][:100]


def _match_signature(banner: str, sig: str) -> Optional[Dict[str, Any]]:
    # Check if a banner matches a signature
    if not sig or not banner:
        return None

    try:
        if sig.startswith("re:"):
            try:
                m = re.search(sig[3:], banner, flags=re.IGNORECASE)
                if m:
                    return {"sig": sig, "method": "regex", "span": m.span()}
            except re.error:
                return None
        else:
            idx = banner.lower().find(sig.lower())
            if idx >= 0:
                return {
                    "sig": sig,
                    "method": "substring",
                    "span": (idx, idx + len(sig))
                }
    except Exception:
        pass

    return None


def _avg_base_score(vulns: List[Dict]) -> float:
    # Average CVSS scores across vulnerabilities
    scores: List[float] = []
    for v in vulns or []:
        try:
            scores.append(float(v.get("base_score", 0)))
        except Exception:
            continue
    return sum(scores) / len(scores) if scores else 0.0


def _compute_score(
    port_match: bool,
    sig_match: bool,
    confidence: str,
    vuln_entries: List[Dict]
) -> float:
    # Combine base score with weights and evidence
    score = _avg_base_score(vuln_entries)

    if port_match:
        score += _PORT_WEIGHT
    if sig_match:
        score += _SIG_WEIGHT + _EVIDENCE_BONUS

    score += _CONF_WEIGHT.get((confidence or "low").lower(), 0.5)
    return round(min(max(score, 0.0), 10.0), 2)


def match_vulns_to_scan(
    scan_results: List[Dict],
    known_vulns: Optional[Dict] = None
) -> List[Dict]:
    # Match scan results against known vulnerabilities and build findings
    if known_vulns is None:
        known_vulns = load_known_vulns()

    findings: List[Dict] = []
    seen = set()  # Avoid duplicate entries

    for r in scan_results or []:
        if not r.get("open"):
            continue

        banner = str(r.get("banner") or "")
        try:
            port = int(r.get("port") or 0)
        except Exception:
            port = 0

        for vendor, vinfo in (known_vulns or {}).items():
            try:
                sigs = vinfo.get("signatures", []) or []
                ports = vinfo.get("ports", []) or []
                vuln_entries = vinfo.get("vulnerabilities", []) or []
                confidence = vinfo.get("confidence", "low")
            except Exception:
                continue

            port_match = port in ports
            matched_sig = None

            # Try to find a matching banner signature
            for sig in sigs:
                matched_sig = _match_signature(banner, sig)
                if matched_sig:
                    break

            if not port_match and not matched_sig:
                continue

            score = _compute_score(
                port_match=bool(port_match),
                sig_match=bool(matched_sig),
                confidence=confidence,
                vuln_entries=vuln_entries
            )

            vuln_ids = tuple(sorted(str(v.get("id") or "") for v in vuln_entries))
            key = (vendor, port, vuln_ids)

            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "vendor": vendor,
                "port": port,
                "banner": banner,
                "vulns": vuln_entries,
                "confidence": confidence,
                "score": score,
                "evidence": {
                    "matched_on": "banner" if matched_sig else "port",
                    "signature": matched_sig.get("sig") if matched_sig else "",
                    "method": matched_sig.get("method") if matched_sig else "",
                    "snippet": _snippet(
                        banner,
                        matched_sig.get("span") if matched_sig else None
                    ),
                }
            })

    # Sort by score descending, then port ascending
    findings.sort(
        key=lambda x: (-float(x.get("score", 0.0)), int(x.get("port", 0)))
    )
    return findings


if __name__ == "__main__":
    import sys
    from src.scanner.port_scanner import scan_ports  # type: ignore

    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    scan = scan_ports(host)
    matched = match_vulns_to_scan(scan)
    print(json.dumps(matched, indent=2))
