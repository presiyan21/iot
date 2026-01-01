# src/scanner/reporting.py

from __future__ import annotations

import json
import os
import tempfile
import time
import html
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from src import config
except Exception:
    config = None


# Determine where reports and artifacts are written
def _get_artifacts_dir() -> Path:
    if config is not None and getattr(config, "ARTIFACTS_DIR", None):
        return Path(config.ARTIFACTS_DIR).resolve()
    # Default to artifacts folder
    return Path(__file__).resolve().parents[2] / "artifacts"


# Default severity thresholds for risk scoring
_DEFAULT_THRESHOLDS = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.0}
REPORT_RISK_THRESHOLDS = getattr(config, "REPORT_RISK_THRESHOLDS", _DEFAULT_THRESHOLDS)
DEFAULT_SUMMARY_LIMIT = int(getattr(config, "REPORT_SUMMARY_LIMIT", 10))


def _ensure_artifacts_dir_exists() -> None:
    # Create artifacts folder if missing
    d = _get_artifacts_dir()
    if not d.exists():
        d.mkdir(parents=True, exist_ok=True)


# Atomic writes prevent partial files from appearing if the process is interrupted
def _atomic_write_json(path: Path, data: Any) -> None:
    _ensure_artifacts_dir_exists()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(path))
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# Atomic write for text/HTML outputs
def _atomic_write_text(path: Path, text: str) -> None:
    _ensure_artifacts_dir_exists()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(path))
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# Map textual confidence labels to numeric weights
def _confidence_value(conf: Optional[str]) -> float:
    if not conf:
        return 1.0
    conf = conf.lower()
    if conf in ("high", "high-confidence"):
        return 3.0
    if conf in ("medium", "med"):
        return 2.0
    if conf in ("low", "low-confidence"):
        return 1.0
    return 1.5


# Increase score for commonly exposed services
def _exposure_value(port: Optional[int]) -> float:
    if not port:
        return 0.0
    well_known = {21, 22, 23, 53, 80, 443, 8080, 554, 8883}
    return 1.5 if port in well_known else 0.5


# Compute a normalised risk score 0–10
def score_vulnerability(vuln: Dict) -> float:
    base = float(vuln.get("score", 0.0)) if isinstance(vuln.get("score"), (int, float)) else 0.0
    base_component = base if base <= 10 else min(10.0, base / 10.0)
    raw = base_component * 1.5 + _exposure_value(vuln.get("port")) + _confidence_value(vuln.get("confidence"))
    return float(round(max(0.0, min(10.0, raw)), 2))


def severity_from_score(score: float) -> str:
    # Map numeric score to severity category
    thr = REPORT_RISK_THRESHOLDS
    if score >= thr.get("critical", 9.0):
        return "critical"
    if score >= thr.get("high", 7.0):
        return "high"
    if score >= thr.get("medium", 4.0):
        return "medium"
    return "low"


# Provide recommended remediation steps based on simple keyword heuristics
def remediation_for_vuln(vuln: Dict) -> List[str]:
    rem: List[str] = []
    vid = (vuln.get("id") or "").lower()
    desc = json.dumps(vuln.get("desc")) if isinstance(vuln.get("desc"), (list, dict)) else str(vuln.get("desc") or "")
    desc = desc.lower()

    if "cve" in vid:
        rem.append("Apply vendor security patch or firmware update.")
    if "traversal" in desc:
        rem.append("Sanitise file paths and enforce strict input validation.")
    if "xss" in desc:
        rem.append("Encode output and validate user input.")
    if "default password" in desc or vuln.get("type") == "default-credential":
        rem.append("Remove default credentials and enforce strong passwords.")
    if "firmware" in desc or "update" in desc:
        rem.append("Use signed firmware and verify integrity before deployment.")

    if not rem:
        rem.append("Review finding and apply vendor-recommended mitigations.")
    return rem


# Deduplicate vulnerabilities to avoid double-counting
def _dedupe_vulns(vuln_list: List[Dict]) -> List[Dict]:
    seen = set()
    out: List[Dict] = []
    for v in vuln_list or []:
        key = (str(v.get("vendor")), int(v.get("port") or 0), json.dumps(v.get("vulns", []), sort_keys=True))
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def _severity_counts(vuln_matches: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vuln_matches or []:
        sev = (v.get("severity") or "low").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _top_issues(vuln_matches: List[Dict], limit: int = DEFAULT_SUMMARY_LIMIT) -> List[Dict]:
    # Return top-N issues sorted by computed risk
    return sorted(vuln_matches, key=lambda v: v.get("computed_score", 0), reverse=True)[:limit]


# Summarise pentest simulation results
def _pentest_summary(pentest: List[Dict]) -> Dict:
    summary = {"tests_run": len(pentest or []), "successful": 0, "high_confidence": 0, "details": []}
    for t in pentest or []:
        success = bool(t.get("success") or t.get("issue"))
        conf = float(t.get("confidence") or 0.0) if isinstance(t.get("confidence"), (int, float)) else 0.0
        if success:
            summary["successful"] += 1
        if conf >= 0.7:
            summary["high_confidence"] += 1
        summary["details"].append({
            "test": t.get("test"),
            "success": success,
            "confidence": round(conf, 2),
        })
    return summary


def _audit_summary(audits: List[Dict]) -> Dict:
    summary = {"total": len(audits or []), "high": 0, "medium": 0, "low": 0, "ids": []}
    for a in audits or []:
        sev = (a.get("severity") or "low").lower()
        if sev in ("high", "critical"):
            summary["high"] += 1
        elif sev == "medium":
            summary["medium"] += 1
        else:
            summary["low"] += 1
        summary["ids"].append(a.get("id"))
    return summary


# Build full JSON report and persist atomically
def create_full_report(
    target: str,
    port_scan: List[Dict],
    vulns: List[Dict],
    fingerprint: Dict,
    audits: List[Dict],
    pentest: List[Dict],
) -> Dict:
    ts = int(time.time())
    vulns_clean = _dedupe_vulns(vulns or [])

    enriched: List[Dict] = []
    for v in vulns_clean:
        vcopy = dict(v)
        vcopy["computed_score"] = score_vulnerability(v)
        vcopy["severity"] = severity_from_score(vcopy["computed_score"])
        vcopy.setdefault("remediation", remediation_for_vuln(vcopy))
        enriched.append(vcopy)

    report = {
        "metadata": {
            "target": target,
            "generated_at": ts,
            "generated_iso": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
            "tool": "IOT-Scanner",
            "tool_version": getattr(config, "TOOL_VERSION", "0.1.0"),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
        },
        "summary": {
            "severity_counts": _severity_counts(enriched),
            "top_risks": _top_issues(enriched),
            "pentest": _pentest_summary(pentest),
            "audits": _audit_summary(audits),
        },
        "port_scan": port_scan or [],
        "vuln_matches": enriched,
        "fingerprint": fingerprint or {},
        "audits": audits or [],
        "pentest_simulations": pentest or [],
    }

    out_path = _get_artifacts_dir() / "full_report.json"
    _atomic_write_json(out_path, report)
    return report


def _escape(text: Optional[str]) -> str:
    # Safely encode text for HTML
    return html.escape(str(text), quote=True) if text is not None else ""


# Generate a standalone HTML report for quick viewing
def generate_html_report(report: Dict, filename: Optional[str] = None) -> Path:
    _ensure_artifacts_dir_exists()
    outfile = Path(filename) if filename else (_get_artifacts_dir() / "full_report.html")

    meta = report.get("metadata", {})
    summary = report.get("summary", {})
    vuln_matches = report.get("vuln_matches", [])
    open_ports = [p for p in report.get("port_scan", []) if p.get("open")]

    lines = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'/>",
        "<title>Scan Report</title>",
        "<style>body{font-family:Arial;max-width:1000px;margin:auto}</style>",
        "</head><body>",
        f"<h1>Scan Report</h1><p>{_escape(meta.get('generated_iso'))}</p>",
    ]

    lines.append("<h2>Open Ports</h2><ul>")
    for p in open_ports:
        lines.append(f"<li>{_escape(p.get('port'))}: {_escape(p.get('banner'))}</li>")
    lines.append("</ul>")

    lines.append("<h2>Findings</h2><ul>")
    for v in vuln_matches:
        lines.append(
            f"<li><strong>{_escape(v.get('id'))}</strong> "
            f"({v.get('severity')}, score {v.get('computed_score')})</li>"
        )
    lines.append("</ul></body></html>")

    _atomic_write_text(outfile, "\n".join(lines))
    return outfile
