# src/auditing/config_auditor.py
from typing import Dict, List, Any, Optional

# pull in helpers when present; fall back to no-op stubs
try:
    from src.auditing.firmware_checker import check_firmware_hash  # type: ignore
except Exception:
    def check_firmware_hash(_v, _db=None):
        return {
            "ok": False,
            "match": False,
            "issue": "checker_unavailable",
            "remediation": ["Firmware checker not available."]
        }

try:
    from src.auditing.password_policy import assess_password_policy  # type: ignore
except Exception:
    def assess_password_policy(cfg: Dict) -> List[Dict]:
        return []

try:
    from src.auditing.encryption_checker import assess_encryption_settings  # type: ignore
except Exception:
    def assess_encryption_settings(cfg: Dict) -> List[Dict]:
        return []


def _score_from_severity(sev: str) -> float:
    s = (sev or "").lower()
    return {"critical": 9.5, "high": 7.0, "medium": 4.0, "low": 1.0}.get(s, 2.0)


def _impact_from_severity(sev: str) -> str:
    s = (sev or "").lower()
    return {
        "critical": "severe",
        "high": "major",
        "medium": "moderate",
        "low": "minor"
    }.get(s, "unknown")


def _mkfinding(
    fid: str,
    issue: str,
    severity: str,
    detail: str,
    evidence: Optional[Dict[str, Any]] = None,
    remediation: Optional[List[str]] = None
) -> Dict:
    # central shape for all findings
    return {
        "id": fid,
        "issue": issue,
        "severity": severity,
        "impact": _impact_from_severity(severity),
        "score": _score_from_severity(severity),
        "detail": detail,
        "evidence": evidence or {},
        "remediation": remediation or []
    }


def _looks_like_default_passwords(cfg: Dict) -> List[Dict]:
    out = []

    # fields where credentials usually hide
    candidates = []
    if "admin_password" in cfg:
        candidates.append(("admin_password", cfg.get("admin_password")))
    if "password" in cfg:
        candidates.append(("password", cfg.get("password")))
    if "credentials" in cfg and isinstance(cfg["credentials"], dict):
        for k, v in cfg["credentials"].items():
            candidates.append((f"credentials.{k}", v))

    defaults = {"admin", "password", "1234", "123456", "root", "toor"}

    for field, val in candidates:
        try:
            if not val:
                continue
            sval = str(val).strip().lower()
            if sval in defaults or len(sval) < 6:
                out.append({
                    "field": field,
                    "value": sval,
                    "reason": "short_or_common"
                })
        except Exception:
            continue

    return out


def audit_config(config: Dict, context: Optional[Dict] = None) -> List[Dict]:
    findings: List[Dict] = []

    # fast checks for risky toggles
    if config.get("telnet", False):
        findings.append(_mkfinding(
            "CFG-001",
            "Telnet enabled",
            "high",
            "Telnet is enabled; use SSH or disable.",
            evidence={"source": "config", "field": "telnet"},
            remediation=["Disable Telnet; enable SSH with strong auth."]
        ))

    if config.get("admin_http", False):
        findings.append(_mkfinding(
            "CFG-002",
            "Admin interface over HTTP",
            "high",
            "Admin interface accessible without TLS.",
            evidence={"source": "config", "field": "admin_http"},
            remediation=["Enable HTTPS for admin interface; use valid certs."]
        ))

    if config.get("debug", False):
        findings.append(_mkfinding(
            "CFG-003",
            "Debug enabled",
            "medium",
            "Debug mode may leak internal info.",
            evidence={"source": "config", "field": "debug"},
            remediation=["Turn off debug mode in production."]
        ))

    open_ports = config.get("open_ports") or []
    if any(p in (23, 2323) for p in open_ports):
        findings.append(_mkfinding(
            "CFG-004",
            "Telnet port open",
            "high",
            "Telnet ports are exposed in configuration.",
            evidence={"source": "config", "field": "open_ports", "ports": open_ports},
            remediation=["Close Telnet ports; filter traffic or require auth."]
        ))

    # many open ports usually means a wider attack surface
    if isinstance(open_ports, (list, tuple)) and len(open_ports) > 6:
        findings.append(_mkfinding(
            "CFG-005",
            "Large open port surface",
            "medium",
            f"Configuration exposes {len(open_ports)} open ports; increases attack surface.",
            evidence={
                "source": "config",
                "field": "open_ports",
                "count": len(open_ports)
            },
            remediation=["Limit exposed services; use network segmentation."]
        ))

    weak = _looks_like_default_passwords(config)
    if weak:
        findings.append(_mkfinding(
            "CFG-006",
            "Default/weak credentials found",
            "high",
            "Configuration contains likely default or weak credentials.",
            evidence={"source": "config", "fields": weak},
            remediation=["Replace defaults; enforce stronger password rules and rotation."]
        ))

    # password policy hints, when helper is present
    try:
        pw_findings = assess_password_policy(config)
        for i, f in enumerate(pw_findings or []):
            fid = f.get("id") or f"PW-{100 + i}"
            findings.append({
                "id": fid,
                "issue": f.get("issue", "password_policy"),
                "severity": f.get("severity", "medium"),
                "impact": _impact_from_severity(f.get("severity", "medium")),
                "score": _score_from_severity(f.get("severity", "medium")),
                "detail": f.get("detail", ""),
                "evidence": f.get("evidence", {}),
                "remediation": f.get("remediation", [])
            })
    except Exception:
        pass

    # crypto and TLS related checks
    try:
        enc_findings = assess_encryption_settings(config)
        for i, f in enumerate(enc_findings or []):
            fid = f.get("id") or f"ENC-{100 + i}"
            findings.append({
                "id": fid,
                "issue": f.get("issue", "encryption"),
                "severity": f.get("severity", "medium"),
                "impact": _impact_from_severity(f.get("severity", "medium")),
                "score": _score_from_severity(f.get("severity", "medium")),
                "detail": f.get("detail", ""),
                "evidence": f.get("evidence", {}),
                "remediation": f.get("remediation", [])
            })
    except Exception:
        pass

    # firmware integrity path
    fw = config.get("firmware")
    if isinstance(fw, dict):
        vendor = fw.get("vendor")
        version = fw.get("version")
        sha = fw.get("sha256") or fw.get("hash") or fw.get("firmware_hash")
        signed_flag = fw.get("signed", None)

        fw_input = {
            "vendor": vendor,
            "version": version,
            "sha256": sha,
            "signed": signed_flag
        }
        fw_result = check_firmware_hash(fw_input)

        if not fw_result.get("ok", False):
            issue_code = fw_result.get("issue", "firmware_issue")
            sev = "high" if issue_code in (
                "db_missing",
                "hash_mismatch",
                "matched_unsigned"
            ) else "medium"

            findings.append(_mkfinding(
                "FW-001",
                "Firmware integrity not verified",
                sev,
                f"Firmware integrity check reported: {issue_code}",
                evidence=fw_result.get("evidence", {}),
                remediation=fw_result.get("remediation", [])
                or ["Verify firmware source and signatures."]
            ))
        else:
            findings.append(_mkfinding(
                "FW-002",
                "Firmware validated",
                "low",
                "Firmware hash matches known signed release.",
                evidence=fw_result.get("evidence", {})
            ))

    return findings


if __name__ == "__main__":
    # quick CLI hook for local runs
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m src.auditing.config_auditor config.json")
        raise SystemExit(1)

    cfg = json.load(open(sys.argv[1], "r", encoding="utf-8"))
    print(json.dumps(audit_config(cfg), indent=2))
