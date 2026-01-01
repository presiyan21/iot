# src/auditing/firmware_checker.py
from __future__ import annotations

import json
import os
import hashlib
from typing import Any, Dict, Optional


# allow runtime override of the firmware DB path
try:
    from src import config 
    _DB_PATH = getattr(config, "FIRMWARE_DB_PATH", None)
except Exception:
    _DB_PATH = None


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
DEFAULT_FIRMWARE_FILE = os.path.join(DATA_DIR, "firmware_hashes.json")
FIRMWARE_FILE = _DB_PATH or DEFAULT_FIRMWARE_FILE


def load_firmware_db(path: str = FIRMWARE_FILE) -> Dict[str, Any]:
    # read local JSON with known hashes
    try:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def hash_file_sha256(path: str) -> str:
    # stream the file to avoid loading large images in memory
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def _normalize_hex(h: Optional[str]) -> Optional[str]:
    if not h:
        return None
    return h.strip().lower()


def compute_hash_match(expected: str, actual: str) -> Dict[str, Any]:
    e = _normalize_hex(expected)
    a = _normalize_hex(actual)
    return {
        "match": bool(e and a and e == a),
        "expected": e,
        "actual": a,
    }


def check_firmware_hash(
    value: Any,
    db: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    # main entry: compare a given hash against the database
    if db is None:
        db = load_firmware_db()

    actual_hash = None
    input_vendor = None
    input_version = None

    if isinstance(value, dict):
        actual_hash = _normalize_hex(
            value.get("sha256") or value.get("hash") or ""
        )
        input_vendor = value.get("vendor")
        input_version = value.get("version")
    else:
        actual_hash = _normalize_hex(str(value))

    result: Dict[str, Any] = {
        "ok": False,
        "match": False,
        "vendor": None,
        "version": None,
        "expected_hash": None,
        "actual_hash": actual_hash,
        "issue": None,
        "remediation": [],
        "evidence": {},
    }

    if not db:
        result["issue"] = "db_missing"
        result["remediation"] = [
            "Provide a firmware hash database or configure FIRMWARE_DB_PATH."
        ]
        return result

    # try a direct vendor/version hit first
    if input_vendor and input_version:
        vendor_record = db.get(input_vendor, {})
        ver_record = vendor_record.get(input_version)

        if ver_record:
            expected = None
            signed_flag = False

            if isinstance(ver_record, dict):
                expected = _normalize_hex(ver_record.get("sha256"))
                signed_flag = bool(ver_record.get("signed", False))
            elif isinstance(ver_record, str):
                expected = _normalize_hex(ver_record)

            cmp = compute_hash_match(expected, actual_hash)
            result.update({
                "vendor": input_vendor,
                "version": input_version,
                "expected_hash": expected,
                "match": cmp["match"],
                "evidence": {
                    "method": "targeted_lookup",
                    "match_details": cmp,
                    "signed": signed_flag,
                },
            })

            if cmp["match"]:
                result["ok"] = signed_flag
                result["issue"] = (
                    "matched_signed" if signed_flag else "matched_unsigned"
                )
                if not signed_flag:
                    result["remediation"] = [
                        "Use signed firmware and verify signatures."
                    ]
                return result

            result["issue"] = "hash_mismatch"
            result["remediation"] = [
                "Do not install unverified firmware.",
                "Confirm firmware source and integrity.",
            ]
            return result

    # otherwise, walk the whole DB
    for vendor in sorted(db.keys()):
        versions = db[vendor]
        for ver in sorted(versions.keys()):
            rec = versions[ver]
            expected = None
            signed_flag = False

            if isinstance(rec, dict):
                expected = _normalize_hex(rec.get("sha256"))
                signed_flag = bool(rec.get("signed", False))
            elif isinstance(rec, str):
                expected = _normalize_hex(rec)

            if not expected:
                continue

            cmp = compute_hash_match(expected, actual_hash)
            if cmp["match"]:
                result.update({
                    "vendor": vendor,
                    "version": ver,
                    "expected_hash": expected,
                    "match": True,
                    "evidence": {
                        "method": "db_scan",
                        "match_details": cmp,
                        "signed": signed_flag,
                    },
                })
                result["ok"] = signed_flag
                result["issue"] = (
                    "matched_signed" if signed_flag else "matched_unsigned"
                )
                if not signed_flag:
                    result["remediation"] = [
                        "Require signed firmware before deployment."
                    ]
                return result

    # nothing matched
    result["issue"] = "hash_mismatch"
    result["remediation"] = [
        "Firmware hash not found in database.",
        "Obtain official firmware from the vendor.",
    ]
    result["evidence"] = {
        "method": "db_scan",
        "match_details": compute_hash_match("", actual_hash),
    }
    return result


if __name__ == "__main__":
    # CLI for ad-hoc checks
    import sys
    import json

    if len(sys.argv) < 2:
        print(
            "Usage: python firmware_checker.py <sha256> "
            "OR python firmware_checker.py <vendor> <version> <sha256>"
        )
        raise SystemExit(1)

    if len(sys.argv) == 2:
        res = check_firmware_hash(sys.argv[1])
    else:
        vendor, version, sha = sys.argv[1:4]
        res = check_firmware_hash({
            "vendor": vendor,
            "version": version,
            "sha256": sha,
        })

    print(json.dumps(res, indent=2))
