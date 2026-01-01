# tests/auditor_test.py

import json
import pytest
from pathlib import Path
from src.auditing.firmware_checker import load_firmware_db, check_firmware_hash

def make_test_db(path: Path):
    # Create a firmware DB for testing
    db = {
        "AcmeCorp": {
            "1.0.0": {"sha256": "aa" * 32, "signed": False},
            "1.0.1": {"sha256": "bb" * 32, "signed": True}
        }
    }
    path.write_text(json.dumps(db), encoding="utf-8")
    return db

def test_load_firmware_db_and_checks(tmp_path: Path):
    # Test loading DB and verifying firmware hashes
    db_file = tmp_path / "firmware_hashes.json"
    db = make_test_db(db_file)

    loaded = load_firmware_db(str(db_file))
    assert isinstance(loaded, dict)
    assert "AcmeCorp" in loaded

    # check unsigned firmware
    unsigned_hash = loaded["AcmeCorp"]["1.0.0"]["sha256"]
    res_unsigned = check_firmware_hash({"vendor": "AcmeCorp", "version": "1.0.0", "sha256": unsigned_hash}, loaded)
    assert res_unsigned["match"] is True
    assert res_unsigned["vendor"] == "AcmeCorp"
    assert res_unsigned["version"] == "1.0.0"
    assert res_unsigned["expected_hash"] == unsigned_hash.lower()
    assert res_unsigned["ok"] is False
    assert res_unsigned["issue"] in ("matched_unsigned", "matched_signed", "matched")

    # check signed firmware
    signed_hash = loaded["AcmeCorp"]["1.0.1"]["sha256"]
    res_signed = check_firmware_hash({"vendor": "AcmeCorp", "version": "1.0.1", "sha256": signed_hash}, loaded)
    assert res_signed["match"] is True
    assert res_signed["ok"] is True
    assert res_signed["issue"] in ("matched_signed", "matched")

def test_check_firmware_hash_mismatch(tmp_path: Path):
    # Test hash mismatch and remediation
    db_file = tmp_path / "firmware_hashes.json"
    make_test_db(db_file)
    bogus = "deadbeef" * 8
    db = load_firmware_db(str(db_file))
    res = check_firmware_hash(bogus, db)
    assert res["match"] is False
    assert res["ok"] is False
    assert res["issue"] == "hash_mismatch"
    assert "remediation" in res and isinstance(res["remediation"], list)
