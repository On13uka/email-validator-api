"""Hermetic tests for the Email Breach Status feature (Have I Been Pwned).

Covers:
  1. Email with breaches -> breach_status.breached=true, breaches listed.
  2. Email with no breaches (HIBP 404) -> breach_status.breached=false.
  3. HIBP_API_KEY missing -> graceful degradation (breach_status=null + error).
  4. is_trusted_identity logic:
       breached + disposable -> false; clean + verified + not-disposable -> true.
  5. Cache hit: second call makes 0 HTTP requests to HIBP.

No real HIBP calls. HIBP HTTP is mocked via patching _fetch_hibp_breach; the
urllib path is never exercised. DNS/SMTP use the shared conftest fixtures.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app import main as evmain


# ---------------------------------------------------------------------------
# Breach-specific fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def isolated_breach_cache(tmp_path, monkeypatch):
    """Point the breach cache at a tmp dir so tests never pollute real cache."""
    cache_dir = tmp_path / "breach-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(evmain, "BREACH_CACHE_DIR", cache_dir)
    return cache_dir


@pytest.fixture
def hibp_key_set(monkeypatch):
    """Set a fake HIBP_API_KEY in the process environment."""
    monkeypatch.setenv("HIBP_API_KEY", "test-key-1234")
    yield
    monkeypatch.delenv("HIBP_API_KEY", raising=False)


@pytest.fixture
def hibp_key_missing(monkeypatch):
    """Ensure HIBP_API_KEY is absent from env AND from the .env file."""
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    # Short-circuit _load_env_file so it never reads a real .env.
    monkeypatch.setattr(evmain, "_load_env_file", lambda: {})


# Sample HIBP breach payloads (shape returned by HIBP API v3).
_HIBP_BREACHES = [
    {
        "Name": "LinkedIn",
        "BreachDate": "2016-05-21",
        "DataClasses": ["Emails", "Passwords"],
    },
    {
        "Name": "Adobe",
        "BreachDate": "2013-10-04",
        "DataClasses": ["Emails", "Password hints"],
    },
]


# ---------------------------------------------------------------------------
# 1. Email with breaches
# ---------------------------------------------------------------------------
def test_breach_with_breaches(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    isolated_breach_cache, hibp_key_set,
):
    with patch.object(evmain, "_fetch_hibp_breach", return_value=evmain._summarize_breaches(_HIBP_BREACHES)) as mock_fetch:
        resp = client.get(
            "/validate",
            params={"email": "alice@example.com", "smtp": "true", "breach": "true"},
        )
    assert resp.status_code == 200
    body = resp.json()
    bs = body["breach_status"]
    assert bs is not None
    assert bs["breached"] is True
    assert bs["breach_count"] == 2
    assert {b["name"] for b in bs["breaches"]} == {"LinkedIn", "Adobe"}
    assert bs["first_breach_date"] == "2013-10-04"
    assert bs["last_breach_date"] == "2016-05-21"
    # Attribution link required by CC BY 4.0.
    assert body["_links"]["breach_data"] == "https://haveibeenpwned.com"
    # breached -> not a trusted identity
    assert body["is_trusted_identity"] is False
    assert body["breach_status_error"] is None
    mock_fetch.assert_called_once()


# ---------------------------------------------------------------------------
# 2. Email with no breaches (HIBP 404)
# ---------------------------------------------------------------------------
def test_breach_no_breaches(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    isolated_breach_cache, hibp_key_set,
):
    clean = {
        "breached": False,
        "breach_count": 0,
        "breaches": [],
        "first_breach_date": None,
        "last_breach_date": None,
    }
    with patch.object(evmain, "_fetch_hibp_breach", return_value=clean) as mock_fetch:
        resp = client.get(
            "/validate",
            params={"email": "alice@example.com", "smtp": "true", "breach": "true"},
        )
    assert resp.status_code == 200
    body = resp.json()
    bs = body["breach_status"]
    assert bs is not None
    assert bs["breached"] is False
    assert bs["breach_count"] == 0
    assert bs["breaches"] == []
    # Clean + SMTP verified + not disposable -> trusted identity TRUE.
    assert body["smtp_verified"] is True
    assert body["is_disposable"] is False
    assert body["is_trusted_identity"] is True
    assert body["_links"]["breach_data"] == "https://haveibeenpwned.com"
    mock_fetch.assert_called_once()


# ---------------------------------------------------------------------------
# 3. HIBP_API_KEY missing -> graceful degradation
# ---------------------------------------------------------------------------
def test_breach_key_missing_degrades_gracefully(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    isolated_breach_cache, hibp_key_missing,
):
    # Even though smtp=true and breach=true, the missing key must NOT crash.
    resp = client.get(
        "/validate",
        params={"email": "alice@example.com", "smtp": "true", "breach": "true"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["breach_status"] is None
    assert body["breach_status_error"] == "HIBP_API_KEY not configured"
    # Cannot determine trust without breach data.
    assert body["is_trusted_identity"] is None
    # Core validation still works.
    assert body["syntax_valid"] is True
    assert body["mx_found"] is True
    assert body["smtp_verified"] is True


# ---------------------------------------------------------------------------
# 4. is_trusted_identity logic: breached+disposable -> false; clean -> true
# ---------------------------------------------------------------------------
def test_is_trusted_identity_logic(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    isolated_breach_cache, hibp_key_set,
):
    # Case A: disposable + breached -> is_trusted_identity False.
    # mailinator.com is in the disposable test set; anything@mailinator.com.
    breached = evmain._summarize_breaches(_HIBP_BREACHES)
    with patch.object(evmain, "_fetch_hibp_breach", return_value=breached):
        resp_a = client.get(
            "/validate",
            params={"email": "anything@mailinator.com", "smtp": "false", "breach": "true"},
        )
    body_a = resp_a.json()
    assert body_a["is_disposable"] is True
    assert body_a["breach_status"]["breached"] is True
    # smtp=false -> smtp_verified None -> is_trusted_identity None (unknown),
    # but the disposable+breached inputs would force False if smtp ran.
    # Verify the composite helper directly enforces the rule.
    assert evmain._compute_is_trusted_identity(True, True, breached) is False
    assert evmain._compute_is_trusted_identity(False, True, breached) is False

    # Case B: clean + verified + not disposable -> is_trusted_identity True.
    clean = {
        "breached": False, "breach_count": 0, "breaches": [],
        "first_breach_date": None, "last_breach_date": None,
    }
    with patch.object(evmain, "_fetch_hibp_breach", return_value=clean):
        resp_b = client.get(
            "/validate",
            params={"email": "alice@example.com", "smtp": "true", "breach": "true"},
        )
    body_b = resp_b.json()
    assert body_b["smtp_verified"] is True
    assert body_b["is_disposable"] is False
    assert body_b["breach_status"]["breached"] is False
    assert body_b["is_trusted_identity"] is True

    # Case C: smtp not run (None) + clean -> is_trusted_identity None (unknown).
    with patch.object(evmain, "_fetch_hibp_breach", return_value=clean):
        resp_c = client.get(
            "/validate",
            params={"email": "alice@example.com", "smtp": "false", "breach": "true"},
        )
    body_c = resp_c.json()
    assert body_c["smtp_verified"] is None
    assert body_c["is_trusted_identity"] is None


# ---------------------------------------------------------------------------
# 5. Cache hit: second call makes 0 HTTP requests to HIBP
# ---------------------------------------------------------------------------
def test_breach_cache_hit_makes_zero_http_calls(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    isolated_breach_cache, hibp_key_set,
):
    clean = {
        "breached": False, "breach_count": 0, "breaches": [],
        "first_breach_date": None, "last_breach_date": None,
    }
    with patch.object(evmain, "_fetch_hibp_breach", return_value=clean) as mock_fetch:
        # First call: cache miss -> _fetch_hibp_breach invoked once.
        r1 = client.get(
            "/validate",
            params={"email": "alice@example.com", "smtp": "true", "breach": "true"},
        )
        assert r1.status_code == 200
        assert r1.json()["breach_status"]["breached"] is False
        assert mock_fetch.call_count == 1

        # Second call: cache hit -> _fetch_hibp_breach NOT invoked at all.
        r2 = client.get(
            "/validate",
            params={"email": "alice@example.com", "smtp": "true", "breach": "true"},
        )
        assert r2.status_code == 200
        assert r2.json()["breach_status"]["breached"] is False
        assert mock_fetch.call_count == 1  # unchanged -> 0 additional HTTP calls

    # Confirm a cache file was actually written to the isolated dir.
    cache_files = list(isolated_breach_cache.glob("*.json"))
    assert len(cache_files) == 1


# ---------------------------------------------------------------------------
# 6. breach=false opt-out -> breach_status null, no HIBP call
# ---------------------------------------------------------------------------
def test_breach_opt_out(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    isolated_breach_cache, hibp_key_set,
):
    with patch.object(evmain, "_fetch_hibp_breach", return_value={"error": "should not be called"}) as mock_fetch:
        resp = client.get(
            "/validate",
            params={"email": "alice@example.com", "smtp": "true", "breach": "false"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["breach_status"] is None
    assert body["breach_status_error"] is None
    assert body["is_trusted_identity"] is None
    assert body["_links"] == {}
    mock_fetch.assert_not_called()