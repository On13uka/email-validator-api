"""Hermetic tests for the Email Validator API.

Covers:
  1. Disposable domain detection (mailinator.com).
  2. Role-based account detection (admin@example.com).
  3. Clean personal email (alice@example.com) -> high score.
  4. Catch-all domain (catchall.example.com) -> is_catch_all=true with mock SMTP.
  5. Syntax invalid -> score 0.

All SMTP and DNS calls are mocked via conftest.py fixtures; no network.
"""
from __future__ import annotations

import pytest

from app import main as evmain


# ---------------------------------------------------------------------------
# 1. Syntax invalid
# ---------------------------------------------------------------------------
def test_invalid_syntax_returns_zero_score(client):
    resp = client.get("/validate", params={"email": "not-an-email"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert body["syntax_valid"] is False
    assert body["score"] == 0
    assert body["is_disposable"] is False
    assert body["is_catch_all"] is None
    assert body["is_role"] is False
    assert body["role_type"] is None
    assert body["stage"] == "syntax"


# ---------------------------------------------------------------------------
# 2. Disposable domain detection
# ---------------------------------------------------------------------------
def test_disposable_domain_detected(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data
):
    resp = client.get(
        "/validate",
        params={"email": "anything@mailinator.com", "smtp": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_disposable"] is True
    assert body["valid"] is True  # disposable emails are syntactically valid
    assert body["mx_found"] is True
    assert body["smtp_verified"] is None  # smtp=false
    assert body["is_catch_all"] is None
    # Disposable => no +10 bonus => score < full
    assert body["score"] <= 75  # 35 syntax + 30 mx = 65; cap a little slack
    assert body["score"] >= 60


# ---------------------------------------------------------------------------
# 3. Role-based account detection
# ---------------------------------------------------------------------------
def test_role_account_detected(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data
):
    resp = client.get(
        "/validate",
        params={"email": "admin@example.com", "smtp": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_role"] is True
    assert body["role_type"] == "admin"
    assert body["is_disposable"] is False
    assert body["valid"] is True
    # Role accounts get no bonus but no penalty:
    # 35 (syntax) + 30 (mx) + 10 (not disposable) = 75.
    assert body["score"] == 75


# ---------------------------------------------------------------------------
# 4. Clean personal email -> high score, smtp verified
# ---------------------------------------------------------------------------
def test_clean_personal_email_high_score(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data
):
    # alice@example.com -> the fake SMTP accepts "alice" for example.com.
    resp = client.get(
        "/validate",
        params={"email": "alice@example.com", "smtp": "true", "catch_all": "true"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["syntax_valid"] is True
    assert body["mx_found"] is True
    assert body["smtp_verified"] is True
    assert body["is_disposable"] is False
    assert body["is_role"] is False
    assert body["role_type"] is None
    # Not catch-all: probe rejects the fake mailbox.
    assert body["is_catch_all"] is False
    # Full score: 35 + 30 + 25 + 10 = 100
    assert body["score"] == 100


# ---------------------------------------------------------------------------
# 5. Catch-all domain detection
# ---------------------------------------------------------------------------
def test_catch_all_domain_detected(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data
):
    # Configure the fake SMTP to accept the catch-all probe (random address).
    fake_smtp.catch_all = True
    resp = client.get(
        "/validate",
        params={"email": "realuser@catchall.example.com", "smtp": "true", "catch_all": "true"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mx_found"] is True
    assert body["smtp_verified"] is True
    assert body["is_catch_all"] is True
    # Catch-all: SMTP bonus capped to +10 instead of +25.
    # Score: 35 + 30 + 10 + 10 = 85
    assert body["score"] == 85
    assert body["catch_all_probe"] is not None
    assert body["catch_all_probe"]["probe_address"].startswith("zzztestnotreal")
    assert body["catch_all_probe"]["is_catch_all"] is True


# ---------------------------------------------------------------------------
# 6. Catch-all probe does not run when smtp=false
# ---------------------------------------------------------------------------
def test_catch_all_skipped_when_smtp_false(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data
):
    resp = client.get(
        "/validate",
        params={"email": "alice@example.com", "smtp": "false", "catch_all": "true"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["smtp_verified"] is None
    assert body["is_catch_all"] is None  # cannot determine without SMTP
    # Score: 35 + 30 + 10 (not disposable) = 75
    assert body["score"] == 75


# ---------------------------------------------------------------------------
# 7. SMTP-rejected mailbox -> valid=False, score reflects
# ---------------------------------------------------------------------------
def test_smtp_rejected_mailbox(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data
):
    # bob@example.com is NOT in the real-mailbox map -> SMTP rejects.
    resp = client.get(
        "/validate",
        params={"email": "bob@example.com", "smtp": "true", "catch_all": "true"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["smtp_verified"] is False
    assert body["valid"] is False
    # Catch-all probe skipped because mailbox was rejected -> is_catch_all=False.
    assert body["is_catch_all"] is False
    # Score: 35 + 30 + 0 (smtp fail) + 10 (not disposable) = 75
    assert body["score"] == 75