"""Hermetic tests for the v2.2.0 table-stakes features:

  1. Syntax suggestion via Levenshtein (did-you-mean).
  2. Free-email-provider flag + provider identification via MX.
  3. Greylisting detection (SMTP 451 -> retry once after 5s).

All DNS, SMTP, and HIBP calls are mocked via the shared conftest fixtures;
no network access. The greylisting wait is patched to 0s via the
`no_greylist_wait` fixture so the suite stays fast.
"""
from __future__ import annotations

import pytest

from app import main as evmain


# ---------------------------------------------------------------------------
# Feature 1: Syntax suggestion
# ---------------------------------------------------------------------------
def test_suggestion_fixes_typo_of_popular_domain(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """gmial.com is a Levenshtein-1 typo of gmail.com.

    gmial.com has no MX (NXDOMAIN in the fake DNS), so the response hits the
    mx-failed branch and the suggestion should still be surfaced because the
    domain is close to a popular one.
    """
    resp = client.get(
        "/validate",
        params={"email": "alice@gmial.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["syntax_valid"] is True  # gmial.com is syntactically valid
    assert body["mx_found"] is False  # but has no MX
    assert body["suggestion"] == "alice@gmail.com"


def test_suggestion_returns_null_when_no_close_match(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """A random domain unlike any popular provider -> suggestion null."""
    resp = client.get(
        "/validate",
        params={"email": "alice@xqzplkqwerty.invalid", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["suggestion"] is None


def test_suggestion_not_offered_for_already_popular_domain(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """gmail.com IS a popular domain -> no suggestion (don't second-guess)."""
    resp = client.get(
        "/validate",
        params={"email": "john.doe@gmail.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # gmail.com is in the popular set -> no correction.
    assert body["suggestion"] is None
    # But is_free_email should be true.
    assert body["is_free_email"] is True


# ---------------------------------------------------------------------------
# Feature 2: Free-email flag + provider identification
# ---------------------------------------------------------------------------
def test_free_email_detected_for_gmail(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """alice@gmail.com -> is_free_email=true. gmail.com is in the free set."""
    resp = client.get(
        "/validate",
        params={"email": "john.doe@gmail.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_free_email"] is True


def test_free_email_false_for_custom_domain(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """example.com is NOT in the free set -> is_free_email=false."""
    resp = client.get(
        "/validate",
        params={"email": "alice@example.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_free_email"] is False


def test_provider_identification_google_workspace(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """gmail.com MX points at gmail-smtp-in.l.google.com -> googleworkspace."""
    resp = client.get(
        "/validate",
        params={"email": "john.doe@gmail.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["email_provider"] == "googleworkspace"


def test_provider_identification_microsoft365(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """outlook.example.com MX -> *.mail.protection.outlook.com -> microsoft365."""
    resp = client.get(
        "/validate",
        params={"email": "user@outlook.example.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mx_found"] is True
    assert body["email_provider"] == "microsoft365"
    # Custom MX host -> not a free email domain.
    assert body["is_free_email"] is False


def test_provider_identification_other_for_unknown_mx(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """example.com MX -> mail.example.com (no pattern match) -> 'other'."""
    resp = client.get(
        "/validate",
        params={"email": "alice@example.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["email_provider"] == "other"


def test_provider_null_when_no_mx(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """No MX (NXDOMAIN) -> email_provider null."""
    resp = client.get(
        "/validate",
        params={"email": "alice@gmial.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mx_found"] is False
    assert body["email_provider"] is None


# ---------------------------------------------------------------------------
# Feature 3: Greylisting detection
# ---------------------------------------------------------------------------
def test_greylisting_detected_when_retry_still_451(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets, no_greylist_wait,
):
    """SMTP returns 451, retry after 5s, still 451 -> is_greylisted=true."""
    fake_smtp.greylist_mode = "always"
    resp = client.get(
        "/validate",
        params={"email": "user@greylist.example.com", "smtp": "true", "catch_all": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # 451 is not an accept -> smtp_verified False. The mailbox was neither
    # accepted nor definitively rejected as nonexistent; the greylisting note
    # tells the caller to retry later.
    assert body["smtp_verified"] is False
    assert body["is_greylisted"] is True
    assert body["greylisting_note"] is not None
    assert "greylisting" in body["greylisting_note"].lower()
    # Catch-all probe is skipped when greylisted.
    assert body["is_catch_all"] is None


def test_greylisting_false_when_retry_succeeds(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets, no_greylist_wait,
):
    """SMTP returns 451 once, retry returns 250 -> is_greylisted=false, verified."""
    fake_smtp.greylist_mode = "once"
    resp = client.get(
        "/validate",
        params={"email": "user@greylist.example.com", "smtp": "true", "catch_all": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # Retry succeeded -> smtp_verified true, is_greylisted false.
    assert body["smtp_verified"] is True
    assert body["is_greylisted"] is False
    assert body["greylisting_note"] is None


def test_greylisting_false_when_no_451(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets, no_greylist_wait,
):
    """Normal 250 response -> is_greylisted=false, no note."""
    fake_smtp.greylist_mode = "off"
    resp = client.get(
        "/validate",
        params={"email": "user@greylist.example.com", "smtp": "true", "catch_all": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["smtp_verified"] is True
    assert body["is_greylisted"] is False
    assert body["greylisting_note"] is None


def test_greylisting_null_when_smtp_not_run(
    client, fake_dns, fake_smtp, isolated_disposable_data, isolated_role_data,
    reset_domain_datasets,
):
    """smtp=false -> is_greylisted=null (not checked)."""
    resp = client.get(
        "/validate",
        params={"email": "alice@example.com", "smtp": "false", "breach": "false"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_greylisted"] is None
    assert body["greylisting_note"] is None