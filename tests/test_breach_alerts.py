"""Pytest tests for Email Validator API: breach alerts (P5.19).

Tests the breach alert subscription + check cycle with mocked HIBP.
Run with: pytest -q
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from unittest.mock import patch

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import breach_alerts  # noqa: E402


@pytest.fixture
def tmp_alerts_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setattr(breach_alerts, "CACHE_DIR", d)
        monkeypatch.setattr(breach_alerts, "ALERTS_PATH", os.path.join(d, "breach_alerts.json"))
        yield d


# ---------------------------------------------------------------------------
# register / get / delete
# ---------------------------------------------------------------------------

def test_register_alert_returns_alert_with_id(tmp_alerts_dir):
    alert = breach_alerts.register_alert("user@example.com")
    assert alert["alert_id"].startswith("ba_")
    assert alert["email"] == "user@example.com"
    assert alert["last_check"] is None
    assert alert["history"] == []


def test_register_alert_normalizes_email(tmp_alerts_dir):
    alert = breach_alerts.register_alert("  USER@Example.COM  ")
    assert alert["email"] == "user@example.com"


def test_register_alert_with_webhook(tmp_alerts_dir):
    alert = breach_alerts.register_alert("u@x.com", "https://hook.url", "secret")
    assert alert["webhook_url"] == "https://hook.url"
    assert alert["webhook_secret"] == "secret"


def test_get_alert_returns_registered(tmp_alerts_dir):
    alert = breach_alerts.register_alert("u@x.com")
    fetched = breach_alerts.get_alert(alert["alert_id"])
    assert fetched is not None
    assert fetched["email"] == "u@x.com"


def test_get_alert_returns_none_for_unknown(tmp_alerts_dir):
    assert breach_alerts.get_alert("ba_nonexistent") is None


def test_delete_alert_removes_it(tmp_alerts_dir):
    alert = breach_alerts.register_alert("u@x.com")
    assert breach_alerts.delete_alert(alert["alert_id"]) is True
    assert breach_alerts.get_alert(alert["alert_id"]) is None


def test_delete_alert_returns_false_for_unknown(tmp_alerts_dir):
    assert breach_alerts.delete_alert("ba_nonexistent") is False


# ---------------------------------------------------------------------------
# _breach_signature
# ---------------------------------------------------------------------------

def test_breach_signature_stable():
    b1 = [{"Name": "Adobe"}, {"Name": "LinkedIn"}]
    b2 = [{"Name": "LinkedIn"}, {"Name": "Adobe"}]
    assert breach_alerts._breach_signature(b1) == breach_alerts._breach_signature(b2)


def test_breach_signature_changes_with_new_breach():
    b1 = [{"Name": "Adobe"}]
    b2 = [{"Name": "Adobe"}, {"Name": "Collection1"}]
    assert breach_alerts._breach_signature(b1) != breach_alerts._breach_signature(b2)


def test_breach_signature_empty():
    assert breach_alerts._breach_signature([]) != breach_alerts._breach_signature([{"Name": "X"}])


# ---------------------------------------------------------------------------
# run_check_cycle (mocked HIBP)
# ---------------------------------------------------------------------------

def test_run_check_cycle_baseline_on_first_check(tmp_alerts_dir):
    """First check records baseline, no alert, no webhook."""
    breach_alerts.register_alert("u@x.com")
    with patch("app.breach_alerts._check_breaches", return_value=[{"Name": "Adobe"}]):
        result = breach_alerts.run_check_cycle()
    assert result["checked"] == 1
    assert result["new_breaches"] == 0
    alert = breach_alerts.get_alert(list(breach_alerts._load_alerts().keys())[0])
    assert alert["last_breach_count"] == 1
    assert alert["last_breach_signature"] is not None
    assert alert["history"][0]["event"] == "baseline"


def test_run_check_cycle_detects_new_breach(tmp_alerts_dir):
    """Second check with a different breach set -> new_breach event."""
    alert = breach_alerts.register_alert("u@x.com")
    # First check: baseline with Adobe.
    with patch("app.breach_alerts._check_breaches", return_value=[{"Name": "Adobe"}]):
        breach_alerts.run_check_cycle()
    # Second check: new breach added.
    with patch("app.breach_alerts._check_breaches", return_value=[{"Name": "Adobe"}, {"Name": "Collection1"}]):
        result = breach_alerts.run_check_cycle()
    assert result["new_breaches"] == 1
    alert = breach_alerts.get_alert(alert["alert_id"])
    assert alert["history"][-1]["event"] == "new_breach"


def test_run_check_cycle_no_change_on_same_breaches(tmp_alerts_dir):
    """Same breach set on re-check -> no_change event."""
    breach_alerts.register_alert("u@x.com")
    with patch("app.breach_alerts._check_breaches", return_value=[{"Name": "Adobe"}]):
        breach_alerts.run_check_cycle()
        result = breach_alerts.run_check_cycle()
    assert result["new_breaches"] == 0
    alert = breach_alerts.get_alert(list(breach_alerts._load_alerts().keys())[0])
    assert alert["history"][-1]["event"] == "no_change"


def test_run_check_cycle_fires_webhook_on_new_breach(tmp_alerts_dir):
    """Webhook is called when a new breach is detected."""
    breach_alerts.register_alert("u@x.com", "https://hook.url", "secret")
    with patch("app.breach_alerts._check_breaches", return_value=[{"Name": "Adobe"}]):
        breach_alerts.run_check_cycle()
    with patch("app.breach_alerts._check_breaches", return_value=[{"Name": "Adobe"}, {"Name": "X"}]), \
         patch("app.breach_alerts._deliver_webhook", return_value={"delivered": True, "status": 200}) as mock_wh:
        result = breach_alerts.run_check_cycle()
    assert result["new_breaches"] == 1
    assert result["webhooks_delivered"] == 1
    assert mock_wh.called


def test_run_check_cycle_no_webhook_when_not_configured(tmp_alerts_dir):
    """No webhook_url -> no webhook delivery attempted."""
    breach_alerts.register_alert("u@x.com")  # no webhook
    with patch("app.breach_alerts._check_breaches", return_value=[{"Name": "Adobe"}]):
        breach_alerts.run_check_cycle()
    with patch("app.breach_alerts._check_breaches", return_value=[{"Name": "Adobe"}, {"Name": "X"}]), \
         patch("app.breach_alerts._deliver_webhook") as mock_wh:
        result = breach_alerts.run_check_cycle()
    assert result["new_breaches"] == 1
    assert result["webhooks_delivered"] == 0
    assert not mock_wh.called


def test_run_check_cycle_empty_alerts(tmp_alerts_dir):
    """No alerts registered -> checked=0."""
    result = breach_alerts.run_check_cycle()
    assert result["checked"] == 0
    assert result["new_breaches"] == 0


def test_run_check_cycle_history_bounded(tmp_alerts_dir):
    """History keeps at most 50 entries."""
    breach_alerts.register_alert("u@x.com")
    for _ in range(55):
        with patch("app.breach_alerts._check_breaches", return_value=[]):
            breach_alerts.run_check_cycle()
    alert = breach_alerts.get_alert(list(breach_alerts._load_alerts().keys())[0])
    assert len(alert["history"]) <= 50


# ---------------------------------------------------------------------------
# _check_breaches (mocked HTTP)
# ---------------------------------------------------------------------------

def test_check_breaches_returns_breaches_on_200():
    with patch("app.breach_alerts._get_hibp_key", return_value="key"), \
         patch("app.breach_alerts.httpx.Client") as mock_cls:
        mock_resp = mock_cls.return_value.__enter__.return_value.get.return_value
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"Name": "Adobe"}]
        result = breach_alerts._check_breaches("u@x.com")
    assert result == [{"Name": "Adobe"}]


def test_check_breaches_returns_empty_on_404():
    with patch("app.breach_alerts._get_hibp_key", return_value="key"), \
         patch("app.breach_alerts.httpx.Client") as mock_cls:
        mock_resp = mock_cls.return_value.__enter__.return_value.get.return_value
        mock_resp.status_code = 404
        result = breach_alerts._check_breaches("u@x.com")
    assert result == []


def test_check_breaches_returns_empty_without_key():
    with patch("app.breach_alerts._get_hibp_key", return_value=""):
        result = breach_alerts._check_breaches("u@x.com")
    assert result == []