"""Shared test fixtures: mock DNS resolver and SMTP RCPT responses.

These tests never hit real SMTP or DNS servers - everything is monkeypatched
so the suite is hermetic and fast.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app import main as evmain


# ---------------------------------------------------------------------------
# DNS MX answer shim
# ---------------------------------------------------------------------------
class _FakeMX:
    def __init__(self, preference: int, exchange: str):
        self.preference = preference
        self.exchange = exchange


def _fake_mx_resolve(domain: str, rdtype: str, lifetime: int = 10):
    """Return canned MX records for known test domains."""
    if rdtype == "MX":
        if domain == "example.com":
            return [_FakeMX(10, "mail.example.com.")]
        if domain == "gmail.com":
            return [_FakeMX(5, "gmail-smtp-in.l.google.com.")]
        if domain == "mailinator.com":
            return [_FakeMX(10, "mail.mailinator.com.")]
        if domain == "catchall.example.com":
            return [_FakeMX(10, "mail.catchall.example.com.")]
        # Unknown domain -> NXDOMAIN
        from dns.resolver import NXDOMAIN
        raise NXDOMAIN()
    if rdtype == "A":
        # A-record fallback used when no MX. Tests don't exercise this path.
        return [_FakeMX(0, "1.2.3.4")]
    from dns.resolver import NoAnswer
    raise NoAnswer()


# ---------------------------------------------------------------------------
# SMTP shim
# ---------------------------------------------------------------------------
class _FakeSMTP:
    """A fake smtplib.SMTP that returns scripted RCPT responses.

    Behavior is keyed off the email passed to .rcpt():
      - Real mailbox (deterministic per domain) -> code 250
      - Anything else (the catch-all probe) -> controlled by
        self.catch_all flag.
    """

    # Per-test configuration set by the fixtures below.
    _next_instance: "_FakeSMTP | None" = None

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.connected = False
        self.mail_from = None
        self.last_rcpt = None
        # Default behavior: real mailboxes accepted, catch-all probe rejected.
        self.catch_all = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def connect(self, host: str, port: int = 25):
        self.connected = True
        self.host = host
        return (220, b"fake smtp ready")

    def ehlo(self, name: str = ""):
        return (250, b"hello")

    def mail(self, sender: str):
        self.mail_from = sender
        return (250, b"ok")

    def rcpt(self, addr: str):
        self.last_rcpt = addr
        # The catch-all probe uses an address starting with the magic prefix.
        if addr.startswith("zzztestnotreal"):
            if self.catch_all:
                return (250, b"ok")
            return (550, b"no such mailbox")
        # Real mailbox behavior: each test domain has one "valid" local part.
        local, _, domain = addr.partition("@")
        valid_local = _REAL_MAILBOXES.get(domain)
        if valid_local and local == valid_local:
            return (250, b"ok")
        return (550, b"no such mailbox")

    def quit(self):
        return (221, b"bye")


# Map: domain -> the local part that the test treats as a real, accepted mailbox.
_REAL_MAILBOXES = {
    "example.com": "alice",
    "gmail.com": "john.doe",
    "mailinator.com": "anything",  # disposable - mailbox result is irrelevant
    "catchall.example.com": "realuser",
}


@pytest.fixture
def fake_smtp(monkeypatch):
    """Patch smtplib.SMTP to return a controllable _FakeSMTP.

    Yields the instance so each test can flip .catch_all on/off.
    """
    instance = _FakeSMTP()
    _FakeSMTP._next_instance = instance

    def _factory(timeout: int = 10):
        # Each new connection in the same request gets the same configured
        # instance, so the catch-all probe reuses the same catch_all flag.
        inst = _FakeSMTP._next_instance or instance
        inst.timeout = timeout
        return inst

    monkeypatch.setattr(evmain.smtplib, "SMTP", _factory)
    return instance


@pytest.fixture
def fake_dns(monkeypatch):
    """Patch dns.resolver.resolve with the canned MX map above."""
    monkeypatch.setattr(evmain.dns.resolver, "resolve", _fake_mx_resolve)
    return _fake_mx_resolve


@pytest.fixture
def isolated_disposable_data(tmp_path, monkeypatch):
    """Point the disposable list at a tiny in-memory file for deterministic tests."""
    tmp_list = tmp_path / "disposable-domains.json"
    tmp_list.write_text(json.dumps(["mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org"]), encoding="utf-8")
    monkeypatch.setattr(evmain, "DISPOSABLE_FILE", tmp_list)
    # Reset the module-level cache so the new file is loaded.
    monkeypatch.setattr(evmain, "_disposable_set", None)
    monkeypatch.setattr(evmain, "_disposable_loaded_at", None)
    return tmp_list


@pytest.fixture
def isolated_role_data(tmp_path, monkeypatch):
    """Point the role-accounts file at a small deterministic set."""
    tmp_roles = tmp_path / "role-accounts.json"
    tmp_roles.write_text(json.dumps(["admin", "info", "support", "sales", "contact", "noreply", "postmaster", "webmaster", "abuse", "billing"]), encoding="utf-8")
    monkeypatch.setattr(evmain, "ROLE_FILE", tmp_roles)
    monkeypatch.setattr(evmain, "_role_set", None)
    return tmp_roles


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    return TestClient(evmain.app)