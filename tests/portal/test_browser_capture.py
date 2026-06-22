"""Unit tests for cli.portal.browser_capture (Option A).

No real browser is launched: the Playwright dependency is injected via a fake
``browser_factory`` and the timing primitives via fake ``sleep``/``clock``, so
the whole capture flow is exercised deterministically and instantly.
"""
from pathlib import Path

import pytest

from cli.portal.browser_capture import (
    PORTAL_COOKIE_NAME,
    BrowserCapture,
    BrowserCaptureConfig,
    BrowserCaptureError,
    _extract_portal_cookie,
)


# ---------------------------------------------------------------------------
# _extract_portal_cookie — pure function
# ---------------------------------------------------------------------------


class TestExtractPortalCookie:
    def test_returns_value_when_present(self):
        cookies = [
            {"name": "other", "value": "x"},
            {"name": PORTAL_COOKIE_NAME, "value": "THE-TOKEN"},
        ]
        assert _extract_portal_cookie(cookies) == "THE-TOKEN"

    def test_returns_none_when_absent(self):
        assert _extract_portal_cookie([{"name": "other", "value": "x"}]) is None

    def test_returns_none_for_empty_list(self):
        assert _extract_portal_cookie([]) is None

    def test_ignores_portal_cookie_with_empty_value(self):
        # An empty value means the cookie is set but not yet populated — treat
        # as "not ready" so the poll loop keeps waiting rather than returning "".
        cookies = [{"name": PORTAL_COOKIE_NAME, "value": ""}]
        assert _extract_portal_cookie(cookies) is None

    def test_returns_first_match(self):
        cookies = [
            {"name": PORTAL_COOKIE_NAME, "value": "FIRST"},
            {"name": PORTAL_COOKIE_NAME, "value": "SECOND"},
        ]
        assert _extract_portal_cookie(cookies) == "FIRST"


# ---------------------------------------------------------------------------
# _poll_for_cookie — browser-agnostic loop with injected clock/sleep
# ---------------------------------------------------------------------------


class _FakeContext:
    """Returns a different cookie list on each cookies() call."""

    def __init__(self, sequence):
        self._sequence = list(sequence)
        self.calls = 0

    def cookies(self):
        self.calls += 1
        if self._sequence:
            return self._sequence.pop(0)
        return []


def _make_capture(monkeypatch=None, **cfg_overrides):
    cfg = BrowserCaptureConfig(
        sso_start_url="https://example.awsapps.com/start",
        timeout_seconds=cfg_overrides.pop("timeout_seconds", 10),
        poll_interval_seconds=cfg_overrides.pop("poll_interval_seconds", 1.0),
        **cfg_overrides,
    )
    # Deterministic, fast clock: each clock() advances by 1 "second".
    ticks = {"t": 0.0}

    def fake_clock():
        ticks["t"] += 1.0
        return ticks["t"]

    sleeps = []
    cap = BrowserCapture(
        cfg,
        sleep=lambda s: sleeps.append(s),
        clock=fake_clock,
    )
    return cap, sleeps


class TestPollForCookie:
    def test_returns_immediately_when_cookie_present(self):
        cap, sleeps = _make_capture()
        ctx = _FakeContext([[{"name": PORTAL_COOKIE_NAME, "value": "TOK"}]])
        assert cap._poll_for_cookie(ctx) == "TOK"
        assert sleeps == []  # no waiting needed

    def test_polls_until_cookie_appears(self):
        cap, sleeps = _make_capture()
        ctx = _FakeContext(
            [
                [],  # not yet
                [{"name": "other", "value": "x"}],  # still not
                [{"name": PORTAL_COOKIE_NAME, "value": "LATE"}],  # now!
            ]
        )
        assert cap._poll_for_cookie(ctx) == "LATE"
        assert ctx.calls == 3
        assert len(sleeps) == 2  # slept between the three polls

    def test_times_out_with_actionable_error(self):
        # timeout_seconds=3 with a clock advancing 1/sec → deadline hit fast.
        cap, _ = _make_capture(timeout_seconds=3)
        ctx = _FakeContext([])  # cookie never appears
        with pytest.raises(BrowserCaptureError) as exc:
            cap._poll_for_cookie(ctx)
        msg = str(exc.value)
        assert PORTAL_COOKIE_NAME in msg
        assert "Timed out" in msg


# ---------------------------------------------------------------------------
# _load_playwright — missing dependency yields a clean, actionable error
# ---------------------------------------------------------------------------


class TestLoadPlaywright:
    def test_missing_playwright_raises_actionable_error(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name.startswith("playwright"):
                raise ImportError("No module named 'playwright'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        with pytest.raises(BrowserCaptureError) as exc:
            BrowserCapture._load_playwright()
        msg = str(exc.value)
        assert "Playwright is not installed" in msg
        assert "playwright install" in msg
        assert "--portal-token" in msg  # points at Option B fallback


# ---------------------------------------------------------------------------
# capture() — full flow with a fake Playwright factory (no real browser)
# ---------------------------------------------------------------------------


class _FakePage:
    def __init__(self):
        self.goto_url = None

    def goto(self, url):
        self.goto_url = url


class _FakeBrowserContext:
    def __init__(self, cookie_value):
        self._cookie_value = cookie_value
        self.closed = False
        self.launched_dir = None
        self.headless = None

    def new_page(self):
        return _FakePage()

    def cookies(self):
        return [{"name": PORTAL_COOKIE_NAME, "value": self._cookie_value}]

    def close(self):
        self.closed = True


class _FakeChromium:
    def __init__(self, ctx):
        self._ctx = ctx

    def launch_persistent_context(self, user_data_dir, headless):
        self._ctx.launched_dir = user_data_dir
        self._ctx.headless = headless
        return self._ctx


class _FakePlaywright:
    def __init__(self, ctx):
        self.chromium = _FakeChromium(ctx)


class _FakeFactory:
    """Mimics sync_playwright(): a context manager yielding a playwright obj."""

    def __init__(self, ctx):
        self._ctx = ctx
        self.pw = _FakePlaywright(ctx)

    def __call__(self):
        return self

    def __enter__(self):
        return self.pw

    def __exit__(self, *exc):
        return False


class TestCapture:
    def test_capture_returns_scraped_cookie(self, tmp_path):
        ctx = _FakeBrowserContext(cookie_value="SCRAPED-TOKEN")
        factory = _FakeFactory(ctx)
        cfg = BrowserCaptureConfig(
            sso_start_url="https://example.awsapps.com/start",
            user_data_dir=tmp_path / "profile",
        )
        cap = BrowserCapture(cfg, browser_factory=factory)

        token = cap.capture()

        assert token == "SCRAPED-TOKEN"
        # Persistent profile dir was created and passed to the launch call.
        assert (tmp_path / "profile").is_dir()
        assert ctx.launched_dir == str(tmp_path / "profile")
        assert ctx.headless is False  # headed by default (MFA needs interaction)
        assert ctx.closed is True  # context always closed

    def test_capture_creates_profile_dir_with_locked_perms(self, tmp_path):
        ctx = _FakeBrowserContext(cookie_value="T")
        factory = _FakeFactory(ctx)
        profile = tmp_path / "nested" / "profile"
        cfg = BrowserCaptureConfig(
            sso_start_url="https://x.awsapps.com/start", user_data_dir=profile
        )
        cap = BrowserCapture(cfg, browser_factory=factory)
        cap.capture()
        assert profile.is_dir()
        mode = profile.stat().st_mode & 0o777
        assert mode == 0o700  # holds an authenticated browser session

    def test_capture_normalises_launch_exception(self, tmp_path):
        class _BoomFactory:
            def __call__(self):
                return self

            def __enter__(self):
                raise RuntimeError("no display / libX missing")

            def __exit__(self, *exc):
                return False

        cfg = BrowserCaptureConfig(
            sso_start_url="https://x.awsapps.com/start",
            user_data_dir=tmp_path / "p",
        )
        cap = BrowserCapture(cfg, browser_factory=_BoomFactory())
        with pytest.raises(BrowserCaptureError) as exc:
            cap.capture()
        assert "Browser capture failed" in str(exc.value)
        assert "playwright install" in str(exc.value)
