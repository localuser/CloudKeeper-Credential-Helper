"""Unit tests for cli.portal.saml_capture (Option A-prime: direct SAML intercept).

No real browser is launched: the Playwright dependency is injected via a fake
``browser_factory`` whose fake page models Playwright's ``expect_request``
context manager, so the whole capture flow is exercised deterministically.

This mirrors the proven shape of test_browser_capture.py — pure decision
functions plus a DI'd fake factory — and additionally proves the
missing-dependency path by monkeypatching ``builtins.__import__``.
"""
import pytest

from cli.portal.saml_capture import (
    DEFAULT_ACS_URL,
    SamlCapture,
    SamlCaptureConfig,
    SamlCaptureError,
    _extract_saml_response,
    _is_saml_acs_request,
)


# ---------------------------------------------------------------------------
# _extract_saml_response — pure function (parse a urlencoded POST body)
# ---------------------------------------------------------------------------


class TestExtractSamlResponse:
    def test_returns_value_when_present(self):
        body = "SAMLResponse=PHNhbWw-&RelayState=https%3A%2F%2Fx"
        assert _extract_saml_response(body) == "PHNhbWw-"

    def test_percent_decodes_base64_payload(self):
        # Azure posts the base64 SAMLResponse percent-encoded; +, /, = arrive
        # as %2B, %2F, %3D and must be decoded back to the raw base64 value.
        body = "SAMLResponse=PHNhbWw%2BPC9zYW1s%2FPg%3D%3D"
        assert _extract_saml_response(body) == "PHNhbWw+PC9zYW1s/Pg=="

    def test_returns_none_when_field_absent(self):
        assert _extract_saml_response("RelayState=foo&other=bar") is None

    def test_returns_none_for_empty_body(self):
        assert _extract_saml_response("") is None

    def test_returns_none_for_none_body(self):
        assert _extract_saml_response(None) is None

    def test_returns_none_for_empty_value(self):
        # Field present but empty → not ready / malformed, treat as no capture.
        assert _extract_saml_response("SAMLResponse=") is None

    def test_picks_saml_response_among_many_fields(self):
        body = "RelayState=foo&SAMLResponse=ABC123&extra=1"
        assert _extract_saml_response(body) == "ABC123"


# ---------------------------------------------------------------------------
# _is_saml_acs_request — pure predicate (match the AWS SAML ACS POST)
# ---------------------------------------------------------------------------


class TestIsSamlAcsRequest:
    def test_matches_post_to_default_acs(self):
        assert _is_saml_acs_request(DEFAULT_ACS_URL, "POST", DEFAULT_ACS_URL) is True

    def test_rejects_get_to_acs(self):
        # A GET (e.g. an asset fetch) to the ACS host must not match.
        assert _is_saml_acs_request(DEFAULT_ACS_URL, "GET", DEFAULT_ACS_URL) is False

    def test_rejects_post_to_other_url(self):
        assert (
            _is_saml_acs_request(
                "https://login.microsoftonline.com/x", "POST", DEFAULT_ACS_URL
            )
            is False
        )

    def test_method_match_is_case_insensitive(self):
        assert _is_saml_acs_request(DEFAULT_ACS_URL, "post", DEFAULT_ACS_URL) is True

    def test_tolerates_trailing_slash(self):
        assert (
            _is_saml_acs_request(
                DEFAULT_ACS_URL + "/", "POST", DEFAULT_ACS_URL
            )
            is True
        )

    def test_tolerates_query_string(self):
        assert (
            _is_saml_acs_request(
                DEFAULT_ACS_URL + "?foo=bar", "POST", DEFAULT_ACS_URL
            )
            is True
        )

    def test_honours_custom_acs_url_for_govcloud(self):
        gov = "https://signin.amazonaws-us-gov.com/saml"
        assert _is_saml_acs_request(gov, "POST", gov) is True
        # The default ACS must NOT match a GovCloud POST when GovCloud is set.
        assert _is_saml_acs_request(DEFAULT_ACS_URL, "POST", gov) is False


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
        with pytest.raises(SamlCaptureError) as exc:
            SamlCapture._load_playwright()
        msg = str(exc.value)
        assert "Playwright is not installed" in msg
        assert "playwright install" in msg
        # Points at the manual-cookie fallback so the user isn't stuck.
        assert "--portal-token" in msg


# ---------------------------------------------------------------------------
# capture() — full flow with a fake Playwright factory (no real browser)
# ---------------------------------------------------------------------------


class _FakeRequest:
    def __init__(self, url, method, post_data):
        self.url = url
        self.method = method
        self.post_data = post_data


class _FakeExpectCtx:
    """Mimics Playwright's page.expect_request(predicate) context manager."""

    def __init__(self, request, predicate):
        self._request = request
        self._predicate = predicate

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @property
    def value(self):
        # Playwright only resolves .value to a request matching the predicate.
        if not self._predicate(self._request):
            raise AssertionError("fake request did not satisfy the predicate")
        return self._request


class _TimeoutExpectCtx:
    """expect_request context whose .value raises (models a login timeout)."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @property
    def value(self):
        raise RuntimeError("Timeout 180000ms exceeded waiting for event")


class _FakePage:
    def __init__(self, request, *, timeout=False):
        self._request = request
        self._timeout = timeout
        self.goto_url = None

    def goto(self, url):
        self.goto_url = url

    def expect_request(self, predicate, timeout=None):
        if self._timeout:
            return _TimeoutExpectCtx()
        return _FakeExpectCtx(self._request, predicate)


class _FakeContext:
    def __init__(self, page):
        self._page = page
        self.closed = False
        self.launched_dir = None
        self.headless = None

    def new_page(self):
        return self._page

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
    def __init__(self, ctx):
        self._ctx = ctx
        self.pw = _FakePlaywright(ctx)

    def __call__(self):
        return self

    def __enter__(self):
        return self.pw

    def __exit__(self, *exc):
        return False


def _make_factory(*, post_data, url=DEFAULT_ACS_URL, method="POST", timeout=False):
    request = _FakeRequest(url=url, method=method, post_data=post_data)
    page = _FakePage(request, timeout=timeout)
    ctx = _FakeContext(page)
    return _FakeFactory(ctx), ctx, page


class TestCapture:
    def test_capture_returns_intercepted_saml_response(self, tmp_path):
        factory, ctx, page = _make_factory(post_data="SAMLResponse=ASSERTION123")
        cfg = SamlCaptureConfig(
            start_url="https://launcher.myapps.microsoft.com/api/signin/app",
            user_data_dir=tmp_path / "profile",
        )
        cap = SamlCapture(cfg, browser_factory=factory)

        saml = cap.capture()

        assert saml == "ASSERTION123"
        assert page.goto_url == "https://launcher.myapps.microsoft.com/api/signin/app"
        assert ctx.launched_dir == str(tmp_path / "profile")
        assert ctx.headless is False  # headed by default (MFA needs interaction)
        assert ctx.closed is True  # context always closed

    def test_capture_creates_profile_dir_with_locked_perms(self, tmp_path):
        factory, _, _ = _make_factory(post_data="SAMLResponse=X")
        profile = tmp_path / "nested" / "profile"
        cfg = SamlCaptureConfig(start_url="https://x", user_data_dir=profile)
        cap = SamlCapture(cfg, browser_factory=factory)
        cap.capture()
        assert profile.is_dir()
        mode = profile.stat().st_mode & 0o777
        assert mode == 0o700  # holds an authenticated browser session

    def test_intercepted_post_without_saml_response_errors(self, tmp_path):
        # A matching POST whose body lacks SAMLResponse must be a clean error,
        # not a None silently propagated downstream.
        factory, _, _ = _make_factory(post_data="RelayState=only")
        cfg = SamlCaptureConfig(start_url="https://x", user_data_dir=tmp_path / "p")
        cap = SamlCapture(cfg, browser_factory=factory)
        with pytest.raises(SamlCaptureError) as exc:
            cap.capture()
        assert "SAMLResponse" in str(exc.value)

    def test_timeout_is_normalised_to_actionable_error(self, tmp_path):
        factory, _, _ = _make_factory(post_data="SAMLResponse=X", timeout=True)
        cfg = SamlCaptureConfig(start_url="https://x", user_data_dir=tmp_path / "p")
        cap = SamlCapture(cfg, browser_factory=factory)
        with pytest.raises(SamlCaptureError) as exc:
            cap.capture()
        msg = str(exc.value)
        assert "SAML" in msg
        # Actionable: tell the user how to recover.
        assert "sign-in" in msg.lower() or "timed out" in msg.lower()

    def test_launch_exception_is_normalised(self, tmp_path):
        class _BoomFactory:
            def __call__(self):
                return self

            def __enter__(self):
                raise RuntimeError("no display / libX missing")

            def __exit__(self, *exc):
                return False

        cfg = SamlCaptureConfig(start_url="https://x", user_data_dir=tmp_path / "p")
        cap = SamlCapture(cfg, browser_factory=_BoomFactory())
        with pytest.raises(SamlCaptureError) as exc:
            cap.capture()
        assert "playwright install" in str(exc.value)
