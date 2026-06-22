"""Option A-prime — direct SAML-assertion interception via a real browser.

Where :mod:`cli.portal.browser_capture` (Option A) scrapes the
``x-amz-sso_authn`` *portal* cookie and then talks to the IAM Identity Center
portal API to enumerate apps, this module takes aws-azure-login's approach: it
drives a real browser through the M365 sign-in and **intercepts the browser's
own ``SAMLResponse`` POST to the AWS SAML ACS endpoint**
(``https://signin.aws.amazon.com/saml``).  The intercepted base64 assertion is
fed straight into the existing
:func:`cli.portal.saml_parser.parse_saml_assertion` →
:meth:`cli.aws.sts_client.StsClient.assume_role_with_saml` path — the *exact*
same downstream plumbing every other path uses.

Why have this at all when Option A already works?
  * **Maximally change-resistant.**  It depends only on the SAML POST that the
    browser must make for sign-in to work at all — there is no portal-API
    surface to break when AWS revises the portal.  It is the same mechanism
    aws-azure-login has relied on for years.
  * **No portal cookie needed.**  The assertion is grabbed in-flight, so we
    never need the ``x-amz-sso_authn`` cookie nor the portal app-list API.

Trade-off (documented, intentional):
  * **One app per sign-in.**  An IdP-initiated SAML POST carries the assertion
    for a *single* AWS app, so this path authenticates the app whose tile/URL
    the *start_url* lands on, rather than enumerating all 32 tiles.  For the
    multi-app picker, use Option A (``--browser``) or Option B
    (``--portal-token``).  This path is the durable single-target escape hatch.

Design mirrors :mod:`cli.portal.browser_capture` exactly so the two stay easy
to reason about together:
  * **Playwright is an OPTIONAL dependency**, imported lazily inside
    :meth:`SamlCapture._load_playwright`; a missing install raises a clean,
    actionable :class:`SamlCaptureError`.
  * **Headed + persistent profile by default** (MFA needs interaction; the
    profile is reused so M365 "stay signed in" survives across runs).
  * **The decision logic is pure and unit-testable without a browser**
    (:func:`_extract_saml_response`, :func:`_is_saml_acs_request`); only the
    thin Playwright-launching shell in :meth:`capture` needs a real browser.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qs

from cli.auth.token_cache import DEFAULT_CACHE_DIR

# The AWS SAML assertion-consumer-service (ACS) endpoint the browser POSTs the
# signed SAMLResponse to once the IdP completes authentication.  GovCloud and
# some partitions use a different host, hence it is configurable.
DEFAULT_ACS_URL = "https://signin.aws.amazon.com/saml"

# The urlencoded form field carrying the base64 SAML assertion.
SAML_RESPONSE_FIELD = "SAMLResponse"

# Persistent browser profile — shared sibling of the token cache, same as
# Option A, so one wipe location covers all browser state.
DEFAULT_PROFILE_DIR = DEFAULT_CACHE_DIR / "browser_profile"


class SamlCaptureError(RuntimeError):
    """Raised when the SAML interception cannot produce an assertion.

    Covers: Playwright not installed, the browser failing to launch, the
    sign-in not completing before the timeout, and a matching POST that
    unexpectedly carries no ``SAMLResponse`` field.
    """


def _extract_saml_response(post_body: Optional[str]) -> Optional[str]:
    """Return the ``SAMLResponse`` value from a urlencoded POST body.

    *post_body* is the raw ``application/x-www-form-urlencoded`` request body
    captured from the browser (``request.post_data`` in Playwright).  The value
    is percent-decoded back to its raw base64 form.  Returns ``None`` when the
    body is empty/absent or the field is missing/empty — i.e. "not a usable
    assertion", so callers treat it as "keep waiting / not this request".

    Pure function: no I/O, no browser — the unit-testable heart of capture.
    """
    if not post_body:
        return None
    # parse_qs percent-decodes values (%2B→+, %2F→/, %3D→=) and drops empties
    # by default, which is exactly the "empty value == not ready" semantics.
    fields = parse_qs(post_body, keep_blank_values=False)
    values = fields.get(SAML_RESPONSE_FIELD)
    if not values:
        return None
    value = values[0]
    return value or None


def _is_saml_acs_request(url: str, method: str, acs_url: str) -> bool:
    """Return True if *url*/*method* is the SAML POST to the ACS endpoint.

    Matches a ``POST`` (case-insensitive) whose URL is *acs_url*, tolerating a
    trailing slash and/or a query string.  Pure predicate, used both as the
    Playwright ``expect_request`` matcher and directly in tests.
    """
    if method.upper() != "POST":
        return False
    # Normalise: strip query string and any single trailing slash.
    base = url.split("?", 1)[0].rstrip("/")
    target = acs_url.split("?", 1)[0].rstrip("/")
    return base == target


@dataclass
class SamlCaptureConfig:
    """Configuration for a direct-SAML-intercept capture run."""

    start_url: str
    acs_url: str = DEFAULT_ACS_URL
    user_data_dir: Path = field(default=DEFAULT_PROFILE_DIR)
    headless: bool = False  # MFA needs interaction → visible by default
    timeout_seconds: int = 180


class SamlCapture:
    """Drive a browser through M365 SSO and intercept the AWS SAML POST.

    The Playwright dependency is injected via *browser_factory* (defaulting to
    the real ``playwright.sync_api.sync_playwright`` loaded lazily), so the
    whole flow is testable with a fake browser context.
    """

    def __init__(
        self,
        config: SamlCaptureConfig,
        *,
        browser_factory: Optional[Callable] = None,
    ) -> None:
        self._config = config
        self._browser_factory = browser_factory

    # -- lazy Playwright load ------------------------------------------------

    @staticmethod
    def _load_playwright() -> Callable:
        """Import and return ``sync_playwright`` lazily.

        Raises:
            SamlCaptureError: if Playwright is not installed, with the exact
            commands to install the optional ``browser`` extra + chromium.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
            raise SamlCaptureError(
                "Playwright is not installed — required for direct SAML "
                "capture (Option A-prime).\n"
                "Install the optional browser extra and a browser binary:\n"
                "    uv pip install 'ck-creds[browser]'   "
                "# (or: pip install playwright)\n"
                "    python -m playwright install chromium\n"
                "Alternatively, paste a cookie manually with --portal-token "
                "(Option B)."
            ) from exc
        return sync_playwright

    # -- public entry point --------------------------------------------------

    def capture(self) -> str:
        """Launch a browser, sign in, and return the intercepted SAML assertion.

        Opens a persistent browser context (reusing the cached M365 session
        when present), navigates to the configured *start_url*, and blocks on
        the browser's ``SAMLResponse`` POST to the ACS endpoint, returning the
        base64 assertion from that request body.

        Returns:
            The base64-encoded SAML assertion (the ``SAMLResponse`` value),
            ready to hand to :func:`cli.portal.saml_parser.parse_saml_assertion`.

        Raises:
            SamlCaptureError: Playwright missing, browser launch failure, login
            timeout, or a matching POST that carried no ``SAMLResponse``.
        """
        factory = self._browser_factory or self._load_playwright()

        # Persistent profile dir, locked down (holds an authenticated browser
        # session — treat like the token cache).
        profile_dir = Path(self._config.user_data_dir)
        profile_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(profile_dir, 0o700)
        except OSError:  # pragma: no cover - best-effort on exotic filesystems
            pass

        acs_url = self._config.acs_url

        def _matcher(request) -> bool:
            return _is_saml_acs_request(request.url, request.method, acs_url)

        try:
            with factory() as pw:
                context = pw.chromium.launch_persistent_context(
                    str(profile_dir),
                    headless=self._config.headless,
                )
                try:
                    page = context.new_page()
                    # Arm the interceptor BEFORE navigating so we never miss a
                    # fast redirect that fires the SAML POST.
                    with page.expect_request(
                        _matcher,
                        timeout=self._config.timeout_seconds * 1000,
                    ) as req_info:
                        page.goto(self._config.start_url)
                    request = req_info.value
                    assertion = _extract_saml_response(request.post_data)
                    if not assertion:
                        raise SamlCaptureError(
                            "Intercepted the AWS SAML POST but it carried no "
                            f"{SAML_RESPONSE_FIELD} field — the IdP may have "
                            "returned an error page instead of an assertion. "
                            "Retry the sign-in."
                        )
                    return assertion
                finally:
                    context.close()
        except SamlCaptureError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalise any Playwright error
            raise SamlCaptureError(
                "Did not capture an AWS SAML assertion: "
                f"{exc}. Finish the M365 sign-in (incl. MFA) in the browser "
                "window before the timeout, or raise --saml-timeout. On "
                "headless servers a browser binary and its system dependencies "
                "must be installed "
                "(`python -m playwright install --with-deps chromium`)."
            ) from exc
