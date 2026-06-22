"""Option A — headless/headed browser cookie capture for the portal session token.

This is the durable, no-Azure-admin path to obtain the IAM Identity Center
portal session cookie (``x-amz-sso_authn``).  A real browser drives the AWS
access-portal start URL, the user completes M365 SSO (incl. MFA) *in that
browser*, and we scrape the ``x-amz-sso_authn`` cookie the portal sets on
success.  The scraped value is fed into the exact same
``_resolve_portal_token()`` seam that Option B (manual paste) uses — so this is
not a parallel code path, just a different *source* for the same token.

Why a real browser at all?  The portal API only accepts the ``x-amz-sso_authn``
session cookie (proven live: an Entra/OIDC token is rejected with HTTP 401, and
the AWS app is SAML-only so no Entra-issued token will ever work — see the
plan's As-Built drift D1/D3).  The only first-party way to mint that cookie is
to complete the SAML→ACS browser exchange, which is exactly what signing in via
the start URL does.

Design notes:
  * **Playwright is an OPTIONAL dependency.**  It is imported lazily inside
    :meth:`BrowserCapture.capture` so the rest of the CLI keeps working when it
    is not installed.  A missing install raises a clean, actionable
    :class:`BrowserCaptureError` with the install commands.
  * **Headed + persistent profile by default.**  MFA needs user interaction, so
    the browser is visible by default, and the browser profile is persisted
    under ``~/.ck_creds/browser_profile`` so subsequent runs reuse the M365
    session ("stay signed in") and capture the cookie with little or no
    interaction — the no-browser-after-first-login goal.
  * **The logic is unit-testable without a browser.**  Cookie extraction
    (:func:`_extract_portal_cookie`) is a pure function, and the poll/timeout
    loop (:meth:`BrowserCapture._poll_for_cookie`) takes any object exposing a
    ``cookies()`` method and uses injected ``sleep``/``clock`` callables, so
    tests drive it with a fake context.  Only the thin Playwright-launching
    shell in :meth:`capture` needs a real browser (exercised by the spike, not
    the unit suite).
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional

from cli.auth.token_cache import DEFAULT_CACHE_DIR

# Cookie the IAM Identity Center access portal sets once SAML→ACS succeeds.
PORTAL_COOKIE_NAME = "x-amz-sso_authn"

# Persistent browser profile — sibling of the token cache, so one `logout`/wipe
# location covers everything.  Reusing it lets M365 "stay signed in" survive
# across runs (the durable, mostly-silent UX).
DEFAULT_PROFILE_DIR = DEFAULT_CACHE_DIR / "browser_profile"


class BrowserCaptureError(RuntimeError):
    """Raised when the browser capture cannot produce a portal session token.

    Covers: Playwright not installed, the browser failing to launch, and the
    login not completing before the timeout.
    """


def _extract_portal_cookie(cookies: Iterable[Mapping]) -> Optional[str]:
    """Return the ``x-amz-sso_authn`` value from a Playwright cookie list.

    *cookies* is the list of cookie dicts as returned by
    ``BrowserContext.cookies()`` — each a mapping with at least ``name`` and
    ``value`` keys.  Returns the first non-empty match, or ``None`` if the
    portal cookie is not present yet (i.e. login is still in progress).

    Pure function: no I/O, no browser — the unit-testable heart of capture.
    """
    for cookie in cookies:
        if cookie.get("name") == PORTAL_COOKIE_NAME:
            value = cookie.get("value")
            if value:
                return value
    return None


@dataclass
class BrowserCaptureConfig:
    """Configuration for a browser capture run."""

    sso_start_url: str
    user_data_dir: Path = field(default=DEFAULT_PROFILE_DIR)
    headless: bool = False  # MFA needs interaction → visible by default
    timeout_seconds: int = 180
    poll_interval_seconds: float = 1.0


class BrowserCapture:
    """Drive a browser to the AWS access portal and scrape the session cookie.

    The Playwright dependency is injected via *browser_factory* (defaulting to
    the real ``playwright.sync_api.sync_playwright`` loaded lazily), and the
    timing primitives via *sleep*/*clock*, so the whole flow is testable with a
    fake browser context and a fake clock.
    """

    def __init__(
        self,
        config: BrowserCaptureConfig,
        *,
        browser_factory: Optional[Callable] = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._browser_factory = browser_factory
        self._sleep = sleep
        self._clock = clock

    # -- lazy Playwright load ------------------------------------------------

    @staticmethod
    def _load_playwright() -> Callable:
        """Import and return ``sync_playwright`` lazily.

        Raises:
            BrowserCaptureError: if Playwright is not installed, with the exact
            commands to install the optional ``browser`` extra + chromium.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - exercised via tests w/ monkeypatch
            raise BrowserCaptureError(
                "Playwright is not installed — required for browser capture "
                "(Option A).\n"
                "Install the optional browser extra and a browser binary:\n"
                "    uv pip install 'ck-creds[browser]'   "
                "# (or: pip install playwright)\n"
                "    python -m playwright install chromium\n"
                "Alternatively, paste a cookie manually with --portal-token "
                "(Option B)."
            ) from exc
        return sync_playwright

    # -- poll loop (browser-agnostic, fully testable) ------------------------

    def _poll_for_cookie(self, context) -> str:
        """Poll *context*.cookies() until the portal cookie appears or timeout.

        *context* is any object exposing a ``cookies()`` method returning a
        list of cookie mappings (a Playwright ``BrowserContext`` in production,
        a fake in tests).  Uses the injected clock/sleep so tests run instantly.

        Raises:
            BrowserCaptureError: if the timeout elapses with no portal cookie.
        """
        deadline = self._clock() + self._config.timeout_seconds
        while True:
            token = _extract_portal_cookie(context.cookies())
            if token:
                return token
            if self._clock() >= deadline:
                raise BrowserCaptureError(
                    "Timed out after "
                    f"{self._config.timeout_seconds}s waiting for the "
                    f"{PORTAL_COOKIE_NAME} cookie. Did the sign-in complete? "
                    "Finish M365 login (incl. MFA) in the browser window, or "
                    "raise the timeout."
                )
            self._sleep(self._config.poll_interval_seconds)

    # -- public entry point --------------------------------------------------

    def capture(self) -> str:
        """Launch a browser, sign in at the start URL, return the portal token.

        Opens a persistent browser context (reusing the cached M365 session
        when present), navigates to the configured SSO start URL, and waits for
        the ``x-amz-sso_authn`` cookie to be set, polling until it appears or
        the timeout elapses.

        Returns:
            The ``x-amz-sso_authn`` portal session token (bare cookie value).

        Raises:
            BrowserCaptureError: Playwright missing, browser launch failure, or
            login timeout.
        """
        factory = self._browser_factory or self._load_playwright()

        # Persistent profile dir, locked down (it holds an authenticated
        # browser session — treat like the token cache).
        profile_dir = Path(self._config.user_data_dir)
        profile_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(profile_dir, 0o700)
        except OSError:  # pragma: no cover - best-effort on exotic filesystems
            pass

        try:
            with factory() as pw:
                context = pw.chromium.launch_persistent_context(
                    str(profile_dir),
                    headless=self._config.headless,
                )
                try:
                    page = context.new_page()
                    page.goto(self._config.sso_start_url)
                    return self._poll_for_cookie(context)
                finally:
                    context.close()
        except BrowserCaptureError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalise any Playwright error
            raise BrowserCaptureError(
                f"Browser capture failed to launch or run: {exc}. "
                "On headless servers a browser binary and its system "
                "dependencies must be installed "
                "(`python -m playwright install --with-deps chromium`)."
            ) from exc
