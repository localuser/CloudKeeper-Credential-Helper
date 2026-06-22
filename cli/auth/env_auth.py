"""ROPC (username/password) authenticator with TOTP fallback (Path 1).

Reads credentials from environment variables:
  CK_CREDS_USERNAME  — M365 UPN (e.g. user@example.com)
  CK_CREDS_PASSWORD  — M365 password (never stored)

Flow:
  1. Try MSAL silent token refresh from cached account.
  2. Try ROPC (username + password) — fast, no browser.
  3. If MFA is required, call totp_callback() to get a one-time code,
     then retry ROPC with password+OTP appended (Azure AD "legacy MFA" pattern).
  4. If still blocked (Conditional Access policy, etc.) → fall back to
     MSAL device-code flow, identical to the non-env-var path.

Hermes TUI usage:
  - Store CK_CREDS_USERNAME + CK_CREDS_PASSWORD in .env
  - Run `ck-creds login` with pty=True in terminal()
  - When TOTP prompt appears, user types 6-digit code into chat
  - Session token cached for ~8h; subsequent logins are silent
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable, Optional

import msal

from .msal_auth import AuthConfig, MsalAuthenticator
from .token_cache import DEFAULT_CACHE_DIR, TokenCache

# MSAL ROPC error codes that mean "MFA required, please supply OTP"
_MFA_ERRORS = frozenset({
    "interaction_required",
    "mfa_required",
    "access_denied",   # some CA policies surface this
})
_MFA_SUBERRORS = frozenset({
    "mfa_required",
    "msauth_phone_app_required",
    "",   # suberror absent but error == interaction_required
})


def _read_env(cfg_username: str | None = None) -> tuple[str | None, str | None]:
    """Return (username, password) from environment, with optional config.json fallback for username."""
    username = os.environ.get("CK_CREDS_USERNAME") or cfg_username or None
    password = os.environ.get("CK_CREDS_PASSWORD")
    return username, password


class EnvAuthenticator:
    """MSAL authenticator that uses env-var credentials for non-interactive login.

    Falls back gracefully through:
      silent cache → ROPC → ROPC+TOTP → device-code
    """

    CACHE_KEY = "msal_tokens"

    def __init__(
        self,
        config: AuthConfig,
        username: str,
        password: str,
        cache_dir: Path = DEFAULT_CACHE_DIR,
    ) -> None:
        self._config = config
        self._username = username
        self._password = password
        self._cache = TokenCache(cache_dir)
        self._token_cache = msal.SerializableTokenCache()

        cached = self._cache.load(self.CACHE_KEY)
        if cached and "msal_state" in cached:
            self._token_cache.deserialize(cached["msal_state"])

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _build_app(self) -> msal.PublicClientApplication:
        return msal.PublicClientApplication(
            self._config.client_id,
            authority=f"https://login.microsoftonline.com/{self._config.tenant_id}",
            token_cache=self._token_cache,
        )

    def _persist_cache(self) -> None:
        if self._token_cache.has_state_changed:
            self._cache.save(self.CACHE_KEY, {
                "msal_state": self._token_cache.serialize(),
                "expires_at": time.time() + 86400 * 90,
            })

    def _ropc(self, app: msal.PublicClientApplication, password: str) -> dict:
        """Attempt ROPC with the given password (or password+otp)."""
        return app.acquire_token_by_username_password(
            username=self._username,
            password=password,
            scopes=self._config.scopes,
        )

    def _needs_totp(self, result: dict) -> bool:
        """True if MSAL says MFA is required and we should try TOTP."""
        error = result.get("error", "")
        suberror = result.get("suberror", "")
        return error in _MFA_ERRORS and suberror in _MFA_SUBERRORS

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def get_access_token(
        self,
        prompt_callback: Optional[Callable[[str], None]] = None,
        totp_callback: Optional[Callable[[], str]] = None,
    ) -> str:
        """Return a valid OAuth2 access token.

        Args:
            prompt_callback: Called with status/fallback messages (rich markup ok).
            totp_callback:   Called (no args) when MFA is required; must return the
                             6-digit TOTP code string. Defaults to a getpass prompt.

        Returns:
            A valid access_token string.
        """
        if prompt_callback is None:
            prompt_callback = print

        app = self._build_app()

        # 1 — silent refresh
        accounts = app.get_accounts(username=self._username)
        if accounts:
            result = app.acquire_token_silent(self._config.scopes, account=accounts[0])
            if result and "access_token" in result:
                self._persist_cache()
                return result["access_token"]

        # 2 — ROPC (password only)
        prompt_callback(f"[dim]Authenticating as [bold]{self._username}[/bold] (ROPC)...[/dim]")
        result = self._ropc(app, self._password)

        if "access_token" in result:
            self._persist_cache()
            return result["access_token"]

        # 3 — ROPC + TOTP (password concatenation)
        if self._needs_totp(result):
            prompt_callback(
                "\n[bold yellow]MFA required.[/bold yellow] "
                "Enter the 6-digit code from your authenticator app."
            )
            if totp_callback is None:
                import getpass
                totp_callback = lambda: getpass.getpass("TOTP: ").strip()  # noqa: E731

            totp = totp_callback()
            result = self._ropc(app, self._password + totp)

            if "access_token" in result:
                self._persist_cache()
                return result["access_token"]

        # 4 — fallback: device-code (browser / phone approval)
        prompt_callback(
            f"\n[yellow]ROPC blocked ({result.get('error', 'unknown')}) — "
            "falling back to device-code flow.[/yellow]"
        )
        fallback = MsalAuthenticator(self._config, cache_dir=self._cache._dir)
        token = fallback.get_access_token(prompt_callback=prompt_callback)
        return token

    def logout(self) -> None:
        """Clear the persisted MSAL token cache."""
        self._cache.clear(self.CACHE_KEY)


# ---------------------------------------------------------------------------
# Convenience factory — use this in main.py
# ---------------------------------------------------------------------------

def get_env_authenticator(
    config: AuthConfig,
    cfg_username: str | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> "EnvAuthenticator | None":
    """Return an EnvAuthenticator if credentials are available, else None.

    Credential resolution order:
      1. CK_CREDS_USERNAME env var   (or cfg_username from config.json)
      2. CK_CREDS_PASSWORD env var   (password never stored anywhere)
    """
    username, password = _read_env(cfg_username=cfg_username)
    if username and password:
        return EnvAuthenticator(config, username=username, password=password, cache_dir=cache_dir)
    return None
