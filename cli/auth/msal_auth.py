"""MSAL-based M365 device-code authenticator (Path 1).

Flow:
  1. Try MSAL silent token refresh from cached account.
  2. If no account / silent fails → initiate device-code flow, print prompt.
  3. Persist the MSAL token cache to ~/.ck_creds/msal_tokens.json after success.
"""
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

import msal

from .token_cache import TokenCache, DEFAULT_CACHE_DIR


@dataclass
class AuthConfig:
    tenant_id: str
    client_id: str
    iic_app_id_uri: str  # e.g. "https://signin.aws.amazon.com/saml"
    scopes: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.scopes:
            self.scopes = [f"{self.iic_app_id_uri}/.default"]


class MsalAuthenticator:
    """Obtain an OAuth2 access token for the IAM Identity Center Azure AD app.

    The token is used downstream by the SAML exchange step to obtain a SAML
    assertion that the IAM Identity Center ACS endpoint will accept.
    """

    CACHE_KEY = "msal_tokens"

    def __init__(self, config: AuthConfig, cache_dir: Path = DEFAULT_CACHE_DIR):
        self._config = config
        self._cache = TokenCache(cache_dir)
        self._token_cache = msal.SerializableTokenCache()
        # Restore persisted MSAL token cache if available
        cached = self._cache.load(self.CACHE_KEY)
        if cached and "msal_state" in cached:
            self._token_cache.deserialize(cached["msal_state"])

    def _build_app(self) -> msal.PublicClientApplication:
        authority = f"https://login.microsoftonline.com/{self._config.tenant_id}"
        return msal.PublicClientApplication(
            self._config.client_id,
            authority=authority,
            token_cache=self._token_cache,
        )

    def _persist_cache(self) -> None:
        if self._token_cache.has_state_changed:
            self._cache.save(self.CACHE_KEY, {
                "msal_state": self._token_cache.serialize(),
                # Long-lived TTL — MSAL manages its own token expiry internally
                "expires_at": time.time() + 86400 * 90,
            })

    def get_access_token(
        self,
        prompt_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Return a valid OAuth2 access token.

        Args:
            prompt_callback: Called with the device-code message string.
                Defaults to ``print`` so the prompt appears in the terminal.

        Returns:
            A valid access_token string.

        Raises:
            RuntimeError: If the auth flow returns an error.
        """
        app = self._build_app()
        accounts = app.get_accounts()

        if accounts:
            result = app.acquire_token_silent(self._config.scopes, account=accounts[0])
            if result and "access_token" in result:
                self._persist_cache()
                return result["access_token"]

        # No cached account or silent refresh failed — device-code flow
        if prompt_callback is None:
            prompt_callback = print

        flow = app.initiate_device_flow(scopes=self._config.scopes)
        prompt_callback(flow["message"])
        result = app.acquire_token_by_device_flow(flow)

        if "error" in result:
            raise RuntimeError(
                f"MSAL auth failed: {result['error']} — {result.get('error_description', '')}"
            )

        self._persist_cache()
        return result["access_token"]

    def logout(self) -> None:
        """Clear the persisted MSAL token cache."""
        self._cache.clear(self.CACHE_KEY)
