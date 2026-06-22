"""AWS SSO OIDC device-code authenticator (Path 2 fallback).

Flow:
  1. Check cache — return token early if still valid.
  2. register_client → start_device_authorization → print prompt URL.
  3. Poll create_token, honouring AuthorizationPendingException + SlowDownException.
  4. Cache the returned portal access token.

The token produced here is the same IAM Identity Center portal access token
as Path 1 produces, so all downstream steps (list apps, per-app SAML, STS)
are identical regardless of which auth path was used.
"""
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import boto3
from botocore.exceptions import ClientError

from .token_cache import TokenCache, DEFAULT_CACHE_DIR


@dataclass
class OidcConfig:
    sso_start_url: str
    region: str
    client_name: str = "ck-creds"


class OidcAuthenticator:
    """Obtain an IAM Identity Center portal access token via AWS SSO OIDC."""

    CACHE_KEY = "oidc_portal_token"

    def __init__(self, config: OidcConfig, cache_dir: Path = DEFAULT_CACHE_DIR):
        self._config = config
        self._cache = TokenCache(cache_dir)

    def get_access_token(
        self,
        prompt_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Return a valid portal access token, prompting via device code if needed.

        Args:
            prompt_callback: Called with the human-readable login prompt string.
                Defaults to ``print``.

        Returns:
            IAM Identity Center portal access_token string.

        Raises:
            TimeoutError: If the device authorization expires before the user logs in.
            ClientError: For unexpected AWS API errors.
        """
        cached = self._cache.load(self.CACHE_KEY)
        if cached:
            return cached["access_token"]

        if prompt_callback is None:
            prompt_callback = print

        client = boto3.client("sso-oidc", region_name=self._config.region)

        reg = client.register_client(
            clientName=self._config.client_name,
            clientType="public",
        )
        client_id = reg["clientId"]
        client_secret = reg["clientSecret"]

        auth = client.start_device_authorization(
            clientId=client_id,
            clientSecret=client_secret,
            startUrl=self._config.sso_start_url,
        )

        interval = max(auth.get("interval", 5), 1)
        prompt_callback(
            f"\n🔐 Open: {auth['verificationUriComplete']}\n"
            f"   Or visit {auth['verificationUri']} and enter: {auth['userCode']}\n"
        )

        deadline = time.time() + auth["expiresIn"]
        while time.time() < deadline:
            time.sleep(interval)
            try:
                result = client.create_token(
                    clientId=client_id,
                    clientSecret=client_secret,
                    grantType="urn:ietf:params:oauth:grant-type:device_code",
                    deviceCode=auth["deviceCode"],
                )
                access_token = result["accessToken"]
                self._cache.save(self.CACHE_KEY, {
                    "access_token": access_token,
                    "expires_at": time.time() + result.get("expiresIn", 28800),
                })
                return access_token
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "AuthorizationPendingException":
                    continue
                elif code == "SlowDownException":
                    interval += 5
                    continue
                else:
                    raise

        raise TimeoutError("AWS SSO OIDC device authorization timed out")

    def logout(self) -> None:
        """Clear the cached portal access token."""
        self._cache.clear(self.CACHE_KEY)
