from __future__ import annotations

import dataclasses
from typing import Optional

import requests

PORTAL_BASE = "https://portal.sso.{region}.amazonaws.com"

# (connect, read) timeout in seconds for all portal HTTP calls.  Without this,
# ``requests`` blocks forever on a stalled socket (observed: a >7-minute hang on
# ``ck-creds list`` against a stalled Azure/portal connection — drift D6).
DEFAULT_TIMEOUT = (5, 30)


@dataclasses.dataclass
class AppInstance:
    id: str
    name: str
    description: str
    application_id: str
    application_name: str
    icon: str


@dataclasses.dataclass
class AppProfile:
    id: str
    name: str
    description: str
    url: str          # full SAML assertion URL — use directly with get_saml_assertion()
    protocol: str
    relay_state: Optional[str]


@dataclasses.dataclass
class SamlAssertion:
    encoded_response: str   # base64-encoded SAML XML — pass straight to STS
    destination: str        # https://signin.aws.amazon.com/saml
    relay_state: Optional[str]


class PortalClient:
    """Client for the IAM Identity Center portal API.

    All calls authenticate with ``Authorization: Bearer <token>`` where the
    token is the ``x-amz-sso_authn`` cookie value obtained after the
    SAML exchange (see :mod:`cli.portal.saml_exchange`).
    """

    def __init__(
        self,
        token: str,
        region: str,
        session: Optional[requests.Session] = None,
        timeout: tuple[float, float] | float = DEFAULT_TIMEOUT,
    ) -> None:
        self._token = token
        self._region = region
        self._base = PORTAL_BASE.format(region=region)
        self._session = session or requests.Session()
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json, text/plain, */*",
        }

    def _form_headers(self) -> dict[str, str]:
        return {
            **self._auth_headers(),
            "Content-Type": "application/x-www-form-urlencoded",
        }

    # ------------------------------------------------------------------
    # App instances
    # ------------------------------------------------------------------

    def list_app_instances(
        self,
        max_result: int = 100,
        pagination_token: Optional[str] = None,
    ) -> tuple[list[AppInstance], Optional[str]]:
        """Return one page of app instances assigned to the current user.

        Returns a ``(apps, next_pagination_token)`` tuple.  When
        ``next_pagination_token`` is ``None`` there are no further pages.
        """
        url = f"{self._base}/instance/appinstances"
        data: dict[str, object] = {
            "max_result": max_result,
            "resource_type": "APPLICATION",
        }
        if pagination_token:
            data["paginationToken"] = pagination_token

        resp = self._session.post(
            url, headers=self._form_headers(), data=data, timeout=self._timeout
        )
        resp.raise_for_status()
        body = resp.json()

        apps = [
            AppInstance(
                id=item["id"],
                name=item["name"],
                description=item.get("description", ""),
                application_id=item["applicationId"],
                application_name=item["applicationName"],
                icon=item.get("icon", ""),
            )
            for item in body["result"]
        ]
        return apps, body.get("paginationToken")

    def list_all_app_instances(self) -> list[AppInstance]:
        """Paginate through *all* app instances and return the combined list."""
        all_apps: list[AppInstance] = []
        pagination_token: Optional[str] = None
        while True:
            apps, pagination_token = self.list_app_instances(
                pagination_token=pagination_token
            )
            all_apps.extend(apps)
            if not pagination_token:
                break
        return all_apps

    # ------------------------------------------------------------------
    # Profiles
    # ------------------------------------------------------------------

    def list_profiles(
        self,
        app_instance_id: str,
        max_result: int = 100,
    ) -> list[AppProfile]:
        """Return profiles for a single app instance.

        Each profile carries a ``url`` field that is the fully-qualified
        SAML assertion endpoint — pass it directly to :meth:`get_saml_assertion`.
        """
        url = f"{self._base}/instance/appinstance/{app_instance_id}/profiles"
        resp = self._session.post(
            url,
            headers=self._form_headers(),
            data={"max_result": max_result},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        return [
            AppProfile(
                id=item["id"],
                name=item["name"],
                description=item.get("description", ""),
                url=item["url"],
                protocol=item["protocol"],
                relay_state=item.get("relayState"),
            )
            for item in body["result"]
        ]

    # ------------------------------------------------------------------
    # SAML assertion
    # ------------------------------------------------------------------

    def get_saml_assertion(self, profile_url: str) -> SamlAssertion:
        """Fetch a SAML assertion from the URL stored in an :class:`AppProfile`.

        The ``encodedResponse`` in the returned object is a base64-encoded
        SAML XML document.  Its ``Attribute`` elements contain the
        ``RoleArn`` and ``PrincipalArn`` needed for
        ``STS.AssumeRoleWithSAML``.
        """
        resp = self._session.get(
            profile_url, headers=self._auth_headers(), timeout=self._timeout
        )
        resp.raise_for_status()
        body = resp.json()
        return SamlAssertion(
            encoded_response=body["encodedResponse"],
            destination=body["destination"],
            relay_state=body.get("relayState"),
        )
