"""SAML exchange: M365 OAuth2 access token → IAM Identity Center portal session token.

Path 1 flow:
  1. GET Azure AD IdP-initiated SAML endpoint with Bearer token.
     Azure AD returns an HTML page with a hidden <form> auto-posting to the ACS URL.
  2. Parse SAMLResponse + action URL from that form.
  3. POST SAMLResponse to the IAM Identity Center ACS URL (allow_redirects=False).
     ACS sets x-amz-sso_authn cookie — this is the portal session token.
"""
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional

import requests


@dataclass
class ExchangeConfig:
    tenant_id: str
    iic_app_id: str  # Azure AD Enterprise App client/object ID for IAM Identity Center


class _FormParser(HTMLParser):
    """Extract hidden form fields and action URL from an HTML SAML POST page."""

    def __init__(self):
        super().__init__()
        self.action: Optional[str] = None
        self.fields: dict[str, str] = {}
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._in_form = True
            self.action = attrs.get("action")
        elif tag == "input" and self._in_form:
            name = attrs.get("name")
            value = attrs.get("value", "")
            if name is not None:
                self.fields[name] = value or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


class SamlExchanger:
    """Exchange an M365 OAuth2 access token for an IAM Identity Center portal session token."""

    AZURE_SAML_ENDPOINT = "https://login.microsoftonline.com/{tenant}/saml2"

    def __init__(self, config: ExchangeConfig, session: Optional[requests.Session] = None):
        self._config = config
        self._session = session or requests.Session()

    def _fetch_saml_html(self, access_token: str) -> str:
        """Call Azure AD IdP-initiated SAML endpoint → HTML form page."""
        url = self.AZURE_SAML_ENDPOINT.format(tenant=self._config.tenant_id)
        resp = self._session.get(
            url,
            params={"client_id": self._config.iic_app_id},
            headers={"Authorization": f"Bearer {access_token}"},
            allow_redirects=True,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.text

    def _parse_saml_form(self, html: str) -> tuple[str, dict[str, str]]:
        """Extract ACS action URL and form fields (SAMLResponse, RelayState) from HTML."""
        parser = _FormParser()
        parser.feed(html)
        if not parser.action or "SAMLResponse" not in parser.fields:
            raise ValueError(
                "SAMLResponse not found in Azure AD response. "
                "Check tenant_id / iic_app_id and ensure the access token scope is correct."
            )
        return parser.action, parser.fields

    def _post_to_acs(self, acs_url: str, form_fields: dict[str, str]) -> str:
        """POST SAML assertion to IAM Identity Center ACS → return portal session token."""
        resp = self._session.post(
            acs_url,
            data=form_fields,
            allow_redirects=False,  # capture Set-Cookie before following redirect
            timeout=30,
        )
        # Prefer requests' cookie jar (handles URL-decoding automatically)
        for name, value in resp.cookies.items():
            if "sso" in name.lower() or "authn" in name.lower():
                return value

        # Fallback: parse raw Set-Cookie header directly
        set_cookie = resp.headers.get("Set-Cookie", "")
        match = re.search(r"x-amz-sso_authn=([^;]+)", set_cookie)
        if match:
            return match.group(1)

        raise ValueError(
            f"Portal session token not found in ACS response. "
            f"Status: {resp.status_code}, Headers: {dict(resp.headers)}"
        )

    def exchange(self, msal_access_token: str) -> str:
        """Full Path 1 exchange: MSAL access token → portal session token.

        Args:
            msal_access_token: OAuth2 access token from MSAL for the IAM Identity Center app.

        Returns:
            IAM Identity Center portal session token (x-amz-sso_authn cookie value).

        Raises:
            ValueError: If the SAML form or portal cookie is not found.
            requests.HTTPError: If Azure AD or ACS returns a non-2xx/3xx response.
        """
        html = self._fetch_saml_html(msal_access_token)
        acs_url, form_fields = self._parse_saml_form(html)
        return self._post_to_acs(acs_url, form_fields)
