import base64
import responses as resp_lib
import pytest
from cli.portal.saml_exchange import SamlExchanger, ExchangeConfig

FAKE_SAML = base64.b64encode(b"<saml>fake</saml>").decode()

FAKE_AZURE_HTML = f"""
<html><body>
<form method="POST" action="https://us-east-1.signin.aws.amazon.com/platform/saml/acs/abc123">
  <input type="hidden" name="SAMLResponse" value="{FAKE_SAML}" />
  <input type="hidden" name="RelayState" value="relay" />
</form>
</body></html>
"""


@pytest.fixture
def config():
    return ExchangeConfig(
        tenant_id="tenant-123",
        iic_app_id="app-id-456",
    )


@resp_lib.activate
def test_fetches_saml_from_azure(config):
    resp_lib.add(
        resp_lib.GET,
        "https://login.microsoftonline.com/tenant-123/saml2",
        body=FAKE_AZURE_HTML,
        status=200,
        content_type="text/html",
    )
    resp_lib.add(
        resp_lib.POST,
        "https://us-east-1.signin.aws.amazon.com/platform/saml/acs/abc123",
        status=302,
        headers={"Set-Cookie": "x-amz-sso_authn=portal-session-token; Path=/"},
    )
    exchanger = SamlExchanger(config)
    portal_token = exchanger.exchange("msal-access-token-xyz")
    assert portal_token == "portal-session-token"


@resp_lib.activate
def test_raises_if_saml_form_not_found(config):
    resp_lib.add(
        resp_lib.GET,
        "https://login.microsoftonline.com/tenant-123/saml2",
        body="<html><body>Error page</body></html>",
        status=200,
        content_type="text/html",
    )
    exchanger = SamlExchanger(config)
    with pytest.raises(ValueError, match="SAMLResponse"):
        exchanger.exchange("bad-token")


@resp_lib.activate
def test_raises_if_acs_returns_no_cookie(config):
    resp_lib.add(
        resp_lib.GET,
        "https://login.microsoftonline.com/tenant-123/saml2",
        body=FAKE_AZURE_HTML,
        status=200,
        content_type="text/html",
    )
    resp_lib.add(
        resp_lib.POST,
        "https://us-east-1.signin.aws.amazon.com/platform/saml/acs/abc123",
        status=302,
        headers={},  # no Set-Cookie
    )
    exchanger = SamlExchanger(config)
    with pytest.raises(ValueError, match="Portal session token not found"):
        exchanger.exchange("msal-access-token-xyz")


@resp_lib.activate
def test_azure_request_sends_bearer_token(config):
    """Verify the Bearer token is sent in the Authorization header."""
    resp_lib.add(
        resp_lib.GET,
        "https://login.microsoftonline.com/tenant-123/saml2",
        body=FAKE_AZURE_HTML,
        status=200,
        content_type="text/html",
    )
    resp_lib.add(
        resp_lib.POST,
        "https://us-east-1.signin.aws.amazon.com/platform/saml/acs/abc123",
        status=302,
        headers={"Set-Cookie": "x-amz-sso_authn=tok; Path=/"},
    )
    exchanger = SamlExchanger(config)
    exchanger.exchange("my-access-token")
    assert resp_lib.calls[0].request.headers["Authorization"] == "Bearer my-access-token"
