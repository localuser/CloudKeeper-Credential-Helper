from unittest.mock import patch, MagicMock
import pytest
from cli.auth.msal_auth import MsalAuthenticator, AuthConfig


@pytest.fixture
def config():
    return AuthConfig(
        tenant_id="tenant-123",
        client_id="client-456",
        iic_app_id_uri="https://signin.aws.amazon.com/saml",
    )


def test_silent_refresh_returns_cached(config, tmp_cache_dir):
    auth = MsalAuthenticator(config, cache_dir=tmp_cache_dir)
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = [{"username": "user@example.com"}]
    mock_app.acquire_token_silent.return_value = {
        "access_token": "tok123",
        "expires_in": 3600,
    }
    with patch("cli.auth.msal_auth.msal.PublicClientApplication", return_value=mock_app):
        token = auth.get_access_token()
    assert token == "tok123"


def test_device_code_flow_invoked_when_no_account(config, tmp_cache_dir):
    auth = MsalAuthenticator(config, cache_dir=tmp_cache_dir)
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = []
    mock_app.initiate_device_flow.return_value = {
        "user_code": "ABCD1234",
        "verification_uri": "https://microsoft.com/devicelogin",
        "message": "Go to https://microsoft.com/devicelogin and enter ABCD1234",
    }
    mock_app.acquire_token_by_device_flow.return_value = {
        "access_token": "newtoken",
        "expires_in": 3600,
    }
    with patch("cli.auth.msal_auth.msal.PublicClientApplication", return_value=mock_app):
        token = auth.get_access_token(prompt_callback=lambda msg: None)
    assert token == "newtoken"


def test_raises_on_auth_error(config, tmp_cache_dir):
    auth = MsalAuthenticator(config, cache_dir=tmp_cache_dir)
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = []
    mock_app.initiate_device_flow.return_value = {
        "user_code": "X",
        "verification_uri": "y",
        "message": "m",
    }
    mock_app.acquire_token_by_device_flow.return_value = {"error": "authorization_declined"}
    with patch("cli.auth.msal_auth.msal.PublicClientApplication", return_value=mock_app):
        with pytest.raises(RuntimeError, match="authorization_declined"):
            auth.get_access_token(prompt_callback=lambda msg: None)


def test_default_scope_derived_from_app_uri(tmp_cache_dir):
    cfg = AuthConfig(
        tenant_id="t",
        client_id="c",
        iic_app_id_uri="https://signin.aws.amazon.com/saml",
    )
    assert cfg.scopes == ["https://signin.aws.amazon.com/saml/.default"]


def test_logout_clears_cache(config, tmp_cache_dir):
    from cli.auth.token_cache import TokenCache
    import time
    cache = TokenCache(tmp_cache_dir)
    cache.save("msal_tokens", {"msal_state": "{}", "expires_at": time.time() + 9999})
    auth = MsalAuthenticator(config, cache_dir=tmp_cache_dir)
    auth.logout()
    assert cache.load("msal_tokens") is None
