from unittest.mock import patch, MagicMock, call
import pytest
from botocore.exceptions import ClientError
from cli.auth.oidc_auth import OidcAuthenticator, OidcConfig


@pytest.fixture
def config():
    return OidcConfig(sso_start_url="https://myorg.awsapps.com/start", region="us-east-1")


def test_returns_access_token(config, tmp_cache_dir):
    auth = OidcAuthenticator(config, cache_dir=tmp_cache_dir)
    mock_client = MagicMock()
    mock_client.register_client.return_value = {
        "clientId": "cid", "clientSecret": "cs", "clientSecretExpiresAt": 9999
    }
    mock_client.start_device_authorization.return_value = {
        "deviceCode": "dc",
        "userCode": "ABCD-1234",
        "verificationUri": "https://device.sso.us-east-1.amazonaws.com",
        "verificationUriComplete": "https://device.sso.us-east-1.amazonaws.com?user_code=ABCD-1234",
        "expiresIn": 600,
        "interval": 1,
    }
    mock_client.create_token.return_value = {"accessToken": "portal-token-abc", "expiresIn": 28800}
    with patch("cli.auth.oidc_auth.boto3.client", return_value=mock_client):
        with patch("cli.auth.oidc_auth.time.sleep"):
            token = auth.get_access_token(prompt_callback=lambda msg: None)
    assert token == "portal-token-abc"


def test_polls_until_authorized(config, tmp_cache_dir):
    auth = OidcAuthenticator(config, cache_dir=tmp_cache_dir)
    mock_client = MagicMock()
    mock_client.register_client.return_value = {
        "clientId": "cid", "clientSecret": "cs", "clientSecretExpiresAt": 9999
    }
    mock_client.start_device_authorization.return_value = {
        "deviceCode": "dc", "userCode": "X", "verificationUri": "y",
        "verificationUriComplete": "y", "expiresIn": 600, "interval": 0,
    }
    pending_error = ClientError({"Error": {"Code": "AuthorizationPendingException"}}, "CreateToken")
    mock_client.create_token.side_effect = [pending_error, {"accessToken": "tok", "expiresIn": 3600}]
    with patch("cli.auth.oidc_auth.boto3.client", return_value=mock_client):
        with patch("cli.auth.oidc_auth.time.sleep"):
            token = auth.get_access_token(prompt_callback=lambda msg: None)
    assert token == "tok"
    assert mock_client.create_token.call_count == 2


def test_slow_down_increases_interval(config, tmp_cache_dir):
    auth = OidcAuthenticator(config, cache_dir=tmp_cache_dir)
    mock_client = MagicMock()
    mock_client.register_client.return_value = {
        "clientId": "cid", "clientSecret": "cs", "clientSecretExpiresAt": 9999
    }
    mock_client.start_device_authorization.return_value = {
        "deviceCode": "dc", "userCode": "X", "verificationUri": "y",
        "verificationUriComplete": "y", "expiresIn": 600, "interval": 1,
    }
    slow_error = ClientError({"Error": {"Code": "SlowDownException"}}, "CreateToken")
    mock_client.create_token.side_effect = [slow_error, {"accessToken": "tok", "expiresIn": 3600}]
    sleep_calls = []
    with patch("cli.auth.oidc_auth.boto3.client", return_value=mock_client):
        with patch("cli.auth.oidc_auth.time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            token = auth.get_access_token(prompt_callback=lambda msg: None)
    assert token == "tok"
    # Second sleep should be longer (interval bumped by 5)
    assert sleep_calls[1] > sleep_calls[0]


def test_cached_token_returned_without_network(config, tmp_cache_dir):
    from cli.auth.token_cache import TokenCache
    import time
    cache = TokenCache(tmp_cache_dir)
    cache.save("oidc_portal_token", {"access_token": "cached-tok", "expires_at": time.time() + 9999})
    auth = OidcAuthenticator(config, cache_dir=tmp_cache_dir)
    with patch("cli.auth.oidc_auth.boto3.client") as mock_boto:
        token = auth.get_access_token()
    mock_boto.assert_not_called()
    assert token == "cached-tok"


def test_logout_clears_cache(config, tmp_cache_dir):
    from cli.auth.token_cache import TokenCache
    import time
    cache = TokenCache(tmp_cache_dir)
    cache.save("oidc_portal_token", {"access_token": "x", "expires_at": time.time() + 9999})
    auth = OidcAuthenticator(config, cache_dir=tmp_cache_dir)
    auth.logout()
    assert cache.load("oidc_portal_token") is None


def test_non_pending_error_raises(config, tmp_cache_dir):
    auth = OidcAuthenticator(config, cache_dir=tmp_cache_dir)
    mock_client = MagicMock()
    mock_client.register_client.return_value = {
        "clientId": "cid", "clientSecret": "cs", "clientSecretExpiresAt": 9999
    }
    mock_client.start_device_authorization.return_value = {
        "deviceCode": "dc", "userCode": "X", "verificationUri": "y",
        "verificationUriComplete": "y", "expiresIn": 600, "interval": 0,
    }
    fatal_error = ClientError({"Error": {"Code": "InvalidClientException"}}, "CreateToken")
    mock_client.create_token.side_effect = fatal_error
    with patch("cli.auth.oidc_auth.boto3.client", return_value=mock_client):
        with patch("cli.auth.oidc_auth.time.sleep"):
            with pytest.raises(ClientError):
                auth.get_access_token(prompt_callback=lambda msg: None)
