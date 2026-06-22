"""Unit tests for cli.auth.env_auth — EnvAuthenticator and get_env_authenticator."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cli.auth.env_auth import EnvAuthenticator, get_env_authenticator, _read_env
from cli.auth.msal_auth import AuthConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_config() -> AuthConfig:
    return AuthConfig(
        tenant_id="test-tenant",
        client_id="test-client",
        iic_app_id_uri="https://signin.aws.amazon.com/saml/test",
    )


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / ".ck_creds"


def _make_authenticator(auth_config, cache_dir, username="user@example.com", password="s3cr3t"):
    return EnvAuthenticator(auth_config, username=username, password=password, cache_dir=cache_dir)


# ---------------------------------------------------------------------------
# _read_env
# ---------------------------------------------------------------------------

class TestReadEnv:
    def test_reads_from_env(self, monkeypatch):
        monkeypatch.setenv("CK_CREDS_USERNAME", "u@example.com")
        monkeypatch.setenv("CK_CREDS_PASSWORD", "pass123")
        username, password = _read_env()
        assert username == "u@example.com"
        assert password == "pass123"

    def test_env_takes_priority_over_cfg(self, monkeypatch):
        monkeypatch.setenv("CK_CREDS_USERNAME", "env@example.com")
        monkeypatch.setenv("CK_CREDS_PASSWORD", "envpass")
        username, _ = _read_env(cfg_username="cfg@example.com")
        assert username == "env@example.com"

    def test_cfg_username_fallback(self, monkeypatch):
        monkeypatch.delenv("CK_CREDS_USERNAME", raising=False)
        monkeypatch.setenv("CK_CREDS_PASSWORD", "pass123")
        username, password = _read_env(cfg_username="cfg@example.com")
        assert username == "cfg@example.com"
        assert password == "pass123"

    def test_returns_none_when_unset(self, monkeypatch):
        monkeypatch.delenv("CK_CREDS_USERNAME", raising=False)
        monkeypatch.delenv("CK_CREDS_PASSWORD", raising=False)
        username, password = _read_env()
        assert username is None
        assert password is None


# ---------------------------------------------------------------------------
# get_env_authenticator
# ---------------------------------------------------------------------------

class TestGetEnvAuthenticator:
    def test_returns_authenticator_when_creds_set(self, monkeypatch, auth_config, cache_dir):
        monkeypatch.setenv("CK_CREDS_USERNAME", "u@example.com")
        monkeypatch.setenv("CK_CREDS_PASSWORD", "pass")
        auth = get_env_authenticator(auth_config, cache_dir=cache_dir)
        assert auth is not None
        assert isinstance(auth, EnvAuthenticator)

    def test_returns_none_when_no_password(self, monkeypatch, auth_config, cache_dir):
        monkeypatch.setenv("CK_CREDS_USERNAME", "u@example.com")
        monkeypatch.delenv("CK_CREDS_PASSWORD", raising=False)
        auth = get_env_authenticator(auth_config, cache_dir=cache_dir)
        assert auth is None

    def test_returns_none_when_no_username_or_cfg(self, monkeypatch, auth_config, cache_dir):
        monkeypatch.delenv("CK_CREDS_USERNAME", raising=False)
        monkeypatch.setenv("CK_CREDS_PASSWORD", "pass")
        auth = get_env_authenticator(auth_config, cache_dir=cache_dir)
        assert auth is None

    def test_uses_cfg_username(self, monkeypatch, auth_config, cache_dir):
        monkeypatch.delenv("CK_CREDS_USERNAME", raising=False)
        monkeypatch.setenv("CK_CREDS_PASSWORD", "pass")
        auth = get_env_authenticator(auth_config, cfg_username="cfg@example.com", cache_dir=cache_dir)
        assert auth is not None
        assert auth._username == "cfg@example.com"


# ---------------------------------------------------------------------------
# EnvAuthenticator.get_access_token
# ---------------------------------------------------------------------------

class TestEnvAuthenticatorGetAccessToken:
    def _mock_msal_app(self, result_first=None, result_second=None):
        """Return a mock MSAL PublicClientApplication."""
        app = MagicMock()
        app.get_accounts.return_value = []  # no cached accounts by default
        if result_second is not None:
            app.acquire_token_by_username_password.side_effect = [result_first, result_second]
        else:
            app.acquire_token_by_username_password.return_value = result_first
        app.acquire_token_silent.return_value = None
        return app

    def test_ropc_success(self, auth_config, cache_dir):
        """Happy path: ROPC returns access_token immediately."""
        authenticator = _make_authenticator(auth_config, cache_dir)
        mock_app = self._mock_msal_app({"access_token": "tok123"})

        with patch.object(authenticator, "_build_app", return_value=mock_app):
            token = authenticator.get_access_token()

        assert token == "tok123"
        mock_app.acquire_token_by_username_password.assert_called_once_with(
            username="user@example.com",
            password="s3cr3t",
            scopes=auth_config.scopes,
        )

    def test_silent_refresh_success(self, auth_config, cache_dir):
        """Silent refresh path returns token without calling ROPC."""
        authenticator = _make_authenticator(auth_config, cache_dir)
        mock_app = MagicMock()
        mock_app.get_accounts.return_value = [{"username": "user@example.com"}]
        mock_app.acquire_token_silent.return_value = {"access_token": "silent_tok"}

        with patch.object(authenticator, "_build_app", return_value=mock_app):
            token = authenticator.get_access_token()

        assert token == "silent_tok"
        mock_app.acquire_token_by_username_password.assert_not_called()

    def test_mfa_required_totp_success(self, auth_config, cache_dir):
        """ROPC returns MFA error → totp_callback called → retry with password+otp succeeds."""
        authenticator = _make_authenticator(auth_config, cache_dir)
        mock_app = self._mock_msal_app(
            result_first={"error": "interaction_required", "suberror": "mfa_required"},
            result_second={"access_token": "tok_with_totp"},
        )
        prompts = []

        with patch.object(authenticator, "_build_app", return_value=mock_app):
            token = authenticator.get_access_token(
                prompt_callback=lambda msg: prompts.append(msg),
                totp_callback=lambda: "123456",
            )

        assert token == "tok_with_totp"
        # Second ROPC call should append TOTP to password
        calls = mock_app.acquire_token_by_username_password.call_args_list
        assert len(calls) == 2
        assert calls[1].kwargs["password"] == "s3cr3t123456"
        # Should have printed MFA prompt
        assert any("MFA" in str(p) for p in prompts)

    def test_mfa_getpass_fallback(self, auth_config, cache_dir):
        """When totp_callback is None, getpass is used."""
        authenticator = _make_authenticator(auth_config, cache_dir)
        mock_app = self._mock_msal_app(
            result_first={"error": "interaction_required", "suberror": "mfa_required"},
            result_second={"access_token": "tok"},
        )

        with patch.object(authenticator, "_build_app", return_value=mock_app), \
             patch("getpass.getpass", return_value="654321"):
            token = authenticator.get_access_token()

        assert token == "tok"
        calls = mock_app.acquire_token_by_username_password.call_args_list
        assert calls[1].kwargs["password"] == "s3cr3t654321"

    def test_device_code_fallback_on_ropc_blocked(self, auth_config, cache_dir):
        """When ROPC fails with a non-MFA error, falls back to device-code."""
        authenticator = _make_authenticator(auth_config, cache_dir)
        mock_app = self._mock_msal_app(
            result_first={"error": "unauthorized_client", "suberror": ""}
        )
        prompts = []

        with patch.object(authenticator, "_build_app", return_value=mock_app), \
             patch("cli.auth.env_auth.MsalAuthenticator") as MockMsal:
            MockMsal.return_value.get_access_token.return_value = "device_tok"
            token = authenticator.get_access_token(
                prompt_callback=lambda msg: prompts.append(msg),
            )

        assert token == "device_tok"
        MockMsal.return_value.get_access_token.assert_called_once()
        assert any("falling back" in str(p).lower() for p in prompts)

    def test_ropc_returns_no_totp_and_no_mfa_falls_through(self, auth_config, cache_dir):
        """ROPC fails with non-MFA error and no TOTP → device-code fallback."""
        authenticator = _make_authenticator(auth_config, cache_dir)
        mock_app = self._mock_msal_app(
            result_first={"error": "access_denied", "suberror": "some_unknown_suberror"}
        )

        with patch.object(authenticator, "_build_app", return_value=mock_app), \
             patch("cli.auth.env_auth.MsalAuthenticator") as MockMsal:
            MockMsal.return_value.get_access_token.return_value = "device_tok"
            token = authenticator.get_access_token(prompt_callback=lambda _: None)

        assert token == "device_tok"

    def test_logout_clears_cache(self, auth_config, cache_dir):
        """logout() removes the cached token."""
        authenticator = _make_authenticator(auth_config, cache_dir)
        # Write a fake cache entry
        authenticator._cache.save("msal_tokens", {"msal_state": "{}", "expires_at": time.time() + 100})
        assert authenticator._cache.load("msal_tokens") is not None
        authenticator.logout()
        assert authenticator._cache.load("msal_tokens") is None
