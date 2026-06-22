"""Tests for cli/main.py — click command wiring."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cli.aws.sts_client import AwsCredentials
from cli.main import cli, _load_config, _save_config
from cli.portal.portal_client import AppInstance, AppProfile, SamlAssertion
from cli.portal.saml_parser import ParsedRole

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

EXPIRY = datetime(2099, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

FAKE_CREDS = AwsCredentials(
    access_key_id="AKIA_FAKE",
    secret_access_key="SECRET_FAKE",
    session_token="TOKEN_FAKE",
    expiration=EXPIRY,
    role_arn="arn:aws:iam::123456789:role/TestRole",
)

FAKE_ROLE = ParsedRole(
    role_arn="arn:aws:iam::123456789:role/TestRole",
    principal_arn="arn:aws:iam::123456789:saml-provider/TestIdP",
    session_name="user@example.com",
    not_on_or_after=EXPIRY,
    session_not_on_or_after=None,
)

FAKE_INSTANCE = AppInstance(
    id="ins-abc123",
    name="TestApp",
    description="",
    application_id="app-xyz",
    application_name="External AWS Account",
    icon="https://static.global.sso.amazonaws.com/icon.png",
)

FAKE_PROFILE = AppProfile(
    id="p-aaa111",
    name="Default",
    description="",
    url="https://portal.sso.eu-west-1.amazonaws.com/saml/assertion/idp/AAAA==",
    protocol="SAML",
    relay_state=None,
)

FAKE_ASSERTION = SamlAssertion(
    encoded_response="ENCODED_RESPONSE",
    destination="https://signin.aws.amazon.com/saml",
    relay_state=None,
)

VALID_CONFIG = {
    "tenant_id": "tenant-id-1",
    "client_id": "client-id-1",
    "iic_app_id_uri": "https://signin.aws.amazon.com/saml/example",
    "iic_azure_app_id": "azure-app-id",
    "sso_start_url": "https://example.awsapps.com/start",
    "region": "eu-west-1",
}


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def tmp_config(tmp_path, monkeypatch):
    """Redirect config path and token cache to tmp_path."""
    config_file = tmp_path / "config.json"
    monkeypatch.setattr("cli.main.CONFIG_PATH", config_file)
    monkeypatch.setattr("cli.main.DEFAULT_CACHE_DIR", tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------


class TestConfigure:
    def test_writes_config(self, runner, tmp_config):
        result = runner.invoke(
            cli,
            ["configure"],
            input="\n".join(
                [
                    "tenant-abc",     # tenant_id
                    "",               # client_id (default)
                    "https://signin.aws.amazon.com/saml/x",  # iic_app_id_uri
                    "azure-id",       # iic_azure_app_id
                    "",               # sso_start_url
                    "eu-west-1",      # region
                    "",               # username (optional, leave blank)
                    "",               # trailing newline
                ]
            ),
        )
        assert result.exit_code == 0, result.output
        cfg_path = tmp_config / "config.json"
        assert cfg_path.exists()
        data = json.loads(cfg_path.read_text())
        assert data["tenant_id"] == "tenant-abc"
        assert data["region"] == "eu-west-1"

    def test_config_file_is_0o600(self, runner, tmp_config):
        runner.invoke(
            cli,
            ["configure"],
            input="\n".join(
                [
                    "t", "", "https://x", "", "", "us-east-1", "", "",
                ]
            ),
        )
        cfg_path = tmp_config / "config.json"
        mode = oct(cfg_path.stat().st_mode & 0o777)
        assert mode == "0o600"


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_clears_token_cache(self, runner, tmp_config):
        # plant a fake token file
        (tmp_config / "portal_token.json").write_text('{"token": "x"}')
        with patch("cli.main.TokenCache") as MockCache:
            mock_instance = MagicMock()
            MockCache.return_value = mock_instance
            result = runner.invoke(cli, ["logout"])
        assert result.exit_code == 0
        mock_instance.clear_all.assert_called_once()

    def test_output_confirms_logout(self, runner, tmp_config):
        with patch("cli.main.TokenCache") as MockCache:
            MockCache.return_value = MagicMock()
            result = runner.invoke(cli, ["logout"])
        assert "cleared" in result.output.lower()


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestList:
    def _mock_chain(self, monkeypatch, instances=None):
        if instances is None:
            instances = [FAKE_INSTANCE]
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.setattr("cli.main._get_portal_token", lambda cfg, path2=False: "tok")
        mock_client = MagicMock()
        mock_client.list_all_app_instances.return_value = instances
        monkeypatch.setattr(
            "cli.main._make_portal_client", lambda cfg, tok: mock_client
        )
        return mock_client

    def test_shows_app_names(self, runner, monkeypatch):
        self._mock_chain(monkeypatch)
        result = runner.invoke(cli, ["list"])
        assert result.exit_code == 0
        assert "TestApp" in result.output

    def test_empty_list_message(self, runner, monkeypatch):
        self._mock_chain(monkeypatch, instances=[])
        result = runner.invoke(cli, ["list"])
        assert result.exit_code == 0
        assert "No applications" in result.output

    def test_path2_flag_passes_through(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        captured = {}

        def fake_oidc_token(cfg):
            captured["path2"] = True
            return "tok"

        monkeypatch.setattr("cli.main._get_oidc_token", fake_oidc_token)
        monkeypatch.setattr(
            "cli.main.SsoClient",
            lambda access_token, region: MagicMock(list_account_roles=lambda: []),
        )
        runner.invoke(cli, ["list", "--path2"])
        assert captured.get("path2") is True


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


class TestLogin:
    def _setup(self, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.setattr("cli.main._get_portal_token", lambda cfg, path2=False: "tok")
        mock_client = MagicMock()
        mock_client.list_all_app_instances.return_value = [FAKE_INSTANCE]
        mock_client.list_profiles.return_value = [FAKE_PROFILE]
        mock_client.get_saml_assertion.return_value = FAKE_ASSERTION
        monkeypatch.setattr("cli.main._make_portal_client", lambda cfg, tok: mock_client)
        monkeypatch.setattr(
            "cli.main.parse_saml_assertion", lambda enc: [FAKE_ROLE]
        )
        monkeypatch.setattr("cli.main._assume", lambda cfg, role, assertion: FAKE_CREDS)
        mock_writer = MagicMock()
        mock_writer.write.return_value = Path("/home/user/.aws/credentials")
        monkeypatch.setattr("cli.main.CredentialsWriter", lambda: mock_writer)
        return mock_writer

    def test_writes_credentials(self, runner, monkeypatch):
        mock_writer = self._setup(monkeypatch)
        result = runner.invoke(cli, ["login", "--app", "TestApp", "--role", "TestRole"])
        assert result.exit_code == 0, result.output
        mock_writer.write.assert_called_once()

    def test_writes_to_specified_profile(self, runner, monkeypatch):
        mock_writer = self._setup(monkeypatch)
        runner.invoke(cli, ["login", "--app", "TestApp", "--profile", "staging"])
        _call_kwargs = mock_writer.write.call_args
        assert _call_kwargs[1].get("profile") == "staging" or _call_kwargs[0][1] == "staging"

    def test_shows_expiry(self, runner, monkeypatch):
        self._setup(monkeypatch)
        result = runner.invoke(cli, ["login", "--app", "TestApp"])
        assert "2099" in result.output


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------


class TestExec:
    def _setup(self, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.setattr("cli.main._get_portal_token", lambda cfg, path2=False: "tok")
        mock_client = MagicMock()
        mock_client.list_all_app_instances.return_value = [FAKE_INSTANCE]
        mock_client.list_profiles.return_value = [FAKE_PROFILE]
        mock_client.get_saml_assertion.return_value = FAKE_ASSERTION
        monkeypatch.setattr("cli.main._make_portal_client", lambda cfg, tok: mock_client)
        monkeypatch.setattr("cli.main.parse_saml_assertion", lambda enc: [FAKE_ROLE])
        monkeypatch.setattr("cli.main._assume", lambda cfg, role, assertion: FAKE_CREDS)

    def test_sets_env_and_runs_command(self, runner, monkeypatch):
        self._setup(monkeypatch)
        captured_env = {}

        def fake_run(cmd, env=None):
            captured_env.update(env or {})
            return MagicMock(returncode=0)

        monkeypatch.setattr("cli.main.subprocess.run", fake_run)
        result = runner.invoke(cli, ["exec", "--app", "TestApp", "--", "aws", "s3", "ls"])
        assert result.exit_code == 0
        assert captured_env.get("AWS_ACCESS_KEY_ID") == "AKIA_FAKE"
        assert captured_env.get("AWS_SECRET_ACCESS_KEY") == "SECRET_FAKE"
        assert captured_env.get("AWS_SESSION_TOKEN") == "TOKEN_FAKE"

    def test_exits_with_subprocess_returncode(self, runner, monkeypatch):
        self._setup(monkeypatch)
        monkeypatch.setattr(
            "cli.main.subprocess.run",
            lambda cmd, env=None: MagicMock(returncode=42),
        )
        result = runner.invoke(cli, ["exec", "--app", "TestApp", "--", "false"])
        assert result.exit_code == 42


# ---------------------------------------------------------------------------
# credential-process
# ---------------------------------------------------------------------------


class TestCredentialProcess:
    def _setup(self, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.setattr("cli.main._get_portal_token", lambda cfg, path2=False: "tok")
        mock_client = MagicMock()
        mock_client.list_all_app_instances.return_value = [FAKE_INSTANCE]
        mock_client.list_profiles.return_value = [FAKE_PROFILE]
        mock_client.get_saml_assertion.return_value = FAKE_ASSERTION
        monkeypatch.setattr("cli.main._make_portal_client", lambda cfg, tok: mock_client)
        monkeypatch.setattr("cli.main.parse_saml_assertion", lambda enc: [FAKE_ROLE])
        monkeypatch.setattr("cli.main._assume", lambda cfg, role, assertion: FAKE_CREDS)

    def test_outputs_valid_json(self, runner, monkeypatch):
        self._setup(monkeypatch)
        result = runner.invoke(cli, ["credential-process", "--app", "TestApp"])
        assert result.exit_code == 0, result.output
        # CliRunner merges stderr+stdout; extract the JSON line
        json_line = next(l for l in result.output.splitlines() if l.startswith("{"))
        data = json.loads(json_line)
        assert data["Version"] == 1
        assert data["AccessKeyId"] == "AKIA_FAKE"
        assert data["SecretAccessKey"] == "SECRET_FAKE"
        assert data["SessionToken"] == "TOKEN_FAKE"
        assert "Expiration" in data

    def test_expiration_is_iso8601(self, runner, monkeypatch):
        self._setup(monkeypatch)
        result = runner.invoke(cli, ["credential-process", "--app", "TestApp"])
        json_line = next(l for l in result.output.splitlines() if l.startswith("{"))
        data = json.loads(json_line)
        # Should parse without error
        datetime.fromisoformat(data["Expiration"])

    def test_no_extra_output_on_stdout(self, runner, monkeypatch):
        """credential-process must print exactly one JSON line (status text goes to stderr).

        CliRunner merges streams; we verify there is exactly one non-empty,
        non-status line and that it parses as valid JSON.
        """
        self._setup(monkeypatch)
        result = runner.invoke(cli, ["credential-process", "--app", "TestApp"])
        json_lines = [l for l in result.output.splitlines() if l.startswith("{")]
        assert len(json_lines) == 1
        parsed = json.loads(json_lines[0])


# ---------------------------------------------------------------------------
# _resolve_portal_token — Option B "manual cookie" injection seam
# ---------------------------------------------------------------------------


class TestResolvePortalToken:
    """The injection seam used by Option B (manual paste) and, later, Option A
    (headless-browser scraped cookie).  When a cookie is injected, the live
    M365/OIDC auth + SAML exchange legs must be skipped entirely."""

    def _no_live_auth(self, monkeypatch):
        """Make the live Path 1 flow explode so we prove it is never reached."""
        def _boom(cfg, path2=False):
            raise AssertionError("_get_portal_token should NOT be called when a cookie is injected")

        monkeypatch.setattr("cli.main._get_portal_token", _boom)

    def test_flag_takes_precedence_and_skips_auth(self, monkeypatch):
        from cli.main import _resolve_portal_token

        self._no_live_auth(monkeypatch)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        assert _resolve_portal_token({}, "RAWCOOKIE") == "RAWCOOKIE"

    def test_env_var_used_when_flag_absent(self, monkeypatch):
        from cli.main import _resolve_portal_token

        self._no_live_auth(monkeypatch)
        monkeypatch.setenv("CK_CREDS_PORTAL_TOKEN", "ENVCOOKIE")
        assert _resolve_portal_token({}, None) == "ENVCOOKIE"

    def test_flag_overrides_env(self, monkeypatch):
        from cli.main import _resolve_portal_token

        self._no_live_auth(monkeypatch)
        monkeypatch.setenv("CK_CREDS_PORTAL_TOKEN", "ENVCOOKIE")
        assert _resolve_portal_token({}, "FLAGCOOKIE") == "FLAGCOOKIE"

    def test_normalises_cookie_pair(self, monkeypatch):
        from cli.main import _resolve_portal_token

        self._no_live_auth(monkeypatch)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        assert _resolve_portal_token({}, "x-amz-sso_authn=ABC123") == "ABC123"

    def test_normalises_bearer_prefix_and_quotes(self, monkeypatch):
        from cli.main import _resolve_portal_token

        self._no_live_auth(monkeypatch)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        assert _resolve_portal_token({}, '  Bearer "ABC123"  ') == "ABC123"

    def test_empty_injected_token_errors(self, monkeypatch):
        import click as _click

        from cli.main import _resolve_portal_token

        self._no_live_auth(monkeypatch)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        with pytest.raises(_click.ClickException):
            _resolve_portal_token({}, "x-amz-sso_authn=")

    def test_falls_back_to_live_auth_when_nothing_injected(self, monkeypatch):
        from cli.main import _resolve_portal_token

        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.setattr("cli.main._get_portal_token", lambda cfg, path2=False: "LIVE")
        assert _resolve_portal_token({}, None) == "LIVE"


class TestListWithInjectedToken:
    """End-to-end: `ck-creds list --portal-token <cookie>` lists apps without auth."""

    def test_injected_token_lists_apps_without_auth(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)

        def _boom(cfg, path2=False):
            raise AssertionError("live auth must be skipped when --portal-token is given")

        monkeypatch.setattr("cli.main._get_portal_token", _boom)

        captured = {}

        def _fake_make_client(cfg, token):
            captured["token"] = token
            mock_client = MagicMock()
            mock_client.list_all_app_instances.return_value = [FAKE_INSTANCE]
            return mock_client

        monkeypatch.setattr("cli.main._make_portal_client", _fake_make_client)

        result = runner.invoke(cli, ["list", "--portal-token", "x-amz-sso_authn=COOKIE9"])
        assert result.exit_code == 0, result.output
        assert "TestApp" in result.output
        assert captured["token"] == "COOKIE9"  # normalised, passed straight through

    def test_expired_cookie_gives_clean_401_message(self, runner, monkeypatch):
        """A 401 from the portal (expired/invalid cookie) must surface as a clean
        ClickException, not a raw requests traceback."""
        import requests

        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.setattr("cli.main._get_portal_token", lambda cfg, path2=False: "unused")

        resp = MagicMock(status_code=401)
        http_err = requests.HTTPError(response=resp)

        def _fake_make_client(cfg, token):
            mock_client = MagicMock()
            mock_client.list_all_app_instances.side_effect = http_err
            return mock_client

        monkeypatch.setattr("cli.main._make_portal_client", _fake_make_client)

        result = runner.invoke(cli, ["list", "--portal-token", "EXPIRED"])
        assert result.exit_code != 0
        assert "401" in result.output
        assert "expired" in result.output.lower()
        # Must be a handled message, not a raw traceback
        assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# _resolve_portal_token — Option A "browser capture" source
# ---------------------------------------------------------------------------


class TestResolvePortalTokenBrowser:
    """The --browser flag / CK_CREDS_BROWSER env routes through the seam to the
    browser-capture function, but an injected --portal-token/env cookie still
    wins (no browser launched when a cookie is already in hand)."""

    def test_browser_flag_invokes_capture(self, monkeypatch):
        from cli.main import _resolve_portal_token

        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.delenv("CK_CREDS_BROWSER", raising=False)

        def _boom(cfg, path2=False):
            raise AssertionError("live Path 1 must be skipped when --browser is set")

        monkeypatch.setattr("cli.main._get_portal_token", _boom)
        monkeypatch.setattr(
            "cli.main._capture_portal_token_via_browser",
            lambda cfg: "BROWSER-TOKEN",
        )
        assert _resolve_portal_token({}, None, use_browser=True) == "BROWSER-TOKEN"

    def test_browser_env_var_invokes_capture(self, monkeypatch):
        from cli.main import _resolve_portal_token

        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.setenv("CK_CREDS_BROWSER", "1")
        monkeypatch.setattr(
            "cli.main._get_portal_token",
            lambda cfg, path2=False: (_ for _ in ()).throw(
                AssertionError("live Path 1 must be skipped")
            ),
        )
        monkeypatch.setattr(
            "cli.main._capture_portal_token_via_browser",
            lambda cfg: "ENV-BROWSER-TOKEN",
        )
        assert _resolve_portal_token({}, None) == "ENV-BROWSER-TOKEN"

    def test_injected_token_beats_browser(self, monkeypatch):
        from cli.main import _resolve_portal_token

        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)

        def _no_browser(cfg):
            raise AssertionError("browser must NOT launch when a cookie is injected")

        monkeypatch.setattr("cli.main._capture_portal_token_via_browser", _no_browser)
        # Even with use_browser=True, an explicit --portal-token wins.
        assert (
            _resolve_portal_token({}, "x-amz-sso_authn=PASTED", use_browser=True)
            == "PASTED"
        )


class TestListWithBrowserCapture:
    """End-to-end: `ck-creds list --browser` captures a cookie then lists apps,
    with the browser capture stubbed (no real browser in the unit suite)."""

    def test_browser_flag_lists_apps(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.delenv("CK_CREDS_BROWSER", raising=False)

        def _boom(cfg, path2=False):
            raise AssertionError("live auth must be skipped when --browser is given")

        monkeypatch.setattr("cli.main._get_portal_token", _boom)
        monkeypatch.setattr(
            "cli.main._capture_portal_token_via_browser",
            lambda cfg: "CAPTURED-COOKIE",
        )

        captured = {}

        def _fake_make_client(cfg, token):
            captured["token"] = token
            mock_client = MagicMock()
            mock_client.list_all_app_instances.return_value = [FAKE_INSTANCE]
            return mock_client

        monkeypatch.setattr("cli.main._make_portal_client", _fake_make_client)

        result = runner.invoke(cli, ["list", "--browser"])
        assert result.exit_code == 0, result.output
        assert "TestApp" in result.output
        assert captured["token"] == "CAPTURED-COOKIE"

    def test_capture_helper_surfaces_clean_error(self, runner, monkeypatch):
        """If the browser capture fails (e.g. Playwright missing), the command
        exits with a clean ClickException, not a traceback."""
        import click as _click

        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.delenv("CK_CREDS_BROWSER", raising=False)

        def _fail(cfg):
            raise _click.ClickException("Playwright is not installed — required for browser capture")

        monkeypatch.setattr("cli.main._capture_portal_token_via_browser", _fail)

        result = runner.invoke(cli, ["list", "--browser"])
        assert result.exit_code != 0
        assert "Playwright is not installed" in result.output
        assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# print-token (Feature A) — capture a cookie and print it for pasting elsewhere
# ---------------------------------------------------------------------------


class TestPrintToken:
    """`ck-creds print-token` makes Option B low-toil: run it on a machine with
    a browser (the laptop), and it prints the bare x-amz-sso_authn cookie to
    STDOUT so it can be captured into a headless environment with:

        export CK_CREDS_PORTAL_TOKEN=$(ck-creds print-token)

    The hard contract is stdout isolation: ONLY the bare token may appear on
    stdout (all status text goes to stderr), or the $(...) capture breaks.
    """

    def test_prints_browser_captured_cookie_on_stdout(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.delenv("CK_CREDS_BROWSER", raising=False)

        # Default path: no injected cookie → browser capture (stubbed).
        monkeypatch.setattr(
            "cli.main._capture_portal_token_via_browser",
            lambda cfg: "SCRAPED-COOKIE",
        )

        result = runner.invoke(cli, ["print-token"])
        assert result.exit_code == 0, result.output
        # Bare token is the ONLY thing on stdout (scriptable capture).
        assert result.stdout.strip() == "SCRAPED-COOKIE"

    def test_status_text_goes_to_stderr_not_stdout(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.delenv("CK_CREDS_BROWSER", raising=False)

        monkeypatch.setattr(
            "cli.main._capture_portal_token_via_browser",
            lambda cfg: "SCRAPED-COOKIE",
        )

        result = runner.invoke(cli, ["print-token"])
        # Nothing but the token on stdout — no rich status leaked in.
        assert result.stdout.count("\n") == 1
        assert "SCRAPED-COOKIE" not in result.stderr

    def test_normalises_injected_cookie_pair(self, runner, monkeypatch):
        """With --portal-token, print-token doubles as a normaliser: a pasted
        `x-amz-sso_authn=<value>` pair is reduced to the bare value. No browser
        launches when a cookie is already in hand."""
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)

        def _no_browser(cfg):
            raise AssertionError("browser must NOT launch when a cookie is injected")

        monkeypatch.setattr("cli.main._capture_portal_token_via_browser", _no_browser)

        result = runner.invoke(
            cli, ["print-token", "--portal-token", "x-amz-sso_authn=ABC123"]
        )
        assert result.exit_code == 0, result.output
        assert result.stdout.strip() == "ABC123"

    def test_capture_failure_is_clean_error(self, runner, monkeypatch):
        """If the browser capture fails (e.g. Playwright missing), print-token
        exits non-zero with a clean message — never a traceback, and never a
        half-written token on stdout."""
        import click as _click

        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.delenv("CK_CREDS_PORTAL_TOKEN", raising=False)
        monkeypatch.delenv("CK_CREDS_BROWSER", raising=False)

        def _fail(cfg):
            raise _click.ClickException(
                "Playwright is not installed — required for browser capture"
            )

        monkeypatch.setattr("cli.main._capture_portal_token_via_browser", _fail)

        result = runner.invoke(cli, ["print-token"])
        assert result.exit_code != 0
        assert "Playwright is not installed" in result.output
        assert "Traceback" not in result.output
        assert result.stdout.strip() == ""  # no token leaked on failure


# ---------------------------------------------------------------------------
# Option A-prime (Feature B) — direct SAML interception wiring in the CLI
# ---------------------------------------------------------------------------


class TestCaptureAssertionViaSamlIntercept:
    """The cli.main helper that drives SamlCapture and wraps the intercepted
    base64 assertion in a SamlAssertion for the unchanged _pick_role/_assume
    path. SamlCaptureError must surface as a clean ClickException."""

    def test_wraps_captured_assertion(self, monkeypatch):
        from cli.main import _capture_assertion_via_saml_intercept
        from cli.portal.portal_client import SamlAssertion

        class _FakeCapture:
            def __init__(self, cfg):  # cfg = SamlCaptureConfig
                self._cfg = cfg

            def capture(self):
                return "INTERCEPTED-B64"

        monkeypatch.setattr("cli.portal.saml_capture.SamlCapture", _FakeCapture)

        result = _capture_assertion_via_saml_intercept(
            {"saml_start_url": "https://launcher/x"}, None
        )
        assert isinstance(result, SamlAssertion)
        assert result.encoded_response == "INTERCEPTED-B64"

    def test_explicit_url_overrides_config(self, monkeypatch):
        from cli.main import _capture_assertion_via_saml_intercept

        seen = {}

        class _FakeCapture:
            def __init__(self, cfg):
                seen["start_url"] = cfg.start_url

            def capture(self):
                return "X"

        monkeypatch.setattr("cli.portal.saml_capture.SamlCapture", _FakeCapture)
        _capture_assertion_via_saml_intercept(
            {"saml_start_url": "https://from-config"}, "https://from-flag"
        )
        assert seen["start_url"] == "https://from-flag"

    def test_missing_start_url_is_clean_error(self, monkeypatch):
        import click as _click

        from cli.main import _capture_assertion_via_saml_intercept

        with pytest.raises(_click.ClickException):
            _capture_assertion_via_saml_intercept({}, None)

    def test_capture_error_becomes_click_exception(self, monkeypatch):
        import click as _click

        from cli.main import _capture_assertion_via_saml_intercept
        from cli.portal.saml_capture import SamlCaptureError

        class _FailCapture:
            def __init__(self, cfg):
                pass

            def capture(self):
                raise SamlCaptureError("Playwright is not installed")

        monkeypatch.setattr("cli.portal.saml_capture.SamlCapture", _FailCapture)
        with pytest.raises(_click.ClickException):
            _capture_assertion_via_saml_intercept(
                {"saml_start_url": "https://x"}, None
            )

    def test_timeout_flows_into_capture_config(self, monkeypatch):
        """An explicit timeout overrides the default on SamlCaptureConfig so the
        interactive-MFA wait can be lengthened — matches the error-message
        promise of a --saml-timeout knob."""
        from cli.main import _capture_assertion_via_saml_intercept

        seen = {}

        class _FakeCapture:
            def __init__(self, cfg):
                seen["timeout_seconds"] = cfg.timeout_seconds

            def capture(self):
                return "X"

        monkeypatch.setattr("cli.portal.saml_capture.SamlCapture", _FakeCapture)
        _capture_assertion_via_saml_intercept(
            {"saml_start_url": "https://x"}, None, timeout=300
        )
        assert seen["timeout_seconds"] == 300


class TestLoginWithBrowserSaml:
    """`ck-creds login --browser-saml` mints credentials by intercepting the
    SAML POST directly — no portal token, no portal client, no app picker."""

    def test_browser_saml_writes_credentials_without_portal(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)

        # The portal path must NOT be touched on the --browser-saml route.
        def _no_portal_token(cfg, portal_token=None, use_browser=False):
            raise AssertionError("portal token resolution must be skipped")

        def _no_portal_client(cfg, tok):
            raise AssertionError("portal client must not be built")

        monkeypatch.setattr("cli.main._resolve_portal_token", _no_portal_token)
        monkeypatch.setattr("cli.main._make_portal_client", _no_portal_client)
        monkeypatch.setattr(
            "cli.main._capture_assertion_via_saml_intercept",
            lambda cfg, saml_url, timeout=None: FAKE_ASSERTION,
        )
        monkeypatch.setattr("cli.main.parse_saml_assertion", lambda enc: [FAKE_ROLE])
        monkeypatch.setattr("cli.main._assume", lambda cfg, role, assertion: FAKE_CREDS)
        mock_writer = MagicMock()
        mock_writer.write.return_value = Path("/home/user/.aws/credentials")
        monkeypatch.setattr("cli.main.CredentialsWriter", lambda: mock_writer)

        result = runner.invoke(cli, ["login", "--browser-saml", "--role", "TestRole"])
        assert result.exit_code == 0, result.output
        mock_writer.write.assert_called_once()

    def test_browser_saml_passes_saml_url_through(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        captured = {}

        def _capture(cfg, saml_url, timeout=None):
            captured["saml_url"] = saml_url
            return FAKE_ASSERTION

        monkeypatch.setattr("cli.main._capture_assertion_via_saml_intercept", _capture)
        monkeypatch.setattr("cli.main.parse_saml_assertion", lambda enc: [FAKE_ROLE])
        monkeypatch.setattr("cli.main._assume", lambda cfg, role, assertion: FAKE_CREDS)
        monkeypatch.setattr("cli.main.CredentialsWriter", lambda: MagicMock())

        runner.invoke(
            cli,
            ["login", "--browser-saml", "--saml-url", "https://app/launch", "-r", "TestRole"],
        )
        assert captured["saml_url"] == "https://app/launch"

    def test_browser_saml_timeout_flag_flows_through(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        captured = {}

        def _capture(cfg, saml_url, timeout=None):
            captured["timeout"] = timeout
            return FAKE_ASSERTION

        monkeypatch.setattr("cli.main._capture_assertion_via_saml_intercept", _capture)
        monkeypatch.setattr("cli.main.parse_saml_assertion", lambda enc: [FAKE_ROLE])
        monkeypatch.setattr("cli.main._assume", lambda cfg, role, assertion: FAKE_CREDS)
        monkeypatch.setattr("cli.main.CredentialsWriter", lambda: MagicMock())

        runner.invoke(
            cli,
            ["login", "--browser-saml", "--saml-timeout", "300", "-r", "TestRole"],
        )
        assert captured["timeout"] == 300


class TestExecWithBrowserSaml:
    def test_browser_saml_execs_with_creds(self, runner, monkeypatch):
        monkeypatch.setattr("cli.main._load_config", lambda: VALID_CONFIG)
        monkeypatch.setattr(
            "cli.main._capture_assertion_via_saml_intercept",
            lambda cfg, saml_url, timeout=None: FAKE_ASSERTION,
        )
        monkeypatch.setattr("cli.main.parse_saml_assertion", lambda enc: [FAKE_ROLE])
        monkeypatch.setattr("cli.main._assume", lambda cfg, role, assertion: FAKE_CREDS)

        captured_env = {}

        def fake_run(cmd, env=None):
            captured_env.update(env or {})
            return MagicMock(returncode=0)

        monkeypatch.setattr("cli.main.subprocess.run", fake_run)
        result = runner.invoke(
            cli, ["exec", "--browser-saml", "--", "aws", "s3", "ls"]
        )
        assert result.exit_code == 0, result.output
        assert captured_env.get("AWS_ACCESS_KEY_ID") == "AKIA_FAKE"
