"""
Integration smoke test — only runs when CK_INTEGRATION=1 in environment.

Requirements:
  - Real ~/.ck_creds/config.json (run `ck-creds configure` first)
  - Valid cached portal token (run `ck-creds login` first)
  - Network access to the IAM Identity Center portal

Run:
  CK_INTEGRATION=1 pytest tests/test_integration_smoke.py -v -s
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("CK_INTEGRATION") != "1",
    reason="Set CK_INTEGRATION=1 to run integration tests",
)

CONFIG_PATH = Path.home() / ".ck_creds" / "config.json"


@pytest.fixture(scope="module")
def cfg() -> dict:
    assert CONFIG_PATH.exists(), (
        "~/.ck_creds/config.json not found — run `ck-creds configure` first"
    )
    with CONFIG_PATH.open() as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def portal_token(cfg: dict) -> str:
    """Load a cached portal bearer token — requires a prior `ck-creds login`."""
    from cli.auth.token_cache import TokenCache

    cache = TokenCache()
    # Try the two possible cache keys (Path 1 and Path 2 store under different keys)
    for key in ("portal_token", "oidc_portal_token"):
        data = cache.load(key)
        if data:
            token = data.get("token") or data.get("access_token") or data.get("accessToken")
            if token:
                return token
    pytest.skip(
        "No cached portal token found — run `ck-creds login` (or `ck-creds login --path2`) first"
    )


@pytest.fixture(scope="module")
def portal_client(cfg: dict, portal_token: str):
    from cli.portal.portal_client import PortalClient

    return PortalClient(token=portal_token, region=cfg["region"])


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


def test_list_app_instances_returns_results(portal_client):
    """Portal API: list_all_app_instances returns at least one application."""
    apps = portal_client.list_all_app_instances()
    assert len(apps) > 0, (
        "No SAML applications found — check your IAM Identity Center assignments"
    )
    print(f"\nFound {len(apps)} app instance(s):")
    for app in apps:
        print(f"  [{app.id}] {app.name}")


def test_list_profiles_for_first_app(portal_client):
    """Portal API: list_profiles returns at least one profile for the first app."""
    apps = portal_client.list_all_app_instances()
    assert apps, "No apps to test profiles against"
    first = apps[0]
    profiles = portal_client.list_profiles(first.id)
    assert len(profiles) > 0, (
        f"No profiles returned for app '{first.name}' ({first.id})"
    )
    print(f"\nApp '{first.name}' has {len(profiles)} profile(s):")
    for p in profiles:
        print(f"  [{p.id}] {p.name}  url={p.url[:60]}...")


def test_get_saml_assertion_is_base64(portal_client):
    """Portal API: SAML assertion endpoint returns a non-empty base64 blob."""
    import base64

    apps = portal_client.list_all_app_instances()
    assert apps
    profiles = portal_client.list_profiles(apps[0].id)
    assert profiles

    assertion = portal_client.get_saml_assertion(profiles[0].url)
    assert assertion.encoded_response, "encodedResponse is empty"
    assert assertion.destination == "https://signin.aws.amazon.com/saml", (
        f"Unexpected destination: {assertion.destination}"
    )
    # Must be valid base64
    decoded = base64.b64decode(assertion.encoded_response)
    assert len(decoded) > 100, "Decoded SAML XML is suspiciously short"
    print(f"\nSAML assertion: {len(decoded)} bytes, destination={assertion.destination}")


def test_parse_saml_assertion_has_roles(portal_client):
    """SAML parser: at least one role ARN is present in the assertion."""
    from cli.portal.saml_parser import parse_saml_assertion

    apps = portal_client.list_all_app_instances()
    assert apps
    profiles = portal_client.list_profiles(apps[0].id)
    assert profiles

    assertion = portal_client.get_saml_assertion(profiles[0].url)
    roles = parse_saml_assertion(assertion.encoded_response)
    assert len(roles) > 0, "No roles found in SAML assertion"
    print(f"\nRoles found in assertion:")
    for role in roles:
        print(f"  {role.role_arn}")


def test_assume_role_returns_credentials(cfg: dict, portal_client):
    """STS: AssumeRoleWithSAML returns valid temporary credentials."""
    from cli.aws.sts_client import StsClient
    from cli.portal.saml_parser import parse_saml_assertion

    apps = portal_client.list_all_app_instances()
    assert apps
    profiles = portal_client.list_profiles(apps[0].id)
    assert profiles

    assertion = portal_client.get_saml_assertion(profiles[0].url)
    roles = parse_saml_assertion(assertion.encoded_response)
    assert roles

    creds = StsClient(region=cfg.get("region", "us-east-1")).assume_role_with_saml(
        roles[0], assertion
    )
    assert creds.access_key_id.startswith("ASIA") or creds.access_key_id.startswith("AKIA"), (
        f"Unexpected key ID prefix: {creds.access_key_id[:4]}"
    )
    assert creds.secret_access_key
    assert creds.session_token
    print(f"\nSTS credentials obtained:")
    print(f"  AccessKeyId: {creds.access_key_id}")
    print(f"  Expiration:  {creds.expiration.isoformat()}")
    print(f"  Role:        {creds.role_arn}")
