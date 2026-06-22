"""Tests for cli.portal.portal_client."""
from __future__ import annotations

import pytest
import responses as rsps_lib

from cli.portal.portal_client import AppInstance, AppProfile, PortalClient, SamlAssertion

REGION = "eu-west-1"
TOKEN = "test-bearer-token"
BASE = f"https://portal.sso.{REGION}.amazonaws.com"

# ---------------------------------------------------------------------------
# Fixtures / sample data
# ---------------------------------------------------------------------------

APP_LIST_RESPONSE = {
    "paginationToken": None,
    "result": [
        {
            "id": "ins-1111111111111111",
            "name": "Example-AdministratorAccess",
            "description": "Example-AdministratorAccess Application",
            "applicationId": "app-3333333333333333",
            "applicationName": "External AWS Account",
            "icon": "https://static.global.sso.amazonaws.com/app-3333333333333333/icons/default.png",
            "searchMetadata": None,
        },
        {
            "id": "ins-2222222222222222",
            "name": "Example2-AdministratorAccess",
            "description": "Example2-AdministratorAccess Application",
            "applicationId": "app-3333333333333333",
            "applicationName": "External AWS Account",
            "icon": "https://static.global.sso.amazonaws.com/app-3333333333333333/icons/default.png",
            "searchMetadata": None,
        },
    ],
}

ASSERTION_URL = (
    f"{BASE}/saml/assertion/idp/"
    "MTIzNDU2Nzg5MDEyX2lucy0xMTExMTExMTExMTExMTExX3AtNDQ0NDQ0NDQ0NDQ0NDQ0NA=="
)

PROFILES_RESPONSE = {
    "paginationToken": None,
    "result": [
        {
            "id": "p-4444444444444444",
            "name": "Default",
            "description": "",
            "url": ASSERTION_URL,
            "protocol": "SAML",
            "relayState": None,
        }
    ],
}

SAML_ASSERTION_RESPONSE = {
    "encodedResponse": "PD94bWw+base64samlxml==",
    "destination": "https://signin.aws.amazon.com/saml",
    "relayState": None,
    "prettyPrintedXml": "",
}


@pytest.fixture
def client() -> PortalClient:
    return PortalClient(token=TOKEN, region=REGION)


# ---------------------------------------------------------------------------
# list_app_instances
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_list_app_instances_returns_apps(client: PortalClient) -> None:
    rsps_lib.add(rsps_lib.POST, f"{BASE}/instance/appinstances", json=APP_LIST_RESPONSE)
    apps, next_token = client.list_app_instances()
    assert len(apps) == 2
    assert next_token is None
    assert isinstance(apps[0], AppInstance)
    assert apps[0].id == "ins-1111111111111111"
    assert apps[0].name == "Example-AdministratorAccess"
    assert apps[1].id == "ins-2222222222222222"


@rsps_lib.activate
def test_list_app_instances_request_body(client: PortalClient) -> None:
    rsps_lib.add(rsps_lib.POST, f"{BASE}/instance/appinstances", json=APP_LIST_RESPONSE)
    client.list_app_instances(max_result=50)
    body = rsps_lib.calls[0].request.body
    assert "max_result=50" in body
    assert "resource_type=APPLICATION" in body


@rsps_lib.activate
def test_list_app_instances_bearer_token(client: PortalClient) -> None:
    rsps_lib.add(rsps_lib.POST, f"{BASE}/instance/appinstances", json=APP_LIST_RESPONSE)
    client.list_app_instances()
    auth = rsps_lib.calls[0].request.headers["Authorization"]
    assert auth == f"Bearer {TOKEN}"


@rsps_lib.activate
def test_list_all_app_instances_paginates(client: PortalClient) -> None:
    page1 = {"paginationToken": "tok-next", "result": [APP_LIST_RESPONSE["result"][0]]}
    page2 = {"paginationToken": None, "result": [APP_LIST_RESPONSE["result"][1]]}
    rsps_lib.add(rsps_lib.POST, f"{BASE}/instance/appinstances", json=page1)
    rsps_lib.add(rsps_lib.POST, f"{BASE}/instance/appinstances", json=page2)
    apps = client.list_all_app_instances()
    assert len(apps) == 2
    # second request must include the pagination token
    second_body = rsps_lib.calls[1].request.body
    assert "paginationToken=tok-next" in second_body


# ---------------------------------------------------------------------------
# list_profiles
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_list_profiles_returns_profiles(client: PortalClient) -> None:
    app_id = "ins-1111111111111111"
    rsps_lib.add(
        rsps_lib.POST,
        f"{BASE}/instance/appinstance/{app_id}/profiles",
        json=PROFILES_RESPONSE,
    )
    profiles = client.list_profiles(app_id)
    assert len(profiles) == 1
    assert isinstance(profiles[0], AppProfile)
    assert profiles[0].id == "p-4444444444444444"
    assert profiles[0].name == "Default"
    assert profiles[0].protocol == "SAML"
    assert profiles[0].url == ASSERTION_URL
    assert profiles[0].relay_state is None


@rsps_lib.activate
def test_list_profiles_request_body(client: PortalClient) -> None:
    app_id = "ins-1111111111111111"
    rsps_lib.add(
        rsps_lib.POST,
        f"{BASE}/instance/appinstance/{app_id}/profiles",
        json=PROFILES_RESPONSE,
    )
    client.list_profiles(app_id, max_result=50)
    body = rsps_lib.calls[0].request.body
    assert "max_result=50" in body


# ---------------------------------------------------------------------------
# get_saml_assertion
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_get_saml_assertion_returns_assertion(client: PortalClient) -> None:
    rsps_lib.add(rsps_lib.GET, ASSERTION_URL, json=SAML_ASSERTION_RESPONSE)
    assertion = client.get_saml_assertion(ASSERTION_URL)
    assert isinstance(assertion, SamlAssertion)
    assert assertion.encoded_response == "PD94bWw+base64samlxml=="
    assert assertion.destination == "https://signin.aws.amazon.com/saml"
    assert assertion.relay_state is None


@rsps_lib.activate
def test_get_saml_assertion_bearer_token(client: PortalClient) -> None:
    rsps_lib.add(rsps_lib.GET, ASSERTION_URL, json=SAML_ASSERTION_RESPONSE)
    client.get_saml_assertion(ASSERTION_URL)
    auth = rsps_lib.calls[0].request.headers["Authorization"]
    assert auth == f"Bearer {TOKEN}"


# ---------------------------------------------------------------------------
# Request timeouts (drift D6 regression) — every portal HTTP call must pass a
# non-None timeout so a stalled socket can never hang the CLI forever.
# ---------------------------------------------------------------------------


def _assert_timeout_passed(mocked, expected) -> None:
    assert mocked.call_count == 1
    assert mocked.call_args.kwargs.get("timeout") == expected


def test_list_app_instances_sets_timeout(mocker) -> None:
    client = PortalClient(token=TOKEN, region=REGION)
    resp = mocker.Mock()
    resp.json.return_value = APP_LIST_RESPONSE
    resp.raise_for_status.return_value = None
    post = mocker.patch.object(client._session, "post", return_value=resp)
    client.list_app_instances()
    _assert_timeout_passed(post, (5, 30))


def test_list_profiles_sets_timeout(mocker) -> None:
    client = PortalClient(token=TOKEN, region=REGION)
    resp = mocker.Mock()
    resp.json.return_value = PROFILES_RESPONSE
    resp.raise_for_status.return_value = None
    post = mocker.patch.object(client._session, "post", return_value=resp)
    client.list_profiles("ins-1111111111111111")
    _assert_timeout_passed(post, (5, 30))


def test_get_saml_assertion_sets_timeout(mocker) -> None:
    client = PortalClient(token=TOKEN, region=REGION)
    resp = mocker.Mock()
    resp.json.return_value = SAML_ASSERTION_RESPONSE
    resp.raise_for_status.return_value = None
    get = mocker.patch.object(client._session, "get", return_value=resp)
    client.get_saml_assertion(ASSERTION_URL)
    _assert_timeout_passed(get, (5, 30))


def test_timeout_is_configurable(mocker) -> None:
    client = PortalClient(token=TOKEN, region=REGION, timeout=12)
    resp = mocker.Mock()
    resp.json.return_value = APP_LIST_RESPONSE
    resp.raise_for_status.return_value = None
    post = mocker.patch.object(client._session, "post", return_value=resp)
    client.list_app_instances()
    _assert_timeout_passed(post, 12)
