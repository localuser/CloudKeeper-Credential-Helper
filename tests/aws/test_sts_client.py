"""Tests for cli.aws.sts_client."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

import pytest
from botocore.exceptions import ClientError

from cli.aws.sts_client import AwsCredentials, StsClient, _is_duration_error
from cli.portal.portal_client import SamlAssertion
from cli.portal.saml_parser import ParsedRole

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPIRY = datetime(2026, 6, 10, 14, 0, 0, tzinfo=timezone.utc)

ROLE = ParsedRole(
    role_arn="arn:aws:iam::123456789012:role/MyRole-SSO-Role",
    principal_arn="arn:aws:iam::123456789012:saml-provider/MyRole-idp",
    session_name="user@example.com",
    not_on_or_after=datetime(2099, 1, 1, tzinfo=timezone.utc),  # far future → 43200
    session_not_on_or_after=None,
)

ASSERTION = SamlAssertion(
    encoded_response="PD94bWwgdmVyc2lvbj0iMS4wIj48L3Jlc3BvbnNlPg==",
    destination="https://signin.aws.amazon.com/saml",
    relay_state=None,
)

STS_RESPONSE = {
    "Credentials": {
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": EXPIRY,
    },
}


def _make_client_error(code: str, message: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}}, "AssumeRoleWithSAML"
    )


def _sts_client_with_mock(mock_sts: MagicMock) -> StsClient:
    session = MagicMock()
    session.client.return_value = mock_sts
    return StsClient(region="eu-west-1", boto_session=session)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_returns_credentials_on_success() -> None:
    mock_sts = MagicMock()
    mock_sts.assume_role_with_saml.return_value = STS_RESPONSE
    client = _sts_client_with_mock(mock_sts)

    creds = client.assume_role_with_saml(ROLE, ASSERTION)

    assert isinstance(creds, AwsCredentials)
    assert creds.access_key_id == "ASIAEXAMPLE"
    assert creds.secret_access_key == "secret"
    assert creds.session_token == "token"
    assert creds.expiration == EXPIRY
    assert creds.role_arn == ROLE.role_arn
    assert creds.region == "eu-west-1"


def test_passes_correct_args_to_sts() -> None:
    mock_sts = MagicMock()
    mock_sts.assume_role_with_saml.return_value = STS_RESPONSE
    client = _sts_client_with_mock(mock_sts)

    client.assume_role_with_saml(ROLE, ASSERTION)

    mock_sts.assume_role_with_saml.assert_called_once_with(
        RoleArn=ROLE.role_arn,
        PrincipalArn=ROLE.principal_arn,
        SAMLAssertion=ASSERTION.encoded_response,
        DurationSeconds=43200,
    )


# ---------------------------------------------------------------------------
# Duration fallback
# ---------------------------------------------------------------------------


def test_retries_with_shorter_duration_on_validation_error() -> None:
    duration_error = _make_client_error(
        "ValidationError",
        "DurationSeconds exceeds the MaxSessionDuration set for this role.",
    )
    mock_sts = MagicMock()
    # First call fails with duration error, second succeeds
    mock_sts.assume_role_with_saml.side_effect = [duration_error, STS_RESPONSE]
    client = _sts_client_with_mock(mock_sts)

    creds = client.assume_role_with_saml(ROLE, ASSERTION)

    assert creds.access_key_id == "ASIAEXAMPLE"
    assert mock_sts.assume_role_with_saml.call_count == 2
    # Second call should use a shorter duration (next ladder step ≤ 43200)
    second_call_kwargs = mock_sts.assume_role_with_saml.call_args_list[1].kwargs
    assert second_call_kwargs["DurationSeconds"] < 43200


def test_exhausts_all_ladder_steps_then_raises() -> None:
    duration_error = _make_client_error(
        "ValidationError",
        "DurationSeconds exceeds the MaxSessionDuration set for this role.",
    )
    mock_sts = MagicMock()
    mock_sts.assume_role_with_saml.side_effect = duration_error
    client = _sts_client_with_mock(mock_sts)

    with pytest.raises(ClientError):
        client.assume_role_with_saml(ROLE, ASSERTION)

    # Should have tried all ladder steps (900 is min and also fails here)
    assert mock_sts.assume_role_with_saml.call_count > 1


def test_non_duration_error_raised_immediately() -> None:
    other_error = _make_client_error("AccessDenied", "User is not authorized.")
    mock_sts = MagicMock()
    mock_sts.assume_role_with_saml.side_effect = other_error
    client = _sts_client_with_mock(mock_sts)

    with pytest.raises(ClientError, match="AccessDenied"):
        client.assume_role_with_saml(ROLE, ASSERTION)

    # Only called once — no retry on non-duration errors
    assert mock_sts.assume_role_with_saml.call_count == 1


# ---------------------------------------------------------------------------
# AwsCredentials helpers
# ---------------------------------------------------------------------------


def test_as_env_keys() -> None:
    creds = AwsCredentials(
        access_key_id="KEY",
        secret_access_key="SECRET",
        session_token="TOKEN",
        expiration=EXPIRY,
        role_arn="arn:aws:iam::123:role/Test",
    )
    env = creds.as_env()
    assert env["AWS_ACCESS_KEY_ID"] == "KEY"
    assert env["AWS_SECRET_ACCESS_KEY"] == "SECRET"
    assert env["AWS_SESSION_TOKEN"] == "TOKEN"


def test_as_credentials_block_keys() -> None:
    creds = AwsCredentials(
        access_key_id="KEY",
        secret_access_key="SECRET",
        session_token="TOKEN",
        expiration=EXPIRY,
        role_arn="arn:aws:iam::123:role/Test",
    )
    block = creds.as_credentials_block()
    assert block["aws_access_key_id"] == "KEY"
    assert block["aws_secret_access_key"] == "SECRET"
    assert block["aws_session_token"] == "TOKEN"


# ---------------------------------------------------------------------------
# _is_duration_error helper
# ---------------------------------------------------------------------------


def test_is_duration_error_true() -> None:
    assert _is_duration_error(
        "ValidationError",
        "DurationSeconds exceeds the MaxSessionDuration set for this role.",
    )


def test_is_duration_error_false_wrong_code() -> None:
    assert not _is_duration_error(
        "AccessDenied",
        "DurationSeconds exceeds the MaxSessionDuration set for this role.",
    )


def test_is_duration_error_false_wrong_message() -> None:
    assert not _is_duration_error("ValidationError", "Some other validation problem.")
