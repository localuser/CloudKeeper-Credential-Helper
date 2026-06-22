from __future__ import annotations

import dataclasses
import logging
from datetime import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from cli.portal.saml_parser import ParsedRole
from cli.portal.portal_client import SamlAssertion

logger = logging.getLogger(__name__)

# STS duration fallback ladder (seconds)
# If the role's MaxSessionDuration is less than what the SAML assertion
# allows, we retry with progressively shorter durations.
_DURATION_FALLBACK_LADDER = [43200, 28800, 14400, 7200, 3600, 900]

# Boto3 error code for duration exceeding the role's MaxSessionDuration
_ERR_DURATION_EXCEEDED = "ValidationError"
_ERR_DURATION_MSG_FRAGMENT = "DurationSeconds"


@dataclasses.dataclass
class AwsCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    role_arn: str
    region: Optional[str] = None

    def as_env(self) -> dict[str, str]:
        """Return a dict suitable for injecting as environment variables."""
        return {
            "AWS_ACCESS_KEY_ID": self.access_key_id,
            "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
            "AWS_SESSION_TOKEN": self.session_token,
        }

    def as_credentials_block(self) -> dict[str, str]:
        """Return a dict matching the keys written to ~/.aws/credentials."""
        return {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "aws_session_token": self.session_token,
        }


class StsClient:
    """Wraps STS.AssumeRoleWithSAML with automatic duration fallback.

    If the role's ``MaxSessionDuration`` is shorter than the duration
    derived from the SAML assertion's ``NotOnOrAfter``, boto3 raises a
    ``ValidationError``.  This client retries down the fallback ladder
    until it finds a duration the role accepts, or raises if all fail.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        boto_session: Optional["boto3.Session"] = None,
    ) -> None:
        self._region = region
        self._boto_session = boto_session or boto3.Session()

    def assume_role_with_saml(
        self,
        role: ParsedRole,
        assertion: SamlAssertion,
    ) -> AwsCredentials:
        """Call STS AssumeRoleWithSAML and return temporary credentials.

        Tries ``role.duration_seconds`` first, then retries with shorter
        durations if the role's MaxSessionDuration rejects the request.

        Args:
            role: Parsed SAML role containing ARNs, session name and expiry.
            assertion: Raw SAML assertion from the portal (base64-encoded).

        Returns:
            :class:`AwsCredentials` with STS temporary credentials.

        Raises:
            ClientError: If all duration attempts are exhausted or STS
                returns any other error.
        """
        sts = self._boto_session.client("sts", region_name=self._region)

        # Build the candidate duration list: start with what the SAML says,
        # then fall through the ladder for anything shorter.
        desired = role.duration_seconds
        candidates = [d for d in _DURATION_FALLBACK_LADDER if d <= desired]
        if not candidates:
            candidates = [900]
        # Prepend the desired value if it's not already in the ladder
        if candidates[0] != desired:
            candidates = [desired] + candidates

        last_error: Optional[ClientError] = None
        for duration in candidates:
            try:
                logger.debug(
                    "AssumeRoleWithSAML role=%s duration=%d", role.role_arn, duration
                )
                response = sts.assume_role_with_saml(
                    RoleArn=role.role_arn,
                    PrincipalArn=role.principal_arn,
                    SAMLAssertion=assertion.encoded_response,
                    DurationSeconds=duration,
                )
                creds = response["Credentials"]
                return AwsCredentials(
                    access_key_id=creds["AccessKeyId"],
                    secret_access_key=creds["SecretAccessKey"],
                    session_token=creds["SessionToken"],
                    expiration=creds["Expiration"],
                    role_arn=role.role_arn,
                    region=self._region,
                )
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                msg = exc.response["Error"]["Message"]
                if _is_duration_error(code, msg) and duration > 900:
                    logger.debug(
                        "Duration %d rejected (%s), retrying with next ladder step",
                        duration,
                        msg,
                    )
                    last_error = exc
                    continue
                raise

        # All ladder steps exhausted
        assert last_error is not None
        raise last_error


def _is_duration_error(code: str, message: str) -> bool:
    """Return True if the ClientError is a DurationSeconds-too-long error."""
    return code == _ERR_DURATION_EXCEEDED and _ERR_DURATION_MSG_FRAGMENT in message
