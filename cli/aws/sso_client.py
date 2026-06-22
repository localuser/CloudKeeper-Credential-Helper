"""AWS SSO (boto3) client for Path 2.

Uses the official boto3 SSO client to enumerate account/role pairs and
obtain STS credentials directly — no portal HTTP API, no SAML assertions.

Flow:
    1. list_accounts(accessToken)         → all accounts assigned to user
    2. list_account_roles(accessToken, accountId) → roles per account
    3. get_role_credentials(accessToken, accountId, roleName)
       → STS AccessKeyId / SecretAccessKey / SessionToken

This is the correct pattern for the OIDC access token produced by
:class:`cli.auth.oidc_auth.OidcAuthenticator`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import boto3

from cli.aws.sts_client import AwsCredentials
from datetime import datetime, timezone


@dataclass
class AccountRole:
    account_id: str
    account_name: str
    role_name: str
    email: str = ""

    @property
    def display_name(self) -> str:
        return f"{self.account_name} ({self.account_id}) → {self.role_name}"


class SsoClient:
    """Wraps boto3 SSO client for listing accounts/roles and fetching credentials."""

    def __init__(self, access_token: str, region: str) -> None:
        self._token = access_token
        self._region = region
        self._client = boto3.client("sso", region_name=region)

    def list_account_roles(self) -> list[AccountRole]:
        """Return all (account, role) pairs assigned to the authenticated user."""
        result: list[AccountRole] = []
        acct_paginator = self._client.get_paginator("list_accounts")
        for page in acct_paginator.paginate(accessToken=self._token):
            for acct in page["accountList"]:
                roles_resp = self._client.list_account_roles(
                    accessToken=self._token,
                    accountId=acct["accountId"],
                )
                for role in roles_resp["roleList"]:
                    result.append(
                        AccountRole(
                            account_id=acct["accountId"],
                            account_name=acct["accountName"],
                            role_name=role["roleName"],
                            email=acct.get("emailAddress", ""),
                        )
                    )
        return result

    def get_credentials(self, account_id: str, role_name: str) -> AwsCredentials:
        """Fetch STS credentials for a specific account+role."""
        resp = self._client.get_role_credentials(
            accessToken=self._token,
            accountId=account_id,
            roleName=role_name,
        )["roleCredentials"]

        expiry_ms = resp["expiration"]
        expiry = datetime.fromtimestamp(expiry_ms / 1000, tz=timezone.utc)

        return AwsCredentials(
            access_key_id=resp["accessKeyId"],
            secret_access_key=resp["secretAccessKey"],
            session_token=resp["sessionToken"],
            expiration=expiry,
            role_arn=f"arn:aws:iam::{account_id}:role/{role_name}",
        )
