"""Tests for cli.aws.credentials_writer."""
from __future__ import annotations

import configparser
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cli.aws.credentials_writer import CredentialsWriter
from cli.aws.sts_client import AwsCredentials

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

EXPIRY = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def make_creds(**overrides) -> AwsCredentials:
    defaults = dict(
        access_key_id="ASIAEXAMPLE123",
        secret_access_key="superSecret",
        session_token="FakeSessionToken",
        expiration=EXPIRY,
        role_arn="arn:aws:iam::123456789012:role/MyRole-SSO-Role",
        region="eu-west-1",
    )
    return AwsCredentials(**{**defaults, **overrides})


@pytest.fixture()
def aws_dir(tmp_path: Path) -> Path:
    d = tmp_path / ".aws"
    d.mkdir()
    return d


@pytest.fixture()
def writer(aws_dir: Path) -> CredentialsWriter:
    return CredentialsWriter(aws_dir=aws_dir)


# ---------------------------------------------------------------------------
# Writing new profiles
# ---------------------------------------------------------------------------


def test_writes_new_profile(writer: CredentialsWriter, aws_dir: Path) -> None:
    writer.write(make_creds(), profile="myprofile")
    content = (aws_dir / "credentials").read_text()
    assert "[myprofile]" in content
    assert "aws_access_key_id = ASIAEXAMPLE123" in content
    assert "aws_secret_access_key = superSecret" in content
    assert "aws_session_token = FakeSessionToken" in content


def test_creates_credentials_file_if_missing(writer: CredentialsWriter, aws_dir: Path) -> None:
    creds_file = aws_dir / "credentials"
    assert not creds_file.exists()
    writer.write(make_creds(), profile="new")
    assert creds_file.exists()


def test_creates_aws_dir_if_missing(tmp_path: Path) -> None:
    missing_dir = tmp_path / "nonexistent" / ".aws"
    writer = CredentialsWriter(aws_dir=missing_dir)
    writer.write(make_creds(), profile="p")
    assert (missing_dir / "credentials").exists()


# ---------------------------------------------------------------------------
# Upsert behaviour
# ---------------------------------------------------------------------------


def test_overwrites_existing_profile(writer: CredentialsWriter, aws_dir: Path) -> None:
    creds_file = aws_dir / "credentials"
    creds_file.write_text(
        "[myprofile]\naws_access_key_id = OLD\naws_secret_access_key = oldsecret\n\n"
        + "[other]\naws_access_key_id = KEEP\n"
    )
    writer.write(make_creds(access_key_id="NEW"), profile="myprofile")
    content = creds_file.read_text()
    assert "NEW" in content
    assert "OLD" not in content


def test_preserves_other_profiles(writer: CredentialsWriter, aws_dir: Path) -> None:
    creds_file = aws_dir / "credentials"
    creds_file.write_text("[production]\naws_access_key_id = PROD\n")
    writer.write(make_creds(), profile="staging")
    content = creds_file.read_text()
    assert "[production]" in content
    assert "PROD" in content
    assert "[staging]" in content


def test_multiple_profiles_coexist(writer: CredentialsWriter, aws_dir: Path) -> None:
    writer.write(make_creds(access_key_id="KEY_A"), profile="account-a")
    writer.write(make_creds(access_key_id="KEY_B"), profile="account-b")
    content = (aws_dir / "credentials").read_text()
    assert "KEY_A" in content
    assert "KEY_B" in content


# ---------------------------------------------------------------------------
# Metadata annotation
# ---------------------------------------------------------------------------


def test_expiration_annotated(writer: CredentialsWriter, aws_dir: Path) -> None:
    writer.write(make_creds(), profile="p")
    content = (aws_dir / "credentials").read_text()
    assert "2099-01-01" in content


def test_role_arn_annotated(writer: CredentialsWriter, aws_dir: Path) -> None:
    writer.write(make_creds(), profile="p")
    content = (aws_dir / "credentials").read_text()
    assert "MyRole-SSO-Role" in content


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------


def test_file_permissions_are_0o600(writer: CredentialsWriter, aws_dir: Path) -> None:
    writer.write(make_creds(), profile="p")
    mode = stat.S_IMODE((aws_dir / "credentials").stat().st_mode)
    assert mode == 0o600


def test_permissions_enforced_on_existing_file(writer: CredentialsWriter, aws_dir: Path) -> None:
    creds_file = aws_dir / "credentials"
    creds_file.write_text("[x]\nkey = val\n")
    os.chmod(creds_file, 0o644)
    writer.write(make_creds(), profile="y")
    mode = stat.S_IMODE(creds_file.stat().st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# remove()
# ---------------------------------------------------------------------------


def test_remove_existing_profile(writer: CredentialsWriter, aws_dir: Path) -> None:
    writer.write(make_creds(), profile="todelete")
    assert writer.remove("todelete") is True
    assert writer.read("todelete") is None


def test_remove_preserves_other_profiles(writer: CredentialsWriter, aws_dir: Path) -> None:
    writer.write(make_creds(access_key_id="A"), profile="keep")
    writer.write(make_creds(access_key_id="B"), profile="drop")
    writer.remove("drop")
    assert writer.read("keep") is not None
    assert writer.read("drop") is None


def test_remove_nonexistent_returns_false(writer: CredentialsWriter) -> None:
    assert writer.remove("ghost") is False


def test_remove_no_file_returns_false(writer: CredentialsWriter) -> None:
    assert writer.remove("anything") is False


# ---------------------------------------------------------------------------
# read()
# ---------------------------------------------------------------------------


def test_read_returns_none_if_no_file(writer: CredentialsWriter) -> None:
    assert writer.read("x") is None


def test_read_returns_none_if_profile_absent(writer: CredentialsWriter) -> None:
    writer.write(make_creds(), profile="a")
    assert writer.read("missing") is None


def test_read_returns_dict_for_existing_profile(writer: CredentialsWriter) -> None:
    writer.write(make_creds(access_key_id="README"), profile="readable")
    data = writer.read("readable")
    assert data is not None
    assert data["aws_access_key_id"] == "README"
