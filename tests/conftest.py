import pytest


@pytest.fixture
def tmp_cache_dir(tmp_path):
    """Isolated token cache directory per test."""
    return tmp_path / ".ck_creds"


@pytest.fixture
def tmp_aws_dir(tmp_path):
    """Isolated ~/.aws directory per test."""
    aws = tmp_path / ".aws"
    aws.mkdir()
    return aws
