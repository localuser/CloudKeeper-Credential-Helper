from __future__ import annotations

import configparser
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from cli.aws.sts_client import AwsCredentials

DEFAULT_AWS_DIR = Path.home() / ".aws"


class CredentialsWriter:
    """Safely upsert a named profile in ``~/.aws/credentials``.

    Uses ``configparser`` so only the target profile is touched — all other
    profiles are preserved verbatim.  The file is created with mode 0o600 if
    it does not exist; an existing file has its permissions set to 0o600 after
    every write.
    """

    def __init__(self, aws_dir: Path = DEFAULT_AWS_DIR) -> None:
        self._dir = aws_dir
        self._file = aws_dir / "credentials"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, creds: AwsCredentials, profile: str = "default") -> Path:
        """Write *creds* into *profile*, creating the file if necessary.

        Args:
            creds: Temporary credentials from STS.
            profile: AWS credentials profile name (e.g. ``"my-account"``).

        Returns:
            Path to the credentials file that was written.
        """
        self._dir.mkdir(parents=True, exist_ok=True)

        config = configparser.ConfigParser()
        if self._file.exists():
            config.read(self._file)

        config[profile] = creds.as_credentials_block()

        # Store expiry and role as comment-style keys so the AWS CLI ignores
        # them but humans can see when creds were issued / what role they map to.
        # configparser does not support real comments in sections, but unknown
        # keys are silently ignored by the AWS CLI, so we prefix with `#`.
        config[profile]["# expiration"] = creds.expiration.isoformat()
        config[profile]["# role_arn"] = creds.role_arn

        with self._file.open("w") as fh:
            config.write(fh)

        os.chmod(self._file, 0o600)
        return self._file

    def remove(self, profile: str) -> bool:
        """Remove *profile* from the credentials file.

        Args:
            profile: Profile name to remove.

        Returns:
            ``True`` if the profile existed and was removed, ``False`` if it
            was not present.
        """
        if not self._file.exists():
            return False

        config = configparser.ConfigParser()
        config.read(self._file)

        if not config.has_section(profile):
            return False

        config.remove_section(profile)
        with self._file.open("w") as fh:
            config.write(fh)
        os.chmod(self._file, 0o600)
        return True

    def read(self, profile: str) -> Optional[dict[str, str]]:
        """Return the key/value pairs for *profile*, or ``None`` if absent."""
        if not self._file.exists():
            return None
        config = configparser.ConfigParser()
        config.read(self._file)
        if not config.has_section(profile):
            return None
        return dict(config[profile])
