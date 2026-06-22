import json
import os
import time
from pathlib import Path
from typing import Optional

DEFAULT_CACHE_DIR = Path.home() / ".ck_creds"


class TokenCache:
    """File-backed token cache stored under ~/.ck_creds/ (or a custom dir).

    Each key maps to a JSON file.  Entries with an ``expires_at`` epoch
    timestamp in the past are treated as missing — the file is left on disk
    until explicitly cleared so callers can inspect stale data if needed.
    """

    def __init__(self, cache_dir: Path = DEFAULT_CACHE_DIR):
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace("/", "_").replace(":", "_")
        return self._dir / f"{safe}.json"

    def save(self, key: str, data: dict) -> None:
        """Persist *data* under *key*.  File is written mode 0o600."""
        path = self._path(key)
        with open(path, "w") as fh:
            json.dump(data, fh)
        os.chmod(path, 0o600)

    def load(self, key: str) -> Optional[dict]:
        """Return cached data or ``None`` if missing or expired."""
        path = self._path(key)
        if not path.exists():
            return None
        with open(path) as fh:
            data = json.load(fh)
        expires_at = data.get("expires_at", 0)
        if expires_at and time.time() > expires_at:
            return None
        return data

    def clear(self, key: str) -> None:
        """Delete the cache file for *key* if it exists."""
        path = self._path(key)
        if path.exists():
            path.unlink()

    def clear_all(self) -> None:
        """Delete every .json file in the cache directory."""
        for f in self._dir.glob("*.json"):
            f.unlink()
