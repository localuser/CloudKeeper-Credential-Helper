import json
from cli.auth.token_cache import TokenCache


def test_roundtrip(tmp_cache_dir):
    cache = TokenCache(cache_dir=tmp_cache_dir)
    cache.save("portal", {"access_token": "abc", "expires_at": 9999999999})
    loaded = cache.load("portal")
    assert loaded["access_token"] == "abc"


def test_missing_returns_none(tmp_cache_dir):
    cache = TokenCache(cache_dir=tmp_cache_dir)
    assert cache.load("nonexistent") is None


def test_expired_returns_none(tmp_cache_dir):
    cache = TokenCache(cache_dir=tmp_cache_dir)
    cache.save("portal", {"access_token": "abc", "expires_at": 1})  # epoch past
    assert cache.load("portal") is None


def test_clear(tmp_cache_dir):
    cache = TokenCache(cache_dir=tmp_cache_dir)
    cache.save("portal", {"access_token": "abc", "expires_at": 9999999999})
    cache.clear("portal")
    assert cache.load("portal") is None


def test_cache_dir_created(tmp_path):
    new_dir = tmp_path / "new_cache"
    cache = TokenCache(cache_dir=new_dir)
    cache.save("x", {"expires_at": 9999999999})
    assert new_dir.exists()


def test_file_permissions(tmp_cache_dir):
    import stat
    cache = TokenCache(cache_dir=tmp_cache_dir)
    cache.save("portal", {"access_token": "secret", "expires_at": 9999999999})
    path = tmp_cache_dir / "portal.json"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


def test_key_sanitisation(tmp_cache_dir):
    cache = TokenCache(cache_dir=tmp_cache_dir)
    cache.save("some/key:with:colons", {"expires_at": 9999999999, "val": "x"})
    assert cache.load("some/key:with:colons")["val"] == "x"
