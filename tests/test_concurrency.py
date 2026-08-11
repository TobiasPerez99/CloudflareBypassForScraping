import asyncio
import pytest
from cf_bypasser.cache.cookie_cache import CookieCache, CachedCookies


def _fresh_cache(tmp_path):
    return CookieCache(cache_file=str(tmp_path / "cache.json"))


def test_version_is_monotonic(tmp_path):
    cache = _fresh_cache(tmp_path)
    cache.set("keyA", {"cf_clearance": "a"}, "UA-1")
    v1 = cache.get("keyA").version
    cache.set("keyA", {"cf_clearance": "b"}, "UA-2")
    v2 = cache.get("keyA").version
    cache.set("keyB", {"cf_clearance": "c"}, "UA-3")
    v3 = cache.get("keyB").version
    assert v2 > v1
    assert v3 > v2  # monótono global, no por-key
