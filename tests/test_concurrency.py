import asyncio
import pytest
from cf_bypasser.cache.cookie_cache import CookieCache, CachedCookies
from cf_bypasser.utils.misc import get_cookie_gen_lock, get_browser_semaphore


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


@pytest.mark.asyncio
async def test_same_key_same_lock():
    a = get_cookie_gen_lock("k1")
    b = get_cookie_gen_lock("k1")
    c = get_cookie_gen_lock("k2")
    assert a is b
    assert a is not c


@pytest.mark.asyncio
async def test_browser_semaphore_bound(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_BROWSERS", "2")
    sem = get_browser_semaphore()
    assert sem._value == 2
