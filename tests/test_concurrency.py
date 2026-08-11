import asyncio
import pytest
from unittest.mock import patch
from cf_bypasser.cache.cookie_cache import CookieCache, CachedCookies
from cf_bypasser.utils.misc import get_cookie_gen_lock, get_browser_semaphore
from cf_bypasser.core.bypasser import CamoufoxBypasser
from cf_bypasser.core.mirror import RequestMirror


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


@pytest.mark.asyncio
async def test_stampede_launches_one_browser(tmp_path):
    bypasser = CamoufoxBypasser(cache_file=str(tmp_path / "c.json"))
    calls = {"n": 0}

    async def fake_generate_once(url, proxy=None):
        calls["n"] += 1
        await asyncio.sleep(0.05)  # simulate slow solve
        return {"cookies": {"cf_clearance": "x"}, "user_agent": "UA"}

    with patch.object(bypasser, "_generate_cookies_once", side_effect=fake_generate_once):
        results = await asyncio.gather(*[
            bypasser.get_or_generate_cookies("https://www.zonaprop.com.ar/x.html")
            for _ in range(10)
        ])

    assert calls["n"] == 1, f"expected 1 browser launch, got {calls['n']}"
    assert all(r["cookies"]["cf_clearance"] == "x" for r in results)
    assert all("version" in r for r in results)


@pytest.mark.asyncio
async def test_second_request_reuses_after_first(tmp_path):
    bypasser = CamoufoxBypasser(cache_file=str(tmp_path / "c.json"))
    calls = {"n": 0}

    async def fake_generate_once(url, proxy=None):
        calls["n"] += 1
        return {"cookies": {"cf_clearance": "y"}, "user_agent": "UA"}

    with patch.object(bypasser, "_generate_cookies_once", side_effect=fake_generate_once):
        await bypasser.get_or_generate_cookies("https://www.zonaprop.com.ar/a.html")
        await bypasser.get_or_generate_cookies("https://www.zonaprop.com.ar/a.html")

    assert calls["n"] == 1  # second call hit the cache


@pytest.mark.asyncio
async def test_generation_timeout_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv("BROWSER_SOLVE_TIMEOUT", "0.1")
    import importlib
    import cf_bypasser.core.bypasser as bmod
    importlib.reload(bmod)
    bypasser = bmod.CamoufoxBypasser(cache_file=str(tmp_path / "c.json"))

    async def never_returns(url, proxy=None):
        await asyncio.sleep(5)

    with patch.object(bypasser, "_generate_cookies_once", side_effect=never_returns):
        result = await bypasser.get_or_generate_cookies("https://www.zonaprop.com.ar/b.html")

    assert result is None
    importlib.reload(bmod)  # restore default timeout for other tests


def test_should_invalidate_on_403_only_when_version_unchanged(tmp_path):
    bypasser = CamoufoxBypasser(cache_file=str(tmp_path / "c.json"))
    mirror = RequestMirror(bypasser)

    bypasser.cookie_cache.set("k", {"cf_clearance": "v2"}, "UA")  # version = 1
    current_version = bypasser.cookie_cache.get("k").version

    # Request had used the current cookie -> genuinely burned -> invalidate.
    assert mirror._should_invalidate_after_403("k", used_version=current_version) is True

    # Request had used an OLDER cookie; a newer one exists -> do NOT invalidate.
    assert mirror._should_invalidate_after_403("k", used_version=current_version - 1) is False


@pytest.mark.asyncio
async def test_semaphore_caps_concurrent_browsers(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_BROWSERS", "2")
    import importlib
    import cf_bypasser.core.bypasser as bmod
    importlib.reload(bmod)

    bypasser = bmod.CamoufoxBypasser(cache_file=str(tmp_path / "c.json"))
    state = {"active": 0, "max": 0}

    async def fake_generate_once(url, proxy=None):
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.05)
        state["active"] -= 1
        return {"cookies": {"cf_clearance": "z"}, "user_agent": "UA"}

    with patch.object(bypasser, "_generate_cookies_once", side_effect=fake_generate_once):
        await asyncio.gather(*[
            bypasser.get_or_generate_cookies(f"https://host{i}.example.com/p.html")
            for i in range(5)
        ])

    assert state["max"] <= 2, f"semaphore breached: {state['max']}"
    importlib.reload(bmod)
