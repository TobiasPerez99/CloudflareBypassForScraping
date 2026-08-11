from hashlib import md5
from typing import Union
import asyncio
import os

def md5_hash(text: Union[str, bytes]) -> str:
    if isinstance(text, str):
        text = text.encode('utf-8')
    return md5(text).hexdigest()

# Global lock state for browser initialization
_global_lock_state = {"lock": None, "loop": None}

def get_browser_init_lock() -> asyncio.Lock:
    """Get the global browser initialization lock for the current event loop."""
    global _global_lock_state
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.Lock()

    if _global_lock_state["lock"] is None or _global_lock_state["loop"] != current_loop:
        _global_lock_state["lock"] = asyncio.Lock()
        _global_lock_state["loop"] = current_loop

    return _global_lock_state["lock"]


# Per-cache-key cookie generation locks, bound to the running event loop.
_cookie_lock_state = {"locks": {}, "loop": None}

def get_cookie_gen_lock(cache_key: str) -> asyncio.Lock:
    """Return a single-flight lock for this cache_key on the current loop."""
    global _cookie_lock_state
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.Lock()

    if _cookie_lock_state["loop"] != current_loop:
        _cookie_lock_state["locks"] = {}
        _cookie_lock_state["loop"] = current_loop

    locks = _cookie_lock_state["locks"]
    if cache_key not in locks:
        locks[cache_key] = asyncio.Lock()
    return locks[cache_key]


# Global cap on concurrent browser launches, bound to the running event loop.
_browser_sem_state = {"sem": None, "loop": None, "value": None}

def get_browser_semaphore() -> asyncio.Semaphore:
    """Return the global browser-concurrency semaphore for the current loop."""
    global _browser_sem_state
    value = int(os.environ.get("MAX_CONCURRENT_BROWSERS", "2"))
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.Semaphore(value)

    if (
        _browser_sem_state["sem"] is None
        or _browser_sem_state["loop"] != current_loop
        or _browser_sem_state["value"] != value
    ):
        _browser_sem_state["sem"] = asyncio.Semaphore(value)
        _browser_sem_state["loop"] = current_loop
        _browser_sem_state["value"] = value
    return _browser_sem_state["sem"] 