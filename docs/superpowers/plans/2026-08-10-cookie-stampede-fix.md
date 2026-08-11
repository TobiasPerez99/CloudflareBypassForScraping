# Cookie Stampede + 403 Poisoning Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detener el espiral de regeneración infinita de cookies de Cloudflare
serializando la generación por hostname (single-flight) y evitando que un 403 con
cookie vieja borre una cookie recién generada (compare-and-invalidate).

**Architecture:** Un `asyncio.Lock` por `cache_key` colapsa N generaciones concurrentes
en 1 (double-checked locking sobre la cache existente). Un semáforo global limita los
navegadores concurrentes. Las cookies llevan un número de `version` monótono; el retry
del mirror ante 403 solo invalida si la cookie que usó sigue siendo la vigente.

**Tech Stack:** Python 3.14, asyncio, FastAPI, Camoufox (mockeado en tests), pytest
(`asyncio_mode = auto`).

## Global Constraints

- Un solo worker / event-loop (`server.py --workers` default 1). Los locks en memoria
  son suficientes; NO usar locks entre procesos.
- El cliente AWS NO se modifica. Fix 100% server-side.
- Los requests DEBEN esperar a la cookie (sin 5xx durante la regeneración).
- El auth por `X-API-Token` queda ACTIVO. NO tocar autenticación.
- NO cambiar la firma pública de los endpoints.
- Los tests mockean Camoufox — nunca lanzan un navegador real.
- Tope de navegadores concurrentes: env `MAX_CONCURRENT_BROWSERS` (default `2`).
- Timeout de solve: env `BROWSER_SOLVE_TIMEOUT` segundos (default `120`).
- El `cf_cookie_cache.json` existente en producción debe seguir cargando (campo
  `version` opcional con default 0 en `from_dict`).

---

## File Structure

- `cf_bypasser/utils/misc.py` — **Modify.** Agrega `get_cookie_gen_lock(cache_key)`
  y `get_browser_semaphore()`. Primitivas de concurrencia por event-loop.
- `cf_bypasser/cache/cookie_cache.py` — **Modify.** Campo `version` en `CachedCookies`
  + contador monótono en `CookieCache.set`.
- `cf_bypasser/core/bypasser.py` — **Modify.** Reescribe `get_or_generate_cookies` con
  single-flight + double-check + semáforo + timeout. Extrae `_generate_cookies_once`.
  El return incluye `version`.
- `cf_bypasser/core/mirror.py` — **Modify.** Recuerda la `version` usada; compare-and-
  invalidate en el 403.
- `tests/test_concurrency.py` — **Create.** Tests unitarios de estampida, double-check,
  compare-and-invalidate, semáforo y timeout (todo mockeado).
- `scripts/cleanup_stale.sh` — **Create.** Limpieza de perfiles/procesos huérfanos
  (entregable operativo aparte).

---

### Task 1: Cookie version en el cache

**Files:**
- Modify: `cf_bypasser/cache/cookie_cache.py`
- Test: `tests/test_concurrency.py`

**Interfaces:**
- Produces:
  - `CachedCookies.version: int` (nuevo campo del dataclass).
  - `CookieCache.set(hostname, cookies, user_agent, ttl_hours=2)` sin cambio de firma,
    pero ahora asigna una `version` monótona interna y la guarda en el entry.
  - `CookieCache.get(hostname) -> Optional[CachedCookies]` devuelve el entry con
    `.version` accesible.

- [ ] **Step 1: Write the failing test**

En `tests/test_concurrency.py` (crear archivo con estos imports arriba):

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_version_is_monotonic -v`
Expected: FAIL — `CachedCookies` no acepta `version` / `AttributeError: version`.

- [ ] **Step 3: Write minimal implementation**

En `cookie_cache.py`, agregar `version` al dataclass (con default para retro-compat):

```python
@dataclass
class CachedCookies:
    hostname: str
    cookies: Dict[str, str]
    user_agent: str
    timestamp: datetime
    expires_at: datetime
    version: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'hostname': self.hostname,
            'cookies': self.cookies,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'version': self.version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CachedCookies':
        return cls(
            hostname=data['hostname'],
            cookies=data['cookies'],
            user_agent=data['user_agent'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            expires_at=datetime.fromisoformat(data['expires_at']),
            version=data.get('version', 0),
        )
```

En `CookieCache.__init__`, inicializar el contador por encima de lo cargado del disco
(agregar tras `self._load_cache()`):

```python
        self._version_counter = max(
            (c.version for c in self.cache.values()), default=0
        )
```

En `CookieCache.set`, asignar la version dentro del lock:

```python
    def set(self, hostname: str, cookies: Dict[str, str], user_agent: str, ttl_hours: int = 2):
        with self.lock:
            self._version_counter += 1
            expires_at = datetime.now() + timedelta(hours=ttl_hours)
            cached = CachedCookies(
                hostname=hostname,
                cookies=cookies,
                user_agent=user_agent,
                timestamp=datetime.now(),
                expires_at=expires_at,
                version=self._version_counter,
            )
            self.cache[hostname] = cached
            self._save_cache()
            logging.info(f"Cached cookies for {hostname}, expires at {expires_at}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_version_is_monotonic -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cf_bypasser/cache/cookie_cache.py tests/test_concurrency.py
git commit -m "feat: add monotonic version to cached cookies"
```

---

### Task 2: Primitivas de concurrencia (lock por cache_key + semáforo)

**Files:**
- Modify: `cf_bypasser/utils/misc.py`
- Test: `tests/test_concurrency.py`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `get_cookie_gen_lock(cache_key: str) -> asyncio.Lock` — mismo lock para el mismo
    `cache_key` dentro del event-loop actual; se reinicia si cambia el loop.
  - `get_browser_semaphore() -> asyncio.Semaphore` — valor `MAX_CONCURRENT_BROWSERS`
    (env, default 2), atado al event-loop actual.

- [ ] **Step 1: Write the failing test**

Agregar a `tests/test_concurrency.py`:

```python
from cf_bypasser.utils.misc import get_cookie_gen_lock, get_browser_semaphore


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_same_key_same_lock tests/test_concurrency.py::test_browser_semaphore_bound -v`
Expected: FAIL — `ImportError: cannot import name 'get_cookie_gen_lock'`.

- [ ] **Step 3: Write minimal implementation**

En `misc.py` (agregar al final, junto al `get_browser_init_lock` existente):

```python
import os

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_same_key_same_lock tests/test_concurrency.py::test_browser_semaphore_bound -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cf_bypasser/utils/misc.py tests/test_concurrency.py
git commit -m "feat: add per-key cookie lock and global browser semaphore"
```

---

### Task 3: Single-flight en get_or_generate_cookies

**Files:**
- Modify: `cf_bypasser/core/bypasser.py:269-307`
- Test: `tests/test_concurrency.py`

**Interfaces:**
- Consumes: `get_cookie_gen_lock`, `get_browser_semaphore` (Task 2); `CachedCookies.version`
  (Task 1).
- Produces:
  - `CamoufoxBypasser.get_or_generate_cookies(url, proxy=None) -> Optional[Dict]`
    devuelve `{"cookies": ..., "user_agent": ..., "version": int}` en éxito, `None` en
    fallo. **El campo `version` es nuevo** y lo consume Task 4.
  - `CamoufoxBypasser._generate_cookies_once(url, proxy) -> Optional[Dict]` — helper
    que hace setup + solve + extract + cleanup para UN intento (sin cache, sin lock).

- [ ] **Step 1: Write the failing test**

Agregar a `tests/test_concurrency.py`:

```python
from unittest.mock import AsyncMock, patch
from cf_bypasser.core.bypasser import CamoufoxBypasser


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_stampede_launches_one_browser -v`
Expected: FAIL — `_generate_cookies_once` no existe / `calls["n"]` == 10.

- [ ] **Step 3: Write minimal implementation**

En `bypasser.py`, actualizar el import de `misc`:

```python
from cf_bypasser.utils.misc import (
    md5_hash,
    get_browser_init_lock,
    get_cookie_gen_lock,
    get_browser_semaphore,
)
```

Agregar constante de timeout cerca del tope del archivo (tras `ADDON_PATH`):

```python
BROWSER_SOLVE_TIMEOUT = float(os.environ.get("BROWSER_SOLVE_TIMEOUT", "120"))
```

Extraer el cuerpo de generación en un helper y reescribir el método público
(reemplaza `bypasser.py:269-307`):

```python
    async def _generate_cookies_once(self, url: str, proxy: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """One browser attempt: setup, solve, extract, cleanup. No cache, no lock."""
        camoufox = None
        browser = None
        context = None
        page = None
        try:
            camoufox, browser, context, page = await self.setup_browser(proxy)
            if await self.solve_cloudflare_challenge(url, page):
                return await self.get_cookies_and_user_agent(context, page)
            return None
        except Exception as e:
            self.log_message(f"Error in _generate_cookies_once: {e}")
            return None
        finally:
            await self.cleanup_browser(camoufox, browser, context, page)

    async def get_or_generate_cookies(self, url: str, proxy: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get cached cookies or generate new ones (single-flight per cache_key)."""
        hostname = urlparse(url).netloc
        cache_key = md5_hash(hostname + (proxy or ""))

        # Fast path: cache hit without taking the lock.
        cached = self.cookie_cache.get(cache_key)
        if cached:
            return {
                "cookies": cached.cookies,
                "user_agent": cached.user_agent,
                "version": cached.version,
            }

        self.log_message(f"No cached cookies for {cache_key}, waiting on single-flight lock...")
        async with get_cookie_gen_lock(cache_key):
            # Double-check: another request may have generated while we waited.
            cached = self.cookie_cache.get(cache_key)
            if cached:
                self.log_message(f"Cookie for {cache_key} generated by another request; reusing")
                return {
                    "cookies": cached.cookies,
                    "user_agent": cached.user_agent,
                    "version": cached.version,
                }

            self.log_message(f"Generating new cookies for {cache_key}...")
            try:
                async with get_browser_semaphore():
                    data = await asyncio.wait_for(
                        self._generate_cookies_once(url, proxy),
                        timeout=BROWSER_SOLVE_TIMEOUT,
                    )
            except asyncio.TimeoutError:
                self.log_message(f"Cookie generation timed out after {BROWSER_SOLVE_TIMEOUT}s for {cache_key}")
                return None

            if data:
                self.cookie_cache.set(cache_key, data["cookies"], data["user_agent"])
                stored = self.cookie_cache.get(cache_key)
                return {
                    "cookies": data["cookies"],
                    "user_agent": data["user_agent"],
                    "version": stored.version if stored else 0,
                }
            return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_stampede_launches_one_browser -v`
Expected: PASS

- [ ] **Step 5: Add double-check + timeout tests**

Agregar a `tests/test_concurrency.py`:

```python
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
```

- [ ] **Step 6: Run the new tests**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py -v`
Expected: PASS (todos)

- [ ] **Step 7: Commit**

```bash
git add cf_bypasser/core/bypasser.py tests/test_concurrency.py
git commit -m "feat: single-flight cookie generation with double-check and timeout"
```

---

### Task 4: Compare-and-invalidate en el 403 del mirror

**Files:**
- Modify: `cf_bypasser/core/mirror.py:131-196`
- Test: `tests/test_concurrency.py`

**Interfaces:**
- Consumes: `get_or_generate_cookies(...)` que ahora devuelve `version` (Task 3);
  `CookieCache.get(...).version` (Task 1).
- Produces: comportamiento del retry-on-403 corregido; sin cambio de firma pública.

- [ ] **Step 1: Write the failing test**

Agregar a `tests/test_concurrency.py`. Testeamos la política de invalidación de forma
aislada replicando la decisión, para no levantar curl_cffi:

```python
from cf_bypasser.core.mirror import RequestMirror
from cf_bypasser.core.bypasser import CamoufoxBypasser


def test_should_invalidate_on_403_only_when_version_unchanged(tmp_path):
    bypasser = CamoufoxBypasser(cache_file=str(tmp_path / "c.json"))
    mirror = RequestMirror(bypasser)

    bypasser.cookie_cache.set("k", {"cf_clearance": "v2"}, "UA")  # version = 1
    current_version = bypasser.cookie_cache.get("k").version

    # Request had used the current cookie -> genuinely burned -> invalidate.
    assert mirror._should_invalidate_after_403("k", used_version=current_version) is True

    # Request had used an OLDER cookie; a newer one exists -> do NOT invalidate.
    assert mirror._should_invalidate_after_403("k", used_version=current_version - 1) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_should_invalidate_on_403_only_when_version_unchanged -v`
Expected: FAIL — `_should_invalidate_after_403` no existe.

- [ ] **Step 3: Write minimal implementation**

En `mirror.py`, agregar el helper de decisión a `RequestMirror`:

```python
    def _should_invalidate_after_403(self, cache_key: str, used_version: int) -> bool:
        """Only invalidate if the cookie we used is still the current one.

        If a newer cookie already exists, another request regenerated it while
        our request was in flight — invalidating would poison the fresh cookie.
        """
        current = self.bypasser.cookie_cache.get(cache_key)
        if current is None:
            return False  # nothing to invalidate; retry will regenerate anyway
        return current.version <= used_version
```

Guardar la `version` usada al obtener las cookies (reemplaza `mirror.py:131-134`):

```python
                cf_data = await self.bypasser.get_or_generate_cookies(target_url, proxy)

                if not cf_data:
                    raise Exception("Failed to get Cloudflare clearance cookies")

                used_version = cf_data.get("version", 0)
```

Reemplazar el bloque del 403 (`mirror.py:185-196`):

```python
                # Check if we got a 403 Forbidden response
                if status_code == 403 and attempt < max_retries:
                    parsed_hostname = urlparse(target_url).netloc
                    cache_key = md5_hash(parsed_hostname + (proxy or ""))
                    if self._should_invalidate_after_403(cache_key, used_version):
                        logging.warning(
                            f"Got 403 from {hostname}; cookie v{used_version} still current, invalidating and retrying..."
                        )
                        self.bypasser.cookie_cache.invalidate(cache_key)
                    else:
                        logging.warning(
                            f"Got 403 from {hostname}; a newer cookie exists, retrying without invalidating..."
                        )
                    await asyncio.sleep(.5)
                    continue
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_should_invalidate_on_403_only_when_version_unchanged -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cf_bypasser/core/mirror.py tests/test_concurrency.py
git commit -m "fix: compare-and-invalidate on 403 to stop cookie poisoning loop"
```

---

### Task 5: Semáforo respeta el tope con hostnames distintos

**Files:**
- Test: `tests/test_concurrency.py`

**Interfaces:**
- Consumes: todo lo anterior.
- Produces: cobertura de que nunca hay > MAX_CONCURRENT_BROWSERS setups simultáneos.

- [ ] **Step 1: Write the failing/covering test**

Agregar a `tests/test_concurrency.py`:

```python
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
```

- [ ] **Step 2: Run test**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py::test_semaphore_caps_concurrent_browsers -v`
Expected: PASS (si falla, revisar que `get_browser_semaphore` lee la env en cada llamada).

- [ ] **Step 3: Run the full concurrency suite**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py -v`
Expected: PASS (todos)

- [ ] **Step 4: Commit**

```bash
git add tests/test_concurrency.py
git commit -m "test: verify global browser semaphore caps concurrency"
```

---

### Task 6: Script de limpieza operativa

**Files:**
- Create: `scripts/cleanup_stale.sh`

**Interfaces:**
- Consumes: nada (script de shell independiente; no importa código Python).
- Produces: script ejecutable para correr a mano o por cron.

- [ ] **Step 1: Write the script**

Crear `scripts/cleanup_stale.sh`:

```bash
#!/bin/bash
# Limpieza de perfiles y navegadores Camoufox huérfanos dejados por solves abortados.
# Uso: ./scripts/cleanup_stale.sh [horas]   (default: 2)
# Pensado para correr DENTRO del contenedor cloudflare-bypass, o adaptando las rutas.
set -euo pipefail

MAX_AGE_HOURS="${1:-2}"
PROFILE_GLOB="/tmp/playwright_firefoxdev_profile-*"

echo "[cleanup] Borrando perfiles > ${MAX_AGE_HOURS}h en ${PROFILE_GLOB}"
find /tmp -maxdepth 1 -name 'playwright_firefoxdev_profile-*' -type d \
    -mmin +$((MAX_AGE_HOURS * 60)) -print -exec rm -rf {} + 2>/dev/null || true

echo "[cleanup] Matando procesos camoufox/node driver con más de ${MAX_AGE_HOURS}h de vida"
# etimes = tiempo de vida en segundos; matar los que superan el umbral.
THRESHOLD=$((MAX_AGE_HOURS * 3600))
ps -eo pid,etimes,comm | awk -v t="$THRESHOLD" \
    '$3 ~ /camoufox|node/ && $2 > t { print $1 }' \
    | while read -r pid; do
        echo "[cleanup] kill -TERM $pid"
        kill -TERM "$pid" 2>/dev/null || true
    done

echo "[cleanup] Listo."
```

- [ ] **Step 2: Make it executable and smoke-test the syntax**

Run: `bash -n scripts/cleanup_stale.sh && echo "syntax ok"`
Expected: `syntax ok`

- [ ] **Step 3: Commit**

```bash
git add scripts/cleanup_stale.sh
git commit -m "chore: add stale profile/process cleanup script"
```

---

### Task 7: Verificación final y notas de deploy

**Files:**
- None (verificación).

- [ ] **Step 1: Correr toda la suite de concurrencia**

Run: `python -m pytest -c tests/pytest.ini tests/test_concurrency.py -v`
Expected: PASS en todos los tests de Tasks 1-5.

- [ ] **Step 2: Confirmar que no rompimos imports del resto**

Run: `python -c "import cf_bypasser.core.bypasser, cf_bypasser.core.mirror, cf_bypasser.cache.cookie_cache, cf_bypasser.utils.misc; print('imports ok')"`
Expected: `imports ok`

- [ ] **Step 3: Generar el diff para entregar**

Run: `git log --oneline -8 && git diff --stat db084e9..HEAD -- cf_bypasser tests scripts`
Expected: muestra los archivos tocados; revisar que sean solo los 6 previstos.

- [ ] **Step 4: Instrucciones de deploy (para el usuario)**

El usuario despliega manualmente. Notas a entregar:

```
En el VPS (/home/debian/CloudflareBypassForScraping):
  1. git pull   (o copiar los 5 archivos de cf_bypasser/ + tests/ + scripts/)
  2. docker compose up -d --build
  3. (opcional) agregar al .env:
       MAX_CONCURRENT_BROWSERS=2
       BROWSER_SOLVE_TIMEOUT=120
  4. Verificar: docker logs -f cloudflare-bypass
     - Al expirar el TTL debe verse "waiting on single-flight lock" y UNA sola
       generación, no un enjambre.

Nota: el VPS está 1 commit atrás del repo (9670959, que comenta el auth). Ese
commit NO se aplica: el auth por X-API-Token queda activo a propósito.
```

- [ ] **Step 5: Commit final (si hubo ajustes)**

```bash
git add -A && git commit -m "docs: deploy notes for cookie stampede fix" || echo "nothing to commit"
```

---

## Self-Review

**Spec coverage:**
- Single-flight + double-check → Task 3. ✓
- Semáforo global → Tasks 2 y 5. ✓
- Versión de cookie → Task 1. ✓
- Compare-and-invalidate en 403 → Task 4. ✓
- Timeout del solve → Task 3 (steps 5-6). ✓
- Retro-compat del cache en disco → Task 1 (`from_dict` default 0). ✓
- Script de limpieza → Task 6. ✓
- Auth intacto / cliente intacto / deploy manual → Task 7 + Global Constraints. ✓

**Placeholder scan:** sin TBD/TODO; todos los steps de código tienen bloque real. ✓

**Type consistency:** `get_or_generate_cookies` devuelve `{"cookies","user_agent","version"}`
en Tasks 3 y 4; `_generate_cookies_once` devuelve `{"cookies","user_agent"}` (sin version,
la version la asigna el cache) consistente en Tasks 3 y 5; `_should_invalidate_after_403(cache_key, used_version)`
igual en Task 4. `CachedCookies.version` usado en Tasks 1, 3, 4. ✓
