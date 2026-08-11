# Fix de estampida de cookies y envenenamiento de cache por 403

**Fecha:** 2026-08-10
**Estado:** Aprobado (diseño)
**Autor:** Tobias + Claude

## Problema

En producción (VPS 72.62.106.93, contenedor Docker `cloudflare-bypass`, puerto 8005)
el servidor "queda buggeado" de forma recurrente. El diagnóstico sobre los logs
mostró un espiral de regeneración infinita de cookies de Cloudflare.

### Evidencia observada

- Funcionamiento normal: requests del cliente AWS (54.236.196.140) respondidos en
  ~600 ms con status 200 usando cookies cacheadas.
- Al expirar el TTL de 2 h del `cf_clearance`, el servidor entra en un estado
  degradado del que **no se recupera solo**. Un reinicio manual (visto hoy a las
  23:01) no lo cura: el cliente sigue pidiendo y la estampida se rearma al instante.
- En la hora pico se registraron ~47 generaciones de cookies (debería ser ~1),
  29 respuestas 403, 31 timeouts del solver y 42 requests llegando al intento 3/3.
- Se observaron 6 procesos Camoufox simultáneos y load average de 9–12 en una
  máquina de **2 CPU** compartida con ~20 contenedores de otros proyectos.
- Ciclo textual en logs: cookie cacheada 23:59:31 → invalidada 23:59:52 →
  regenerada → invalidada de nuevo.

### Causas raíz

1. **Estampida de navegadores.** `CamoufoxBypasser.get_or_generate_cookies`
   (`cf_bypasser/core/bypasser.py:269`) no tiene lock por hostname. Solo el arranque
   del browser está serializado (`get_browser_init_lock`). Ante N requests
   concurrentes con cache-miss, se lanzan N instancias completas de Camoufox. En una
   máquina de 2 CPU esto satura el host y hace que los challenges de Cloudflare se
   resuelvan lento o fallen por timeout (`Cloudflare checkbox not found`,
   `Cloudflare iframes not found`, `Execution context was destroyed`).

2. **Envenenamiento de cache por el retry-on-403.** `RequestMirror.mirror_request`
   (`cf_bypasser/core/mirror.py:186`) invalida la cookie compartida ante *cualquier*
   403 y reintenta. Un request que viajaba con una cookie vieja borra la cookie
   recién generada por otro request, disparando una regeneración nueva. El resultado
   es un loop de invalidación/regeneración que se autoalimenta.

## Restricciones (definidas con el usuario)

- **El cliente AWS no se modifica** en esta iteración. El fix es 100% del lado del
  servidor.
- **Los requests deben esperar a la cookie**, no recibir error. El cliente no debe
  ver 5xx durante la regeneración; solo tolera un pico de latencia (~1 min cada 2 h).
- **El deploy lo hace el usuario.** Se entrega el diff completo + instrucciones; no
  se despliega a producción desde esta sesión.
- **El auth por `X-API-Token` queda ACTIVO.** En el VPS sigue activo (el commit local
  `9670959` que lo comenta no está desplegado). Este fix no toca la autenticación.
- El servidor corre con **un solo worker** (`server.py` usa `--workers` default 1 e
  ignora el `WORKERS=3` del compose). Confirmado inspeccionando el contenedor: hay un
  único proceso `python3 server.py`. Un solo event-loop implica que un `asyncio.Lock`
  en memoria serializa correctamente a todos los requests.

## Enfoque elegido

**Opción A: Single-flight en la generación de cookies + manejo inteligente del 403.**
Ataca las dos causas de raíz con cambios acotados (3 archivos) sin cambiar la interfaz
de ningún endpoint. Se descartó la Opción B (refresco proactivo en background: más
piezas móviles de las necesarias ahora) y la Opción C (solo un semáforo global: no
arregla el envenenamiento por 403).

## Diseño

### Componentes afectados

**1. `cf_bypasser/utils/misc.py` — primitivas de concurrencia**

- `get_cookie_gen_lock(cache_key: str) -> asyncio.Lock`: devuelve un lock **por
  cache_key**, creado de forma lazy y atado al event-loop actual (mismo patrón que el
  `get_browser_init_lock` existente). Se guarda en un dict `{cache_key: asyncio.Lock}`.
  Si el event-loop cambia (reinicio), el dict se reinicia.
- `get_browser_semaphore() -> asyncio.Semaphore`: semáforo global que limita el número
  de navegadores concurrentes. Tope leído de la env var `MAX_CONCURRENT_BROWSERS`
  (default `2`). Atado al event-loop igual que arriba.
- Limpieza oportunista: al liberar un `cookie_gen_lock`, si no quedan waiters, se
  elimina la entrada del dict para no acumular locks de hostnames únicos.

**2. `cf_bypasser/cache/cookie_cache.py` — versión de cookie**

- `CachedCookies` gana un campo `version: int`.
- Un contador global incremental (o el `timestamp` en microsegundos) asigna la
  `version` en cada `set`. Cada cookie nueva tiene una `version` estrictamente mayor
  que la anterior para ese cache_key.
- `to_dict`/`from_dict` serializan `version` (con default 0 si falta, para tolerar
  el archivo de cache viejo en disco).

**3. `cf_bypasser/core/bypasser.py` — single-flight + double-checked locking**

Reescritura de `get_or_generate_cookies`:

```
async def get_or_generate_cookies(url, proxy):
    cache_key = md5(hostname + proxy)

    # 1) Fast path: cache hit sin lock
    cached = cookie_cache.get(cache_key)
    if cached:
        return {cookies, user_agent, version}

    # 2) Cache miss: adquirir el lock del cache_key (single-flight)
    async with get_cookie_gen_lock(cache_key):
        # 3) Double-check: otro request pudo haber generado mientras esperábamos
        cached = cookie_cache.get(cache_key)
        if cached:
            return {cookies, user_agent, version}   # sin lanzar navegador

        # 4) Somos el único generador: lanzar navegador bajo el semáforo global
        async with get_browser_semaphore():
            data = await asyncio.wait_for(
                self._generate_cookies(url, proxy),   # setup + solve + extract
                timeout=BROWSER_SOLVE_TIMEOUT,        # ~120s, env-configurable
            )
        if data:
            cookie_cache.set(cache_key, data.cookies, data.user_agent)  # asigna version
            return {cookies, user_agent, version}
        return None
```

- El `finally` de cleanup del navegador se mantiene dentro de `_generate_cookies`.
- `get_or_generate_cookies` ahora devuelve también la `version` usada, para que el
  mirror pueda hacer compare-and-invalidate.
- Ante N requests concurrentes con cookie expirada se lanza **exactamente 1 navegador**;
  los N-1 restantes despiertan en el paso 3, encuentran la cookie fresca y salen con 200.

**4. `cf_bypasser/core/mirror.py` — compare-and-invalidate en el 403**

`mirror_request` recuerda la `version` de la cookie que usó para armar el request.
Al recibir 403 (`mirror.py:186`), en lugar de invalidar siempre:

```
if status_code == 403 and attempt < max_retries:
    current = cookie_cache.get(cache_key)
    if current is None or current.version > used_version:
        # Otro request ya regeneró la cookie mientras la mía viajaba.
        # NO invalidar. Reintentar tomará la cookie nueva.
        pass
    else:
        # La cookie que usé sigue siendo la vigente => está quemada de verdad.
        cookie_cache.invalidate(cache_key)
    await asyncio.sleep(0.5)
    continue
```

El retry vuelve a llamar a `get_or_generate_cookies`, que por el single-flight
regenera **una sola vez** aunque lleguen muchos 403 concurrentes.

### Flujo de datos (caso estampida)

1. TTL expira; cache queda vacía para `cache_key(zonaprop)`.
2. Llegan 10 requests casi simultáneos. Los 10 hacen cache-miss (paso 1).
3. El primero adquiere `cookie_gen_lock`. Los otros 9 quedan esperando el lock.
4. El primero re-verifica cache (vacía), toma el semáforo, lanza 1 Camoufox, resuelve
   el challenge, cachea la cookie con `version = V`, libera lock y semáforo.
5. Los 9 restantes adquieren el lock uno por uno, en el double-check encuentran la
   cookie `V`, la devuelven sin lanzar navegador.
6. Los 10 requests responden 200. Se lanzó 1 navegador en vez de 10.

### Manejo de errores y bordes

- **Timeout del solve:** `asyncio.wait_for(..., timeout=BROWSER_SOLVE_TIMEOUT)`
  (default ~120 s, env `BROWSER_SOLVE_TIMEOUT`). Si expira: se libera lock y semáforo,
  el navegador se limpia en el `finally`, y ese request devuelve el error como hoy. El
  siguiente en la cola adquiere el lock y reintenta. Sin colas infinitas.
- **Excepción durante la generación:** el `async with` libera el lock siempre; el
  `finally` de cleanup del navegador se mantiene. No quedan locks tomados ni cache
  envenenada.
- **Semáforo global (tope 2):** aún con hostnames distintos, nunca más de 2 Camoufox
  simultáneos en la máquina de 2 CPU. Configurable por `MAX_CONCURRENT_BROWSERS`.
- **Fuga de locks:** el dict de locks por cache_key se limpia oportunistamente cuando
  no quedan waiters. En la práctica el tráfico es casi todo zonaprop, así que es
  despreciable de todos modos.
- **`bypass_cache`:** el flag `x-bypass-cache` sigue funcionando: invalida antes de
  llamar a `get_or_generate_cookies`, que entra al single-flight normalmente.
- **Compatibilidad del archivo de cache:** `from_dict` tolera entries sin `version`
  (default 0), así que el `cf_cookie_cache.json` existente en el contenedor no rompe.

### Higiene operativa (entregable aparte, no toca el server)

Script `scripts/cleanup_stale.sh` que:
- Borra perfiles `/tmp/playwright_firefoxdev_profile-*` más viejos que N horas.
- Mata procesos Camoufox / node driver huérfanos (sin proceso padre `server.py`).

Se entrega listo para correr a mano o por cron. **No se instala automático sin OK
del usuario.** Motivo: hoy hay 28 perfiles viejos (desde el 1/7) y procesos zombie
que contribuyen a la degradación del host.

## Testing

Todos los tests mockean Camoufox (sin navegador real), consistente con `tests/`.
Se corren con `python -m pytest -c tests/pytest.ini tests/ -v`.

1. **Estampida (test central):** cookie expirada + N=10 corutinas concurrentes sobre
   `get_or_generate_cookies`, con `setup_browser`/`_generate_cookies` mockeado y un
   contador de invocaciones. Aserción: el navegador se lanzó **exactamente 1 vez** y
   las 10 corutinas recibieron la misma cookie.
2. **Double-check:** dos corutinas; la segunda encuentra la cookie en el re-read
   dentro del lock y no lanza navegador.
3. **Compare-and-invalidate:** cookie `v2` en cache; request que usó `v1` recibe 403
   → aserción: **no** se invalida (el retry usa `v2`). Segundo caso: version igual →
   sí invalida exactamente una vez.
4. **Semáforo:** con `MAX_CONCURRENT_BROWSERS=2` y 5 hostnames distintos, nunca hay
   más de 2 setups de navegador simultáneos.
5. **Timeout:** `_generate_cookies` que nunca resuelve → `wait_for` corta a los N s,
   el request devuelve None/error y el lock queda libre para el siguiente.

## Entrega y deploy

- Se entrega el diff completo de los archivos modificados + los tests nuevos.
- Instrucciones de deploy para que las corra el usuario: `git pull` (o copiar los
  archivos) y `docker compose up -d --build` en `/home/debian/CloudflareBypassForScraping`.
- Nota: el VPS está 1 commit atrás del repo (`9670959`), pero eso solo afectaba el
  auth (que dejamos activo), así que **no impacta este fix**.

## Fuera de alcance

- Modificar el cliente AWS (usar `/zonaprop-batch`, backoff del lado del cliente).
- Refresco proactivo de cookies en background (Opción B).
- Cambiar la autenticación o alinear el commit `9670959`.
- Automatizar la limpieza de procesos/perfiles vía cron (se entrega el script, no se
  instala).
