# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CloudflareBypassForScraping is a Python-based HTTP server that bypasses Cloudflare protection using Camoufox (a Firefox-based browser automation tool). It provides two main capabilities:
1. **Cookie Generation**: Generate Cloudflare clearance cookies for protected websites
2. **Request Mirroring**: Transparently proxy HTTP requests through the bypass server to Cloudflare-protected sites

The project uses a FastAPI server with an async architecture, browser automation via Camoufox, and includes intelligent cookie caching with 2-hour TTLs.

## Development Commands

### Running the Server
```bash
# Standard run (single worker)
python server.py

# With custom port/workers
python server.py --port 8005 --workers 3

# Using Docker
docker compose up -d

# Build from source
docker build -t cloudflare-bypass .
docker run -p 8005:8005 cloudflare-bypass
```

### Testing
```bash
# Install test dependencies
pip install -r tests/test-requirements.txt

# Run all tests
python -m pytest -c tests/pytest.ini tests/ -v

# Run specific test suites
python -m pytest -c tests/pytest.ini tests/test_cookies.py -v      # Cookie generation
python -m pytest -c tests/pytest.ini tests/test_html.py -v         # HTML retrieval
python -m pytest -c tests/pytest.ini tests/test_mirror.py -v       # Request mirroring
python -m pytest -c tests/pytest.ini tests/test_server.py -v       # Server endpoints

# Run with timeout (important for browser automation tests)
python -m pytest -c tests/pytest.ini tests/ -v --timeout=120
```

### Installation
```bash
# Main dependencies (Camoufox)
pip install -r requirements.txt

# Server dependencies (FastAPI, uvicorn, etc.)
pip install -r server_requirements.txt

# Legacy server (old implementation)
pip install -r old_server_requirements.txt
python old_server.py
```

## Architecture

### Core Components

**1. Server Layer** (`cf_bypasser/server/`)
- `app.py`: FastAPI app creation with CORS, lifespan management
- `routes.py`: Endpoint definitions and request routing
  - `/cookies`: Legacy cookie generation endpoint
  - `/html`: HTML content extraction endpoint
  - `/{path:path}`: Catch-all for request mirroring (supports all HTTP methods)
  - `/cache/stats`: Cache statistics
  - `/cache/clear`: Cache invalidation
- `models.py`: Pydantic models for request/response validation

**2. Core Bypass Logic** (`cf_bypasser/core/`)
- `bypasser.py`: `CamoufoxBypasser` class
  - Browser setup with randomized fingerprints (OS, screen resolution, Firefox version)
  - Cloudflare challenge detection and solving using `playwright-captcha`
  - Cookie extraction and caching
  - Supports HTTP/HTTPS/SOCKS4/SOCKS5 proxies
- `mirror.py`: `RequestMirror` class
  - Dynamic request forwarding with cookie injection
  - Uses `curl_cffi` for HTTP requests (Firefox impersonation)
  - Merges user cookies with Cloudflare cookies (user cookies take precedence)
  - Automatic retry on 403 responses with cache invalidation

**3. Caching System** (`cf_bypasser/cache/`)
- `cookie_cache.py`: Thread-safe cookie cache
  - File-based persistence (`cf_cookie_cache.json`)
  - 2-hour TTL by default
  - Automatic expiration cleanup
  - Cache key: MD5 hash of hostname + proxy

**4. Configuration** (`cf_bypasser/utils/`)
- `config.py`: Browser fingerprint generation
  - Randomized Firefox versions (140-145)
  - OS-specific configurations (Windows, macOS, Linux)
  - Screen resolutions, hardware concurrency, language settings
  - Firefox-like HTTP headers for request impersonation
- `misc.py`: Utility functions (MD5 hashing, global browser init lock)

### Request Flow

**Cookie Generation (`/cookies`):**
1. Check if `x-hostname` header present → if yes, treat as mirror request
2. Otherwise, validate URL and proxy parameters
3. Check cache for existing valid cookies
4. If cache miss: spawn Camoufox browser → navigate to URL → solve Cloudflare challenge → extract cookies
5. Cache cookies with 2-hour TTL → return cookies + user-agent

**Request Mirroring (catch-all `/{path:path}`):**
1. Extract `x-hostname`, `x-proxy`, `x-bypass-cache` headers
2. Get or generate Cloudflare cookies for hostname (with cache bypass if requested)
3. Strip mirror-specific headers, merge cookies (user cookies override CF cookies)
4. Forward request using `curl_cffi` with Firefox impersonation
5. On 403 response: invalidate cache and retry (max 2 retries)
6. Return response with original status code and headers

### Special Headers for Request Mirroring

- `x-hostname` (required): Target hostname (e.g., `example.com`)
- `x-proxy` (optional): Proxy URL in format `http://user:pass@host:port` or `socks5://host:port`
- `x-bypass-cache` (optional): Set to `true` to force fresh cookie generation

### Browser Automation Details

- Uses **Camoufox** (Firefox-based) with randomized fingerprints
- **Playwright-captcha** integration for automatic challenge solving
- Supports both Cloudflare Turnstile and Interstitial challenges
- Browser initialization is **globally locked** (browserforge is not thread-safe)
- Each request uses an isolated browser instance (created and destroyed per request)
- Headless mode with optional proxy and geoip support

### Cache Management

- Cookies cached by hostname + proxy combination (MD5 hashed)
- Default TTL: 2 hours
- Thread-safe with `threading.RLock`
- Persisted to JSON file for server restarts
- Automatic cleanup of expired entries on browser setup
- Can be manually cleared via `/cache/clear` endpoint

## Important Development Notes

### Proxy Support
- Proxy format: `scheme://[username:password@]host:port`
- Supported schemes: `http://`, `https://`, `socks4://`, `socks5://`
- Proxy is passed to both Camoufox browser context and curl_cffi session

### Cookie Merging Strategy
User-provided cookies take precedence over Cloudflare cookies, except for CF-specific cookies (`cf_clearance`, `__cf_bm`, `__cfruid`) which always override to ensure bypass works.

### Error Handling
- 403 responses trigger automatic cache invalidation and retry
- Browser cleanup is guaranteed via try/finally blocks
- Failed challenge solves return `None` rather than raising exceptions
- Global lifespan manager handles startup/shutdown cleanup

### Testing Considerations
- Tests require system dependencies (xvfb, libgtk, fonts, etc.)
- Use `--timeout=120` for browser automation tests
- Tests are organized by functionality (cookies, html, mirror, server)
- GitHub Actions runs tests daily and on push/PR

### URL Safety
The server blocks requests to:
- Localhost/127.0.0.1
- Private IP ranges (10.x, 172.16-31.x, 192.168.x)
- File:// URLs

### Backward Compatibility
- Legacy `/cookies` endpoint maintained for existing integrations
- Old server implementation preserved in `old_server.py` with separate requirements
