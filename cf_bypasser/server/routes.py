import logging
import re
import time
import json
from contextlib import asynccontextmanager
from typing import Optional, AsyncGenerator
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, Response, Query, Depends
from fastapi.responses import JSONResponse
from bs4 import BeautifulSoup

from cf_bypasser.core.bypasser import CamoufoxBypasser
from cf_bypasser.core.mirror import RequestMirror
from cf_bypasser.server.models import (
    CookieRequest, CookieResponse, HeadersResponse, HeadersMetadata,
    MirrorRequestHeaders, MirrorResponse, CacheStatsResponse, CacheClearResponse,
    ErrorResponse, MirrorRequestInfo, CookieGenerationInfo
)
from cf_bypasser.utils.misc import md5_hash

# Global instances
global_bypasser = None
global_mirror = None

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Lifespan context manager for FastAPI application startup and shutdown.
    """
    global global_bypasser, global_mirror
    
    # Startup
    logger.info("Starting Cloudflare Bypasser Server...")
    
    # Initialize bypasser with cache
    global_bypasser = CamoufoxBypasser(max_retries=5, log=True)
    
    # Initialize request mirror
    global_mirror = RequestMirror(global_bypasser)
    
    logger.info("Server initialization complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Cloudflare Bypasser Server...")
    
    try:
        if global_mirror:
            await global_mirror.cleanup()
        
        if global_bypasser:
            await global_bypasser.cleanup()
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
    
    logger.info("Server shutdown complete")


def is_safe_url(url: str) -> bool:
    """Check if the URL is safe (not localhost/private)."""
    try:
        parsed_url = urlparse(url)
        ip_pattern = re.compile(
            r"^(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]\.\d+\.\d+|192\.168\.\d+\.\d+)$"
        )
        hostname = parsed_url.hostname
        if (hostname and ip_pattern.match(hostname)) or parsed_url.scheme == "file":
            return False
        return True
    except:
        return False


def setup_routes(app: FastAPI):
    """Setup all routes for the FastAPI application."""
    
    @app.get("/cookies", response_model=CookieResponse, responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
    async def get_cookies(
        request: Request,
        url: Optional[str] = Query(None, description="Target URL to get cookies for"),
        retries: int = Query(5, ge=1, le=10, description="Number of retry attempts"),
        proxy: Optional[str] = Query(None, description="Proxy URL (optional)")
    ):
        """
        Legacy endpoint for backward compatibility.
        Get Cloudflare clearance cookies for a URL.
        
        If x-hostname header is present, this is treated as a mirror request
        and forwarded to the target site's /cookies path.
        """
        # Check if this is a mirror request (has x-hostname header)
        headers = dict(request.headers)
        if any(key.lower() == 'x-hostname' for key in headers.keys()):
            # This is a mirror request - forward to the catch-all handler
            return await mirror_request(request, "cookies")
        
        # For internal API, url is required
        if not url:
            raise HTTPException(
                status_code=400,
                detail="url parameter is required when x-hostname header is not present"
            )
        
        # Validate URL
        if not is_safe_url(url):
            raise HTTPException(
                status_code=400, 
                detail="Invalid or unsafe URL - localhost and private IPs are not allowed"
            )
        
        # Validate proxy format if provided
        if proxy and not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            raise HTTPException(
                status_code=400,
                detail="Proxy must start with http://, https://, socks4://, or socks5://"
            )
        
        try:
            start_time = time.time()
            logger.info(f"Getting cookies for {url} (retries: {retries}, proxy: {'yes' if proxy else 'no'})")
            
            # Use the global bypasser or create a new one
            bypasser = global_bypasser or CamoufoxBypasser(max_retries=retries, log=True)
            
            # Get cookies using the cache system
            data = await bypasser.get_or_generate_cookies(url, proxy)
            
            if not data:
                raise HTTPException(status_code=500, detail="Failed to bypass Cloudflare protection")
            
            generation_time = int((time.time() - start_time) * 1000)
            cf_cookies = [name for name in data["cookies"].keys() if name.startswith(('cf_', '__cf'))]
            
            logger.info(f"Successfully generated {len(data['cookies'])} cookies in {generation_time}ms")
            logger.info(f"Cloudflare cookies: {cf_cookies}")
            
            return CookieResponse(
                cookies=data["cookies"],
                user_agent=data["user_agent"]
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting cookies for {url}: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

    @app.get("/get-headers", response_model=HeadersResponse, responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
    async def get_headers(
        request: Request,
        url: Optional[str] = Query(None, description="Target URL to get headers for"),
        retries: int = Query(5, ge=1, le=10, description="Number of retry attempts")
    ):
        """
        Get Cloudflare clearance cookies and headers for a URL.
        Returns both the cookies and formatted HTTP headers ready to use.

        If the cookies are cached, returns them immediately.
        If not cached, generates new cookies by solving Cloudflare challenge.
        """
        # Check if this is a mirror request (has x-hostname header)
        headers = dict(request.headers)
        if any(key.lower() == 'x-hostname' for key in headers.keys()):
            raise HTTPException(
                status_code=400,
                detail="x-hostname header not supported for /get-headers endpoint. Use direct URL parameter."
            )

        # url is required
        if not url:
            raise HTTPException(
                status_code=400,
                detail="url parameter is required"
            )

        # Validate URL
        if not is_safe_url(url):
            raise HTTPException(
                status_code=400,
                detail="Invalid or unsafe URL - localhost and private IPs are not allowed"
            )

        try:
            start_time = time.time()
            logger.info(f"Getting headers for {url} (retries: {retries})")

            # Use the global bypasser or create a new one
            bypasser = global_bypasser or CamoufoxBypasser(max_retries=retries, log=True)

            # Get cookies using the cache system (no proxy)
            data = await bypasser.get_or_generate_cookies(url, proxy=None)

            if not data:
                raise HTTPException(status_code=500, detail="Failed to bypass Cloudflare protection")

            # Extract hostname and generate cache key to access metadata
            hostname = urlparse(url).netloc
            cache_key = md5_hash(hostname + "")  # Empty string for no proxy

            # Access cache metadata
            cached = bypasser.cookie_cache.cache.get(cache_key)
            if not cached:
                raise HTTPException(
                    status_code=500,
                    detail="Cache metadata not found after cookie generation"
                )

            # Format cookies as HTTP header string
            cookies_str = "; ".join([f"{name}={value}" for name, value in data["cookies"].items()])
            formatted_headers = f"Cookie: {cookies_str}\nUser-Agent: {data['user_agent']}"

            generation_time = int((time.time() - start_time) * 1000)
            cf_cookies = [name for name in data["cookies"].keys() if name.startswith(('cf_', '__cf'))]

            logger.info(f"Successfully generated {len(data['cookies'])} cookies in {generation_time}ms")
            logger.info(f"Cloudflare cookies: {cf_cookies}")
            logger.info(f"Cache expires at: {cached.expires_at.isoformat()}")

            return HeadersResponse(
                cookies=data["cookies"],
                user_agent=data["user_agent"],
                metadata=HeadersMetadata(
                    timestamp=cached.timestamp.isoformat(),
                    expires_at=cached.expires_at.isoformat()
                ),
                formatted_headers=formatted_headers
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting headers for {url}: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

    @app.get("/html", responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
    async def get_html(
        request: Request,
        url: Optional[str] = Query(None, description="Target URL to get HTML content for"),
        retries: int = Query(5, ge=1, le=10, description="Number of retry attempts"),
        proxy: Optional[str] = Query(None, description="Proxy URL (optional)"),
        bypassCookieCache: bool = Query(False, description="Force fresh cookie generation")
    ):
        """
        Get HTML content from a URL after bypassing Cloudflare protection.
        Returns the raw HTML content directly.
        
        """
        # Check if this is a mirror request (has x-hostname header)
        headers = dict(request.headers)
        if any(key.lower() == 'x-hostname' for key in headers.keys()):
            return await mirror_request(request, "html")
        
        # For internal API, url is required
        if not url:
            raise HTTPException(
                status_code=400,
                detail="url parameter is required when x-hostname header is not present"
            )
        
        # Validate URL
        if not is_safe_url(url):
            raise HTTPException(
                status_code=400, 
                detail="Invalid or unsafe URL - localhost and private IPs are not allowed"
            )
        
        # Validate proxy format if provided
        if proxy and not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            raise HTTPException(
                status_code=400,
                detail="Proxy must start with http://, https://, socks4://, or socks5://"
            )
        
        try:
            start_time = time.time()
            logger.info(f"Getting HTML content for {url} (retries: {retries}, proxy: {'yes' if proxy else 'no'})")
            
            # Use the global bypasser or create a new one
            bypasser = global_bypasser or CamoufoxBypasser(max_retries=retries, log=True)
            
            # Get HTML content using the new method
            data = await bypasser.get_or_generate_html(url, proxy, bypass_cache=bypassCookieCache)
            
            if not data:
                raise HTTPException(status_code=500, detail="Failed to bypass Cloudflare protection")
            
            generation_time = int((time.time() - start_time) * 1000)
            cf_cookies = [name for name in data["cookies"].keys() if name.startswith(('cf_', '__cf'))]
            content_length = len(data["html"])
            
            logger.info(f"Successfully generated HTML content ({content_length} chars) and {len(data['cookies'])} cookies in {generation_time}ms")
            logger.info(f"Cloudflare cookies: {cf_cookies}")
            
            # Return raw HTML content with proper headers
            return Response(
                content=data["html"],
                media_type="text/html",
                headers={
                    "x-cf-bypasser-cookies": str(len(data["cookies"])),
                    "x-cf-bypasser-user-agent": data["user_agent"],
                    "x-cf-bypasser-final-url": data["url"],
                    "x-processing-time-ms": str(generation_time)
                }
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.info(f"Error getting HTML content for {url}: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

    @app.api_route("/zonaprop/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def zonaprop_request(request: Request, path: str = ""):
        """
        ZonaProp-specific endpoint that extracts preloaded state JSON from the page.

        This endpoint:
        1. Mirrors the request through Cloudflare bypass (same as regular mirroring)
        2. Parses the HTML response with BeautifulSoup
        3. Extracts the script tag with id="preloadedData"
        4. Parses window.__PRELOADED_STATE__ JSON
        5. Returns only the JSON data

        Required Headers:
        - x-hostname: Target hostname (e.g., "zonaProp.com.ar")

        Optional Headers:
        - x-proxy: Proxy URL (http://, https://, socks4://, socks5://)
        - x-bypass-cache: Force fresh cookie generation (true/false)
        """
        try:
            start_time = time.time()

            # Extract headers
            headers = dict(request.headers)

            # Extract mirror-specific headers
            hostname = None
            proxy = None
            bypass_cache = False

            for key, value in headers.items():
                key_lower = key.lower()
                if key_lower == 'x-hostname':
                    hostname = value
                elif key_lower == 'x-proxy':
                    proxy = value
                elif key_lower == 'x-bypass-cache':
                    bypass_cache = value.lower() in ('true', '1', 'yes', 'on')

            # Validate required headers
            if not hostname:
                raise HTTPException(
                    status_code=400,
                    detail="x-hostname header is required for ZonaProp requests"
                )

            # Validate hostname
            if not is_safe_url(f"https://{hostname}"):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid or unsafe hostname - localhost and private IPs are not allowed"
                )

            # Validate proxy format if provided
            if proxy and not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                raise HTTPException(
                    status_code=400,
                    detail="x-proxy must start with http://, https://, socks4://, or socks5://"
                )

            logger.info(f"ZonaProp request: {request.method} {hostname}/{path}")
            if proxy:
                logger.info(f"Using proxy: {proxy}")
            if bypass_cache:
                logger.info("x-bypass-cache header detected - forcing fresh cookie generation")

            # Get request body
            body = await request.body()

            # Get query string
            query_string = str(request.query_params)

            # Use the global mirror or create a new one
            mirror = global_mirror or RequestMirror(global_bypasser)

            # Mirror the request to get HTML content
            status_code, response_headers, response_content = await mirror.mirror_request(
                method=request.method,
                path=f"/{path}" if path else "/",
                query_string=query_string,
                headers=headers,
                body=body
            )

            # Check if request was successful
            if status_code != 200:
                logger.warning(f"ZonaProp request returned status {status_code}")
                raise HTTPException(
                    status_code=status_code,
                    detail=f"Target server returned status {status_code}"
                )

            # Parse HTML with BeautifulSoup
            html_content = response_content.decode('utf-8', errors='ignore')
            soup = BeautifulSoup(html_content, 'lxml')

            # Find script tag with id="preloadedData"
            script_tag = soup.find('script', id="preloadedData")

            if not script_tag:
                logger.error("No script tag found with id='preloadedData'")
                raise HTTPException(
                    status_code=404,
                    detail="No script tag found with id='preloadedData' in the page"
                )

            # Extract script text
            script_text = script_tag.text.strip()

            # Find window.__PRELOADED_STATE__ marker
            preloaded_state_marker = 'window.__PRELOADED_STATE__ = '
            start_index = script_text.find(preloaded_state_marker)

            if start_index == -1:
                logger.error("window.__PRELOADED_STATE__ marker not found in script")
                raise HTTPException(
                    status_code=404,
                    detail="window.__PRELOADED_STATE__ marker not found in script tag"
                )

            # Extract JSON starting after the marker
            json_start = start_index + len(preloaded_state_marker)
            json_text = script_text[json_start:].strip()

            # Find the end of the JSON object (usually ends with }; or }\n)
            # Parse the JSON to ensure it's valid
            try:
                # Try to parse the JSON - it should be a complete object
                # Handle potential trailing semicolon or other characters
                json_text_cleaned = json_text

                # Remove trailing semicolon if present
                if json_text_cleaned.endswith(';'):
                    json_text_cleaned = json_text_cleaned[:-1]

                # Parse the JSON
                preloaded_data = json.loads(json_text_cleaned)

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON: {e}")
                # Try to find the end of the JSON object more carefully
                try:
                    # Find matching closing brace
                    brace_count = 0
                    json_end = 0
                    for i, char in enumerate(json_text):
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                json_end = i + 1
                                break

                    if json_end > 0:
                        json_text_cleaned = json_text[:json_end]
                        preloaded_data = json.loads(json_text_cleaned)
                    else:
                        raise HTTPException(
                            status_code=500,
                            detail=f"Failed to extract valid JSON: {str(e)}"
                        )
                except Exception as parse_error:
                    logger.error(f"Failed to parse JSON after cleanup: {parse_error}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"Failed to parse JSON from script tag: {str(parse_error)}"
                    )

            processing_time = int((time.time() - start_time) * 1000)
            logger.info(f"ZonaProp request completed successfully in {processing_time}ms")

            # Return the JSON data
            return JSONResponse(
                content=preloaded_data,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error processing ZonaProp request: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

    @app.post("/cache/clear", response_model=CacheClearResponse, responses={500: {"model": ErrorResponse}})
    async def clear_cache():
        """
        Clear the cookie cache and cleanup active sessions.
        This will force fresh cookie generation for all subsequent requests.
        """
        try:
            cleared_entries = 0
            
            if global_bypasser:
                cache = global_bypasser.cookie_cache.cache
                cleared_entries = len(cache)
                global_bypasser.cookie_cache.clear_all()
                logger.info(f"Cleared {cleared_entries} cache entries")
            
            if global_mirror:
                await global_mirror.cleanup()
                logger.info("Cleaned up mirror sessions")
            
            return CacheClearResponse(
                status="success",
                message=f"Cache cleared successfully - {cleared_entries} entries removed"
            )
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")

    @app.get("/cache/stats", response_model=CacheStatsResponse, responses={500: {"model": ErrorResponse}})
    async def cache_stats():
        """
        Get detailed cache statistics including active entries and hostnames.
        """
        try:
            if not global_bypasser:
                return CacheStatsResponse(
                    cached_entries=0,
                    total_hostnames=0,
                    hostnames=[]
                )
            
            cache = global_bypasser.cookie_cache.cache
            active_entries = sum(1 for cached in cache.values() if not cached.is_expired())
            expired_entries = len(cache) - active_entries
            
            logger.info(f"Cache stats: {active_entries} active, {expired_entries} expired, {len(cache)} total")
            
            return CacheStatsResponse(
                cached_entries=active_entries,
                total_hostnames=len(cache),
                hostnames=list(cache.keys())
            )
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to get cache stats: {str(e)}")

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def mirror_request(request: Request, path: str = ""):
        """
        Dynamic request mirroring endpoint
        
        Required Headers:
        - x-hostname: Target hostname (e.g., "example.com")
        
        Optional Headers:
        - x-proxy: Proxy URL (http://, https://, socks4://, socks5://)
        - x-bypass-cache: Force fresh cookie generation (true/false)
        
        Returns the mirrored response from the target with Cloudflare protection bypassed.
        """
        
        # Skip mirroring for cache management endpoints only
        if path.startswith("cache/"):
            raise HTTPException(status_code=404, detail="Not found")
        
        try:
            start_time = time.time()
            
            # Extract headers
            headers = dict(request.headers)
            
            # Extract mirror-specific headers
            hostname = None
            proxy = None
            bypass_cache = False
            
            for key, value in headers.items():
                key_lower = key.lower()
                if key_lower == 'x-hostname':
                    hostname = value
                elif key_lower == 'x-proxy':
                    proxy = value
                elif key_lower == 'x-bypass-cache':
                    bypass_cache = value.lower() in ('true', '1', 'yes', 'on')
            
            # Validate required headers
            if not hostname:
                raise HTTPException(
                    status_code=400, 
                    detail="x-hostname header is required for request mirroring"
                )
            
            # Validate hostname
            if not is_safe_url(f"https://{hostname}"):
                raise HTTPException(
                    status_code=400, 
                    detail="Invalid or unsafe hostname - localhost and private IPs are not allowed"
                )
            
            # Validate proxy format if provided
            if proxy and not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                raise HTTPException(
                    status_code=400,
                    detail="x-proxy must start with http://, https://, socks4://, or socks5://"
                )
            
            # Log request info
            request_info = MirrorRequestInfo(
                method=request.method,
                hostname=hostname,
                path=f"/{path}" if path else "/",
                proxy_used=proxy,
                cache_bypassed=bypass_cache,
                attempt_number=1,
                max_attempts=3
            )
            
            logger.info(f"Mirroring {request_info.method} request to {request_info.hostname}{request_info.path}")
            if proxy:
                logger.info(f"Using proxy: {proxy}")
            if bypass_cache:
                logger.info("x-bypass-cache header detected - forcing fresh cookie generation")
            
            # Get request body
            body = await request.body()
            
            # Get query string
            query_string = str(request.query_params)
            
            # Use the global mirror or create a new one
            mirror = global_mirror or RequestMirror(global_bypasser)
            
            # Mirror the request
            status_code, response_headers, response_content = await mirror.mirror_request(
                method=request.method,
                path=f"/{path}" if path else "/",
                query_string=query_string,
                headers=headers,
                body=body
            )
            
            processing_time = int((time.time() - start_time) * 1000)
            
            # Log response info
            logger.info(f"Request to {hostname} completed with status {status_code} in {processing_time}ms")
            logger.info(f"Response size: {len(response_content)} bytes")
            
            # Create response with proper headers
            response = Response(
                content=response_content,
                status_code=status_code,
                headers=response_headers
            )
            
            # Add custom headers for debugging
            response.headers["x-cf-bypasser-version"] = "2.0.0"
            response.headers["x-processing-time-ms"] = str(processing_time)
            response.headers["x-cache-bypassed"] = str(bypass_cache).lower()
            
            return response

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error mirroring request: {e}")
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")