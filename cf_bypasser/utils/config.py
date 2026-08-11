import os
import random
from typing import Optional, Dict, List

OPERATING_SYSTEMS = ["windows", "macos", "linux"]

SCREEN_RESOLUTIONS = [
    (1920, 1080),
    (1366, 768),
    (2560, 1440),
]

DEFAULT_LOCALE = (os.environ.get("BYPASS_LOCALE", "es-AR").strip() or "es-AR")


def _base_lang(lang: str) -> str:
    """Return the base language of a locale, e.g. 'es-AR' -> 'es'."""
    return lang.split("-", 1)[0] if "-" in lang else lang


def build_accept_language(lang: str) -> str:
    """Build an Accept-Language header value from a locale like 'es-AR'."""
    base = _base_lang(lang)
    parts = [lang]
    if base != lang:
        parts.append(f"{base};q=0.9")
    if base != "en":
        parts.append("en-US;q=0.8")
        parts.append("en;q=0.7")
    return ",".join(parts)


def build_navigator_languages(lang: str) -> List[str]:
    """Build a realistic navigator.languages list from a locale like 'es-AR'."""
    base = _base_lang(lang)
    langs = [lang]
    if base != lang:
        langs.append(base)
    if not lang.startswith("en"):
        langs.append("en-US")
    seen = set()
    return [x for x in langs if not (x in seen or seen.add(x))]


class BrowserConfig:
    """Generate random browser configurations with integrated UA generation."""
        
    @staticmethod
    def get_firefox_headers(lang: Optional[str] = None) -> Dict[str, str]:
        """Get Firefox-specific headers. Accept-Language follows the locale."""
        lang = lang or DEFAULT_LOCALE
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': build_accept_language(lang),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        }
    
    @staticmethod
    def generate_random_config(
        selected_os: Optional[str] = None,
        firefox_version: int = None,
        lang: Optional[str] = None
    ) -> Dict:
        """Generate random browser configuration based on OS."""
        lang = lang or DEFAULT_LOCALE

        if selected_os is None or selected_os not in OPERATING_SYSTEMS:
            selected_os = random.choice(OPERATING_SYSTEMS)
        
        if firefox_version is None:
            firefox_version = random.randint(140, 145) # Recent Firefox versions
        
        # Random screen resolution
        screen_width, screen_height = random.choice(SCREEN_RESOLUTIONS)
        
        # Calculate inner dimensions (subtract browser chrome)
        toolbar_height = random.randint(70, 100)
        inner_width = screen_width
        inner_height = screen_height - toolbar_height
        
        # Random history length
        history_length = random.randint(2, 8)
        
        # Random hardware cores (realistic values)
        hardware_cores = random.choice([2, 4, 6, 8, 12, 16, 20, 24])
        
        # Language configuration (realistic list derived from the locale)
        languages = build_navigator_languages(lang)

        config = {
            'window.outerHeight': screen_height,
            'window.outerWidth': screen_width,
            'window.innerHeight': inner_height,
            'window.innerWidth': inner_width,
            'window.history.length': history_length,
            'navigator.appCodeName': 'Mozilla',
            'navigator.appName': 'Netscape',
            'navigator.hardwareConcurrency': hardware_cores,
            'navigator.product': 'Gecko',
            'navigator.productSub': '20100101',
            'navigator.language': lang,
            'navigator.languages': languages,
        }
        
        # OS-specific configurations
        if selected_os == "windows":
            return BrowserConfig._configure_windows(config, firefox_version)
        elif selected_os == "macos":
            return BrowserConfig._configure_macos(config, firefox_version)
        elif selected_os == "linux":
            return BrowserConfig._configure_linux(config, firefox_version)
        
        return config
    
    @staticmethod
    def _configure_windows(config: Dict, firefox_version: int) -> Dict:
        """Configure Windows-specific browser settings."""
        win_versions = [
            "Windows NT 10.0; Win64; x64",
            "Windows NT 11.0; Win64; x64",
        ]
        win_version = random.choice(win_versions)
        
        config.update({
            'navigator.userAgent': f'Mozilla/5.0 ({win_version}; rv:{firefox_version}.0) Gecko/20100101 Firefox/{firefox_version}.0',
            'navigator.appVersion': f'5.0 ({win_version})',
            'navigator.oscpu': win_version,
            'navigator.platform': 'Win32',
            'navigator.maxTouchPoints': random.choice([0, 10]),
        })
        return config
    
    @staticmethod
    def _configure_macos(config: Dict, firefox_version: int) -> Dict:
        """Configure macOS-specific browser settings."""
        macos_versions = [
            ("13_0", "13.0"),  # Ventura
            ("14_0", "14.0"),  # Sonoma
            ("15_0", "15.0"),  # Sequoia
        ]
        mac_ver_underscore, mac_ver_dot = random.choice(macos_versions)
        
        config.update({
            'navigator.userAgent': f'Mozilla/5.0 (Macintosh; Intel Mac OS X {mac_ver_underscore}; rv:{firefox_version}.0) Gecko/20100101 Firefox/{firefox_version}.0',
            'navigator.appVersion': f'5.0 (Macintosh)',
            'navigator.oscpu': f'Intel Mac OS X {mac_ver_dot}',
            'navigator.platform': 'MacIntel',
            'navigator.maxTouchPoints': 0,
        })
        return config
    
    @staticmethod
    def _configure_linux(config: Dict, firefox_version: int) -> Dict:
        """Configure Linux-specific browser settings."""
        linux_distros = [
            "X11; Ubuntu; Linux x86_64", 
        ]
        linux_distro = random.choice(linux_distros)
        
        config.update({
            'navigator.userAgent': f'Mozilla/5.0 ({linux_distro}; rv:{firefox_version}.0) Gecko/20100101 Firefox/{firefox_version}.0',
            'navigator.appVersion': '5.0 (X11)',
            'navigator.oscpu': 'Linux x86_64',
            'navigator.platform': 'Linux x86_64',
            'navigator.maxTouchPoints': 0,
        })
        return config


# Maintain backward compatibility
def generate_random_config(selected_os: Optional[str] = None, firefox_version: int = None, lang: Optional[str] = None) -> dict:
    """Generate random browser configuration based on OS (backward compatibility function)."""
    return BrowserConfig.generate_random_config(selected_os, firefox_version, lang)