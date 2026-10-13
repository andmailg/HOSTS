import re
import os
import tldextract
import requests
from config import TLDEXTRACT_CACHE_DIR

# Отключаем SSL-верификацию для tldextract (корпоративный SSL-сертификат)
_original_get = requests.get
def _patched_get(*args, **kwargs):
    kwargs['verify'] = False
    return _original_get(*args, **kwargs)
requests.get = _patched_get

_extract = tldextract.TLDExtract(cache_dir=str(TLDEXTRACT_CACHE_DIR))

# --- Паттерны для скоринговой системы ---
AD_TRACKER_PATTERNS = [
    r"\/metrika\/", r"\/hit;", r"tracker\.", r"header-bidding", r"\/ads\/system\/", 
    r"sync-loader", r"counter", r"analytics", r"gnezdo\.ru", r"fundingchoices", 
    r"\/cm\.", r"context\.js", r"telemetry", r"adriver", r"bs\.serving-sys", r"advert", r"adfox",
    r"viqeo", r"vigo\.tech", r"embeds\.rambler"
]

SYSTEM_ASSETS_PATTERNS = [
    r"\/dist\/client\/assets\/", r"\/dist\/client\/fonts\/", r"\/scrooge-client\/",
    r"\.hsmedia\.ru", r"\.viqeo\.tv", r"\.bbci\.co\.uk", r"\.bbc\.co\.uk", r"\.thetruestory\.news", r"cdn.*iportal\.ru"
]

# --- БЕЛЫЙ СПИСОК ДОМЕНОВ (Исключения из блокировки) ---
STRICT_DOMAINS_WHITELIST = [
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "googleapis.com", 
    "gstatic.com", "googleusercontent.com", "google.dk", "gvt1.com",
    "youtube.com", "ytimg.com", "nflximg.net", "dmcdn.net", "rackcdn.com",
    "yastatic.net", "avatars.mds.yandex.net", "favicon.yandex.net",
    "dzen.ru", "dzeninfra.ru", "imgsmail.ru", "mail.ru", "yandex.ru",
    "vk.com", "vk.ru", "vkuser.net", "vkuserphoto.ru", "vk-portal.net", 
    "vk-cdn.net", "vk.me", "vkvd.net", "vkuseraudio.net", "vkvideo.ru",
    "ok.ru", "okcdn.ru", "odnoklassniki.ru", "mycdn.me",
    "rutube.ru", "static.rutube.ru", "rutubelist.ru", "blrutube.ru",
    "mos.ru", "sberbank.ru", "sbrf.ru", "sber.ru",
    "thetruestory.news", "rferl.org", "fastpic.org", "imageban.ru", 
    "pic4net.com", "directupload.eu", "hostingkartinok.com", "rutracker.cc", 
    "imgchest.com", "ichef.bbci.co.uk", "static.bbci.co.uk", 
    "mybbc-analytics.files.bbci.co.uk", "static.files.bbci.co.uk", "emp.bbci.co.uk"
]

# --- ЧЕРНЫЙ СПИСОК (Паттерны блокировки рекламы и трекеров) ---
STRICT_SUBDOMAINS_BLACKLIST_PATTERNS = [
    r"(^|\.)log\.strm\.yandex\.ru$", r"(^|\.)viqeo\.tv$", r"(^|\.)vigo\.tech$",
    r"(^|\.)log\.rutube\.ru$", r"^ssp\.rutube\.ru$", r"^goya\.rutube\.ru$",
    r"^adx\.videonow\.ru$", r"^px\.hsmedia\.ru$", r"(^|\.)adriver\.ru$",
    r"\.ms\.dzen\.ru$", r"\.cu\.dzen\.ru$", r"(^|\.)supercdn\.ru$",
    r"(^|\.)mrgcdn\.ru$", r"(^|\.)24smi\.net$", r"(^|\.)hybrid\.ai$",
    r"(^|\.)ohmy\.bid$", r"(^|\.)adseedtech\.com$", r"(^|\.)appsflyersdk\.com$",
    r"(^|\.)betweendigital\.com$", r"(^|\.)bidderstack\.com$", r"(^|\.)bidvol\.com$",
    r"(^|\.)bumlam\.com$", r"(^|\.)buzzoola\.com$", r"(^|\.)viadata\.store$",
    r"(^|\.)hbrd\.io$", r"(^|\.)mediatoday\.ru$", r"^embeds\.rambler\.ru$",
    r"^ssp\.rambler\.ru$", r"^ssp01\.rambler\.ru$", r"^pixel\.rambler\.ru$",
    r"^mc\.yandex\.[a-z]+$", r"^an\.yandex\.[a-z]+$", r"^ads\.yandex\.[a-z]+$", r"ad\.mail\.ru$", r"reklama\.mail\.ru$"
]

def _extract_domain_regex(url):
    match = re.search(r"https?://([^/:]+)", url)
    return match.group(1).lower() if match else None

def get_apex_domain(url):
    if not url or url.startswith("data:"):
        return None
    try:
        extracted = _extract(url if url.startswith(("http://", "https://")) else f"http://{url}")
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    except Exception:
        pass
    domain = _extract_domain_regex(url)
    return domain if domain else None

def should_block_domain(domain, page_apex=None, score=None):
    domain = domain.lower().strip()
    domain_apex = get_apex_domain(domain)
    
    is_strict_ad = any(re.search(pat, domain, re.IGNORECASE) for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS)
    if is_strict_ad: return True
    if any(x in domain for x in ["hsmedia.ru", "iportal.ru", "vedomosti.ru", "ampproject.org"]): return False
    if domain in STRICT_DOMAINS_WHITELIST or domain_apex in STRICT_DOMAINS_WHITELIST: return False
    if page_apex and (domain == page_apex or f"www.{domain}" == page_apex or domain_apex == page_apex): return False
    if domain_apex and (domain_apex.startswith("google.") or domain_apex.startswith("yandex.")):
        if "tagmanager" in domain or "analytics" in domain: return True
        return False
    if score is not None: return score["ad_score"] > score["clean_score"]
    return True


def sort_domains_by_level(domains):
    """Сортирует домены по уровню вложенности: сначала домены верхнего уровня, потом поддомены."""
    return sorted(domains, key=lambda d: len(d.split(".")))
