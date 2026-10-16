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
    r"viqeo", r"vigo\.tech", r"embeds\.rambler",

    # --- Специфичные рекламные пути Росбалта/СМИ2 ---
    r"smi2\.ru\/newdata\/",       # Конкретный подпуть редиректов СМИ2
    r"\/advert\/",                # Общие рекламные каталоги
    r"\/banners\/"                # Пути к статическим баннерам медиахолдингов
]

SYSTEM_ASSETS_PATTERNS = [
    r"\/dist\/client\/assets\/", r"\/dist\/client\/fonts\/", r"\/scrooge-client\/",
    r"\.hsmedia\.ru", r"\.viqeo\.tv", r"\.bbci\.co\.uk", r"\.bbc\.co\.uk", r"\.thetruestory\.news", r"cdn.*iportal\.ru"
]

# --- Инфраструктурные домены медиа-холдингов и веб-платформ ---
# Проверяются на частичное вхождение (substring match)
MEDIA_INFRASTRUCTURE_WHITELIST = [
    "hsmedia.ru", 
    "iportal.ru", 
    "vedomosti.ru", 
    "ampproject.org",
    "rambler.ru"      # Спасает служебную авторизацию и движок Рамблера на Газете.ru
]

# --- ГЛОБАЛЬНЫЙ БЕЛЫЙ СПИСОК ДОМЕНОВ (Точное совпадение домена или его корня) ---
STRICT_DOMAINS_WHITELIST = [
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "googleapis.com", 
    "gstatic.com", "googleusercontent.com", "google.dk", "gvt1.com",
    "youtube.com", "ytimg.com", "nflximg.net", "dmcdn.net", "rackcdn.com",
    "avatars.mds.yandex.net", "favicon.yandex.net",
    "dzen.ru", "dzeninfra.ru", "imgsmail.ru", "mail.ru",
    "vk.com", "vk.ru", "vkuser.net", "vkuserphoto.ru", "vk-portal.net", 
    "vk-cdn.net", "vk.me", "vkvd.net", "vkuseraudio.net", "vkvideo.ru",
    "ok.ru", "okcdn.ru", "odnoklassniki.ru", "mycdn.me",
    "rutube.ru", "static.rutube.ru", "rutubelist.ru", "blrutube.ru",
    "mos.ru", "sberbank.ru", "sbrf.ru", "sber.ru",
    "thetruestory.news", "rferl.org", "fastpic.org", "imageban.ru", 
    "pic4net.com", "directupload.eu", "hostingkartinok.com", "rutracker.cc", 
    "imgchest.com", "ichef.bbci.co.uk", "static.bbci.co.uk", 
    "mybbc-analytics.files.bbci.co.uk", "static.files.bbci.co.uk", "emp.bbci.co.uk",
    
    # --- Экосистема Газета.ru (Служебные домены) ---
    "gazeta.ru", "s.gazeta.ru", "img.gazeta.ru", "static.gazeta.ru",
    
    # --- Экосистема КП (Служебные домены) ---
    "kp.ru", "s1.kpcdn.net", "s2.kpcdn.net", "s3.kpcdn.net", "s4.kpcdn.net", "static.kpcdn.net",

    # --- Экосистема Росбалт ---
    "rosbalt.ru", "www.rosbalt.ru", "1mi-media.ru", "rosbalt.ru/news",
    # --- nnmclub.to ---
    "nnmstatic.win"
]

# --- ЧЕРНЫЙ СПИСОК (Паттерны блокировки рекламы и трекеров) ---
STRICT_SUBDOMAINS_BLACKLIST_PATTERNS = [
    r"^yandex\.ru$",
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
    r"^mc\.yandex\.[a-z]+$", r"^an\.yandex\.[a-z]+$", r"^ads\.yandex\.[a-z]+$", r"ad\.mail\.ru$", r"reklama\.mail\.ru$",
    r"(^|\.)scorecardresearch\.com$",
    
    # --- Специфичные тизерные сети и счетчики для Gazeta.ru и KP.ru ---
    r"(^|\.)smi2\.ru$",           # Новостной агрегатор-обменник рекламы СМИ2
    r"(^|\.)tns-counter\.ru$",    # Mediascope (бывший TNS) — трекер статистики
    r"(^|\.)mediascope\.net$",    # Главные аналитические скрипты Mediascope
    r"(^|\.)gnezdo\.ru$",         # Крупная тизерная сеть женской тематики
    r"(^|\.)relap\.io$",          # Рекомендательный виджет Relap с нативной рекламой
    r"(^|\.)rambler\.ru\/banner", # Баннерная сеть Рамблера
    r"^[a-z0-9\-]+\.adfox\.ru$",   # Динамические поддомены таргетинга AdFox

    # --- Рекламные и обменные сети экосистемы Росбалта (1МИ) ---
    r"(^|\.)24smi\.info$",        # Тизерная сеть 24СМИ (дополнительный домен)
    r"(^|\.)mirtesen\.ru$",       # Рекомендательная сеть МирТесен (часто склеен с СМИ2)
    r"(^|\.)lentainform\.ru$",    # Вариация Лентаинформ
    r"(^|\.)marketgid\.com$",     # Старая тизерная сеть / MGID
    r"(^|\.)mgid\.com$",          # Глобальный MGID, часто присутствующий на новостных ресурсах
    r"(^|\.)adverticum\.com$"     # Провайдер баннерной рекламы
]

# Кэшируем скомпилированные регулярные выражения для ускорения обработки больших списков
_COMPILED_BLACKLIST_PATTERNS = [re.compile(pat, re.IGNORECASE) for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS]

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
    
    # 1. Проверка по жесткому черному списку (скомпилированные регулярные выражения)
    if any(pat.search(domain) for pat in _COMPILED_BLACKLIST_PATTERNS):
        return True
        
    # 2. Мягкий инфраструктурный белый список (Поиск частичного совпадения подстроки)
    if any(infra_domain in domain for infra_domain in MEDIA_INFRASTRUCTURE_WHITELIST): 
        return False
        
    # 3. Глобальный белый список (Точное совпадение корня / apex-домена)
    if domain in STRICT_DOMAINS_WHITELIST or domain_apex in STRICT_DOMAINS_WHITELIST: 
        return False
        
    # 4. Защита от самоблокировки сканируемого в данный момент сайта
    if page_apex and (domain == page_apex or f"www.{domain}" == page_apex or domain_apex == page_apex): 
        return False
        
    # 5. Исключения для инфраструктуры поисковиков (кроме их систем аналитики и менеджеров тегов)
    if domain_apex and (domain_apex.startswith("google.") or domain_apex.startswith("yandex.")):
        if "tagmanager" in domain or "analytics" in domain: 
            return True
        return False
        
    # 6. Динамический скоринг по результатам анализа URLScan API
    if score is not None: 
        return score["ad_score"] > score["clean_score"]
        
    return True

def sort_domains_by_level(domains):
    """Сортирует по apex-домену, внутри — по уровню вложенности, затем алфавитно."""
    def sort_key(d):
        apex = get_apex_domain(d) or d
        depth = len(d.split(".")) - len(apex.split("."))
        return (apex, depth, d)
    return sorted(domains, key=sort_key)
