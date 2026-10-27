import re
import os
import tldextract
import requests
from config import TLDEXTRACT_CACHE_DIR, RELATED_APEXES, STRICT_BAN_RATIO, STRICT_BAN_MARGIN, HOST_HINT_BONUS

# Отключаем SSL-верификацию для tldextract (корпоративный SSL-сертификат)
# Включается только явно: TLDEXTRACT_INSECURE=1 (на GitHub Actions не нужно).
if os.environ.get("TLDEXTRACT_INSECURE") == "1":
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
    "rambler.ru",      
    "files.1mi.media",
    "kpcdn.net",
    "vdmsti.ru",       
    "rbk.ru",          
    "openwebmp.com",   
    "viafoura.co",     
    "viafoura.net",
    "disqus.com",      
    "disquscdn.com",
    "spot.im",         
    "infogram.com",    
    "apester.com",
    "kinescope.io",       # Видеохостинг и стриминг Kinescope
    "kinescopecdn.net",   # Распределенная сеть доставки видео Kinescope
    "brightcove.com",     # Плееры Brightcove (BBC, Аль-Джазира и др.)
    "brightcovecdn.com",  # Статика и медиа-потоки Brightcove
    "wistia.com",         # Платформа Wistia
    "jwplayer.com",       # Независимые плееры JW Player в СМИ
    "bunny.net",          # Bunny Stream инфраструктура
    "injectoften.com",    # Служебный домен доставки плеера Connatix
    "coolbonsai.com",     # Служебное контентное зеркало Connatix
    
    # --- Экосистема Yahoo (Служебная авторизация, CDN статики и почты) ---
    "yahoo.com", "yimg.com", "yahoofinance.com", "yahoo.net",
]

# --- ГЛОБАЛЬНЫЙ БЕЛЫЙ СПИСОК ДОМЕНОВ (Точное совпадение домена или его корня) ---
STRICT_DOMAINS_WHITELIST = [
    # --- Глобальные CDN и служебная инфраструктура Google ---
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "googleapis.com", 
    "gstatic.com", "googleusercontent.com", "google.dk", "gvt1.com",
    "googletagmanager.com", "googletagservices.com", "google-analytics.com", "google.com",
    
    "wildberries.ru",       # Ритейл (ломался из-за ads-media)     
    "tinypass.com",
    
    # --- Медиа-контент и видеохостинги ---
    "youtube.com", "ytimg.com", "nflximg.net", "dmcdn.net", "rackcdn.com",
    
    # --- Экосистема Яндекс / Дзен (Служебные CDN, медиа-серверы и капча) ---
    "avatars.mds.yandex.net", "favicon.yandex.net", "yastatic.net", 
    "yastatic-net.ru", "yandexcloud.net", "dzen.ru", "dzeninfra.ru", 
    
    # --- Экосистема VK / Mail.ru / Одноклассники ---
    "mail.ru", "www.mail.ru", "imgsmail.ru", "r.mradx.net",
    "vk.com", "vk.ru", "vkuser.net", "vkuserphoto.ru", "vk-portal.net", 
    "vk-cdn.net", "vk.me", "vkvd.net", "vkuseraudio.net", "vkvideo.ru", "vk.team",
    "vkcloud-storage.ru", "ok.ru", "okcdn.ru", "odnoklassniki.ru", "mycdn.me", "top-fwz1.mail.ru",

    "securitylab.ru",

    # --- Экосистема МТС, Tele2 ---
    "mts.ru", "t2.ru",

    # --- Экосистема X (Twitter) ---
    "twimg.com",
    "twitter.com",
    "x.com",

    # --- Экосистема Yahoo ---
    "consent.cmp.oath.com",     # Сбор согласий и трекинг кук Oath/Yahoo
    
    # --- Видео и стриминг (РФ) ---
    "rutube.ru", "static.rutube.ru", "rutubelist.ru", "blrutube.ru",
    
    # --- Государственные, банковские и новостные ресурсы ---
    "mos.ru", "sberbank.ru", "sbrf.ru", "sber.ru",
    "thetruestory.news", "rferl.org", "ichef.bbci.co.uk", "static.bbci.co.uk", 
    "mybbc-analytics.files.bbci.co.uk", "static.files.bbci.co.uk", "emp.bbci.co.uk",
    "bbc.com", "www.bbc.com", "bbc.co.uk",
    "piano.io",  # Инфраструктура подписок Ведомостей/СМИ
    
    # --- Фотохостинги и файловые хранилища ---
    "fastpic.org", "imageban.ru", "pic4net.com", "directupload.eu", 
    "hostingkartinok.com", "imgchest.com",
    
    # --- Экосистема Газета.ru (Служебные домены) ---
    "gazeta.ru", "s.gazeta.ru", "img.gazeta.ru", "static.gazeta.ru",
    
    # --- Экосистема КП (Служебные домены) ---
    "kp.ru", "s1.kpcdn.net", "s2.kpcdn.net", "s3.kpcdn.net", "s4.kpcdn.net", "static.kpcdn.net",

    # --- Экосистема Росбалт ---
    "rosbalt.ru", "www.rosbalt.ru", "1mi-media.ru",
    
    # --- Торрент-трекеры и их статика ---
    "rutracker.cc", "nnmstatic.win",

    "tildacdn.com", "tildaapi.com",   # Конструктор сайтов Tilda (к нему обращаются тысячи чистых сайтов)
    "cnews.ru",                      # Издание CNews
    "ngs.ru", "fontanka.ru", "e1.ru",# Городские порталы Шкулёв Медиа (блокировать их целиком нельзя)
    "openstreetmap.org",             # Картографический сервис (используется на чистых сайтах)

    # --- Системные CDN, библиотеки и медиа-инфраструктура (Защита от FP) ---
    "jquery.com", 
    "createjs.com", 
    "userapi.com", 
    "sketchfab.com", 
    "plyr.io",
    "openfpcdn.io",
    "sentry.io",            # Сборщик ошибок UI, без него ломаются скрипты
    "browser-intake-datadoghq.com",
    "sentry-saas.rambler-co.ru",
]

# --- ЧЕРНЫЙ СПИСОК (Паттерны блокировки рекламы и трекеров) ---
STRICT_SUBDOMAINS_BLACKLIST_PATTERNS = [
    # Yahoo
    r"^analytics.*\.yahoo\.[a-z]+$",
    r"^geo\.yahoo\.com$",

    # --- Таргетированная реклама и метрики Яндекса (без блокировки yastatic/cloud) ---
    r"^(an|mc|ads|awaps|bs|context|direct|pagead)\.yandex\.[a-z]+$",
    r"(^|\.)log\.strm\.yandex\.ru$",
    
    # --- Рекламная экосистема VK / Mail.ru ---
    r"^ad\.mail\.ru$", 
    r"^reklama\.mail\.ru$",
    r"(^|\.)tracker-api\.vk-analytics\.ru$",
    r"^top(-[a-z0-9]+)?\.mail\.ru$",
    
    # --- Видео-реклама и трекеры Rutube ---
    r"(^|\.)log\.rutube\.ru$", 
    r"^ssp\.rutube\.ru$", 
    r"^goya\.rutube\.ru$",
    
    # --- Инфраструктура Дзена (Рекламные и рекомендательные блоки) ---
    #r"(^|\.)ms\.dzen\.ru$", 
    #r"(^|\.)cu\.dzen\.ru$", 

    # --- Рекламные и баннерные сети Рамблера ---
    r"^embeds\.rambler\.ru$",
    r"^ssp\.rambler\.ru$", 
    r"^ssp01\.rambler\.ru$", 
    r"^pixel\.rambler\.ru$",
    r"(^|\.)rambler\.ru/banner", 

    # --- Медиа-трекеры, пиксели и видео-реклама СМИ ---
    r"(^|\.)viqeo\.tv$", 
    r"(^|\.)vigo\.tech$",
    r"^adx\.videonow\.ru$", 
    r"^sync\.videonow\.ru$",
    r"^px\.hsmedia\.ru$", 
    r"(^|\.)adriver\.ru$",
    r"(^|\.)supercdn\.ru$",
    r"(^|\.)mrgcdn\.ru$",
    r"(^|\.)stbid\.ru$",                 # Блокирует stbid.ru со ВСЕМИ его динамическими хэш-поддоменами целиком
    r"^[a-z0-9\-]{15,}\.stbid\.ru$",     # Альтернативная точечная ловушка для длинных хвостов stbid
    
    # --- Новостные тизерные сети и агрегаторы рекламы (Росбалт / 1МИ / СМИ2) ---
    r"(^|\.)smi2\.ru$",           # Обменник СМИ2
    r"(^|\.)smi2\.net$",          # Зеркала и статика СМИ2
    r"(^|\.)24smi\.net$",         # Тизерная сеть 24СМИ
    r"(^|\.)24smi\.info$",        # Дополнительные домены 24СМИ
    r"(^|\.)mirtesen\.ru$",       # Рекомендательная сеть МирТесен
    r"(^|\.)lentainform\.ru$",    # Тизерная сеть Лентаинформ
    r"(^|\.)marketgid\.com$",     # Старая тизерная сеть / MGID
    r"(^|\.)mgid\.com$",          # Глобальный медиа-агрегатор рекламы
    r"(^|\.)adverticum\.com$",    # Провайдер баннеров
    r"(^|\.)gnezdo\.ru$",         # Тизерная сеть Гнездо
    r"(^|\.)relap\.io$",          # Нативная реклама Relap
    r"^[a-z0-9\-]+\.adfox\.ru$",   # Динамический таргетинг AdFox
    
    # --- Системы веб-аналитики и глобальные трекеры статистики ---
    r"(^|\.)tns-counter\.ru$",    # Mediascope (бывший TNS)
    r"(^|\.)mediascope\.net$",    # Аналитика Mediascope
    r"(^|\.)scorecardresearch\.com$", # Глобальный трекер Comscore
    
    # --- Зарубежные рекламные RTB-биржи и SSP-платформы ---
    r"(^|\.)hybrid\.ai$",
    r"(^|\.)ohmy\.bid$",
    r"(^|\.)adseedtech\.com$",
    r"(^|\.)appsflyersdk\.com$",
    r"(^|\.)betweendigital\.com$",
    r"(^|\.)bidderstack\.com$",
    r"(^|\.)bidvol\.com$",
    r"(^|\.)bumlam\.com$",
    r"(^|\.)buzzoola\.com$",
    r"(^|\.)viadata\.store$",
    r"(^|\.)hbrd\.io$",
    r"(^|\.)mediatoday\.ru$",
    r"(^|\.)casalemedia\.com$",
    r"(^|\.)outbrain\.com$",
    r"(^|\.)outbrainimg\.com$",
    r"(^|\.)33across\.com$",
    r"(^|\.)weborama-tech\.ru$",
    r"(^|\.)weborama\.fr$",
    r"(^|\.)skcrtxr\.com$",
    r"(^|\.)facecast\.net$",
    r"(^|\.)pubmatic\.com$",
    r"(^|\.)bestdahlia\.com$",  # Рекламная синхронизация кук Bestdahlia
    r"(^|\.)adnxs\.com$",          # Рекламная RTB-биржа AppNexus
    r"(^|\.)push4site\.com$",      # Пуш-уведомления и реклама Push4site
    r"(^|\.)adhigh\.net$",         # Рекламный пиксель и трекер AdHigh
    r"(^|\.)linkssp\.ru$",         # Рекламообменная сеть SSP
]

# --- Паттерны для детекции динамических хэш-поддоменов ---
_IS_HASH_PATTERNS = [
    re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),             # MD5 (Google safeframe и др.)
    re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-", re.IGNORECASE),  # Часть UUID
    re.compile(r"^\d{6,}$"),                                   # Чисто числовые ID от 6 знаков
]

# Кэшируем скомпилированные регулярные выражения
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

def _in_list(domain, entries):
    """Точное совпадение или поддомен записи (а не подстрока: notyahoo.com != yahoo.com)."""
    return any(domain == e or domain.endswith("." + e) for e in entries)

def is_hard_blacklisted(domain):
    """True, если домен (или его apex) явно попадает под STRICT_SUBDOMAINS_BLACKLIST_PATTERNS.
    Такие домены блокируются независимо от скоринга: у ad.mail.ru на странице mail.ru
    clean_score раздувается бонусом «тот же apex-домен», но это всё равно реклама."""
    domain = domain.lower().strip()
    apex = get_apex_domain(domain)
    return any(pat.search(domain) or (apex and pat.search(apex)) for pat in _COMPILED_BLACKLIST_PATTERNS)

def is_same_site(url, seed_apex):
    """True, если URL принадлежит сайту сида: тот же apex-домен (любой поддомен) или явно связанный из RELATED_APEXES."""
    apex = get_apex_domain(url)
    if not apex or not seed_apex:
        return False
    return apex == seed_apex or apex in RELATED_APEXES.get(seed_apex, ())

def should_block_domain(domain, page_apex=None, score=None):
    domain = domain.lower().strip()
    domain_apex = get_apex_domain(domain)
    
    # Если сам домен или его APEX (например, stbid.ru, casalemedia.com, ad.mail.ru) явно совпадает
    # с правилом из черного списка, блокируем БЕЗУСЛОВНО, не дожидаясь динамического скоринга.
    if is_hard_blacklisted(domain):
        return True
        
    # 1. ЖЕСТКИЙ ЧЕРНЫЙ СПИСОК (Регулярные выражения для текущего поддомена).
    # Проверяется ДО белого списка, иначе точечные правила (analytics.yahoo.com,
    # ssp.rambler.ru, px.hsmedia.ru ...) перекрываются белым списком корня.
    if any(pat.search(domain) for pat in _COMPILED_BLACKLIST_PATTERNS):
        return True

    # 2. ЗАЩИТА СЛУЖЕБНОЙ ИНФРАСТРУКТУРЫ (совпадение домена или его поддомена)
    if _in_list(domain, MEDIA_INFRASTRUCTURE_WHITELIST):
        return False

    # 3. ИСКЛЮЧЕНИЯ ДЛЯ ИНФРАСТРУКТУРЫ ПОИСКОВИКОВ
    if domain_apex and (domain_apex.startswith("google.") or domain_apex.startswith("yandex.")):
        if "tagmanager" in domain or "analytics" in domain: 
            return True
        return False

    # 4. ГЛОБАЛЬНЫЙ БЕЛЫЙ СПИСОК
    if domain in STRICT_DOMAINS_WHITELIST or domain_apex in STRICT_DOMAINS_WHITELIST: 
        return False

    # 5. ЗАЩИТА ОТ САМОБЛОКИРОВКИ
    if page_apex and (domain == page_apex or f"www.{domain}" == page_apex or domain_apex == page_apex): 
        return False
        
    # 6. ДИНАМИЧЕСКИЙ СКОРИНГ (С защитой от случайных срабатываний)
    if score is not None:
        ad_score = score.get("ad_score", 0)
        clean_score = score.get("clean_score", 0)
        
        # Если домен явно полезен (много системных ассетов), 
        # рекламный скор должен быть значительно выше для блокировки
        if clean_score > 0:
            return ad_score > (clean_score * 2) + 15  # Требуем уверенного перевеса
            
        # Если clean_score == 0, блокируем только при явном триггере,
        # а не из-за случайного "+6 за сторонний запрос"
        return ad_score >= 20 
        
    return True

# --- Сессионная классификация: агрегирование по страницам и группам «реплик» ---
_AD_HOST_LABEL_RE = re.compile(
    r"^(?:ads?|adx|adserver|adserv|adsrv|adtech|adnetwork|ssp|dsp|rtb|bid|bidder|prebid|pixel|px|sync|track|tracker|tracking|beacon)\d*$"
)

def host_ad_hint(domain):
    """True, если среди меток хоста (без TLD, с разбиением по дефису) есть рекламный термин: ads, ssp, dsp, rtb, px, sync ..."""
    labels = []
    for part in domain.lower().split(".")[:-1]:
        labels.extend(part.split("-"))
    return any(_AD_HOST_LABEL_RE.match(label) for label in labels)

def service_group_key(domain):
    """Ключ «одного сервиса»: реплики вида hal9000.x.net / hal90005.x.net, px2.x.pro / px4.x.pro, cs13.x.ru / cs2.x.ru
    получают общий ключ (первая метка без хвостовых цифр). У доменов 2-го уровня ключ — сам домен."""
    domain = domain.lower().strip()
    parts = domain.split(".")
    if len(parts) < 3:
        return domain
    stripped = re.sub(r"\d+$", "", parts[0]) or "#"
    return ".".join([stripped] + parts[1:])

def is_confident_ad(domain, score=None):
    """Строгий бан (идёт в hosts): явный чёрный список, нет данных скоринга (старые записи hosts),
    clean_score == 0 или ad_score > clean_score * STRICT_BAN_RATIO + STRICT_BAN_MARGIN."""
    if is_hard_blacklisted(domain):
        return True
    if not score:
        return True
    clean = score.get("clean_score", 0)
    ad = score.get("ad_score", 0)
    return clean == 0 or ad > clean * STRICT_BAN_RATIO + STRICT_BAN_MARGIN

def classify_session(domain_stats):
    """
    Единое решение по домену на основе очков со ВСЕХ страниц сессии (а не последней страницы).
    domain_stats: {domain: {"clean_score", "ad_score", "pages", "own_site"}}.
    Реплики одного сервиса (service_group_key) оцениваются по суммарным очкам группы;
    рекламный признак в имени хоста добавляет HOST_HINT_BONUS один раз на группу.
    Домен, который хотя бы раз был «своим» для сканируемой страницы (own_site), защищён от самоблокировки.
    Возвращает (ad_domains, clean_domains); в записях clean_score/ad_score — итоговые очки решения.
    """
    groups = {}
    for d in domain_stats:
        groups.setdefault(service_group_key(d), []).append(d)

    ad_domains, clean_domains = {}, {}
    for members in groups.values():
        clean = sum(domain_stats[m].get("clean_score", 0) for m in members)
        ad = sum(domain_stats[m].get("ad_score", 0) for m in members)
        own_site = any(domain_stats[m].get("own_site") for m in members)
        hint = any(host_ad_hint(m) for m in members)
        if hint:
            ad += HOST_HINT_BONUS
        for d in members:
            entry = {
                "clean_score": clean, "ad_score": ad,
                "pages": domain_stats[d].get("pages", 1),
                "group": len(members), "hint": hint,
            }
            page_apex = get_apex_domain(d) if own_site else None
            if should_block_domain(d, page_apex=page_apex, score=entry):
                ad_domains[d] = entry
            else:
                clean_domains[d] = entry
    return ad_domains, clean_domains

def _is_hash(left_segment):
    """Проверяет, является ли сегмент домена хэшем или идентификатором."""
    if any(pat.search(left_segment) for pat in _IS_HASH_PATTERNS):
        return True
    # Хэши с дефисами (буквы + цифры)
    if "-" in left_segment and len(re.findall(r"[a-z0-9]", left_segment)) > 15:
        return True
    return False

def normalize_and_detect_dynamic_domain(domain):
    """
    Детектирует динамические хэш-поддомены и нормализует их до базового узла.
    Возвращает (is_dynamic, normalized_domain).
    """
    domain = domain.lower().strip()
    parts = domain.split('.')
    if len(parts) <= 2:
        # Если домен второго уровня (apex), ничего не схлопываем, чтобы не заблокировать корень
        return False, domain
        
    left_segment = parts[0]
    apex = get_apex_domain(domain)
    
    # --- СТРАТЕГИЯ 1: Защита крупных легитимных экосистем ---
    # (где корень блокировать НЕЛЬЗЯ, но нужно изолировать рекламные фреймы)
    if apex == "googlesyndication.com":
        return True, "safeframe.googlesyndication.com"
        
    if apex == "dzen.ru":
        for sub in ["cu.dzen.ru", "ms.dzen.ru"]:
            if sub in domain:
                return True, sub
        return False, domain  # Защищаем dzen.ru от полной блокировки

    # --- СТРАТЕГИЯ 2: Безусловное схлопывание для известных рекламных сетей ---
    # Если базовый домен (например, stbid.ru или adfox.ru) уже находится в черном списке,
    # любой его глубокий поддомен автоматически признается динамическим мусором и схлопывается до корня.
    if apex:
        if any(pat.search(apex) for pat in _COMPILED_BLACKLIST_PATTERNS):
            return True, apex

    # --- СТРАТЕГИЯ 3: Строгие паттерны для динамического мусора (универсальные ловушки) ---
    is_hash = _is_hash(left_segment)

    if is_hash and apex:
        return True, apex

    return False, domain

def sort_domains_by_level(domains):
    """Сортирует по apex-домену, внутри — по уровню вложенности, затем алфавитно."""
    def sort_key(d):
        apex = get_apex_domain(d) or d
        depth = len(d.split(".")) - len(apex.split("."))
        return (apex, depth, d)
    return sorted(domains, key=sort_key)
