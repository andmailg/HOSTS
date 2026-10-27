import os
import urllib3
from pathlib import Path
import re
from urllib.parse import urlparse

# --- Настройки путей проекта ---
HOSTS_FILE = Path(__file__).parent.parent / "hosts_advanced.txt"
LOG_FILE = Path(__file__).parent.parent / "log.txt"
DEFAULT_URL_FILE = Path(__file__).parent.parent / "urls.txt"
TLDEXTRACT_CACHE_DIR = Path(__file__).parent / ".tldextract_cache"
TLDEXTRACT_CACHE_DIR.mkdir(exist_ok=True)

# --- Настройки URLScan API ---
URLSCAN_SCAN = "https://urlscan.io/api/v1/scan/"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
URLSCAN_RESULT = "https://urlscan.io/api/v1/result/"

# --- Системные лимиты ---
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
SCAN_TIMEOUT = 180
POLL_INTERVAL = 20
MAX_CONCURRENT = 30
MAX_URLS_PER_SITE = 2
MAX_DEPTH = 100             
TARGET_SCAN = ""

# --- Настройки для Playwright обхода (Rosbalt.ru) ---
HEADLESS_MODE = True
PAGE_TIMEOUT_MS = 30000

# Паттерны для поиска служебных разделов, хабов и мусорных путей в URL
IGNORED_PATH_PATTERNS = [
    # --- 1. ТЕХНИЧЕСКИЕ РЕСУРСЫ, ФИДЫ И ИГРЫ ---
    r'/(rss|feed|archive|xmlfeeds)',  # Фиды и архивы (включая Пикабу)
    r'/(search|tag|quiz|games?)($|/|\.)', # Поиск, теги, тесты и мини-игры (Лента/Дзен)
    
    # --- 2. АВТОРИЗАЦИЯ, ЛИЧНЫЕ КАБИНЕТЫ И ПОЧТА ---
    r'/(login|auth|deposit|registration|passport)($|/|\.)', 
    r'://(mail|profile|account)\.',   # Служебные поддомены авторизации
    
    # --- 3. СЛУЖЕБНЫЕ, ЮРИДИЧЕСКИЕ И СПРАВОЧНЫЕ СТРАНИЦЫ ---
    r'/(map|rules|contacts|cookie|mediakit|vacancies|support)($|/|\.)', 
    r'/(about|info|privacy|agreement|terms|disclaimer|copyright)($|/|\.)', 
    r'/(reklama|feedback)($|/|\.)',   # Рекламодателям и обратная связь
    r'/adv(ertising)?($|/|\.)',        # Международная реклама
    
    # --- 4. ХАБЫ, ОБЩИЕ ЛЕНТЫ И РУБРИКИ ПЕРВОГО УРОВНЯ (Отсечение хабов-пустышек) ---
    r'/(lenta|opinion|articles|community|book|currency|russia|pressreleases|news)/?$',
    r'/blog/(personal|company)/[^/]+/?$', 
    r'/region/[^/]+\.html$',               
    r'/go(/|$)',                          
    r'/@[^/]+/?$',                         # Каналы Дзена/Пикабу и авторы
    
    # --- 5. СПЕЦИФИЧНЫЕ ИСКЛЮЧЕНИЯ ИЗДАННИЙ ИЗ НАБОРА ---
    # РБК: Исключает служебные/региональные поддомены, кроме главных контентных
    r'://(?!(www|pro|quote|finance|news)(\.|$))[a-z0-9\-]+\.rbc\.ru',
    r'://www\.rbc\.ru/?$',                 # Только зеркало главной страницы РБК
    r'/short_news($|/|\.)',                # Лента коротких новостей РБК
    
    # YAHOO & BBC & EURONEWS: Технические и поисковые хабы зарубежных СМИ
    r'(search|my|style|login)\.yahoo\.com',
    r'://www\.(bbc\.com|ru\.euronews\.com)/?$', # Исключает только главные страницы-агрегаторы
    
    # СЕТЬ ШКУЛЁВ МЕДИА (Фонтанка, НГС, Е1): Отсекает общие личные кабинеты, форумы и знакомства
    r'://(passport|forum|love|dating)\.(fontanka|ngs|e1)\.ru',
    r'/(promokody|games)($|/|\.)',         # Коммерческие промокоды и игры региональных сетей
]


# Сайты, чьи ссылки считаются «своими» для сида, хотя apex-домен у них другой
# (раньше это угадывалось подстрокой: "mail.ru" in "sportmail.ru", но так же сработало бы на "notmail.ru").
RELATED_APEXES = {
    "mail.ru": ("sportmail.ru",),
}

# Если предпоследний сегмент пути — один из этих, последний сегмент считается ID статьи, а не рубрикой
# (Дзен: /a/<id>, /news/show/<id>)
ARTICLE_PARENT_SEGMENTS = {"a", "show"}

# Предварительная компиляция для ускорения работы регулярных выражений
_COMPILED_IGNORED_PATHS = [re.compile(pat, re.IGNORECASE) for pat in IGNORED_PATH_PATTERNS]

def is_ignored_path(path: str) -> bool:
    """
    Проверяет, содержит ли переданный путь (или полный URL) служебные разделы или рубрики.
    """
    if not path or path == "/":
        return False
        
    clean_path = path.strip().lower()
    if not clean_path.startswith('/') and '://' not in clean_path:
        clean_path = "/" + clean_path
    
    # 1. Проверка по жесткому списку регулярных выражений (теперь поддерживает и полные URL)
    if any(pat.search(clean_path) for pat in _COMPILED_IGNORED_PATHS):
        return True
        
    # 2. Динамический анализ рубрик
    # Отрезаем доменную часть для корректного анализа сегментов, если передан полный URL
    path_only = urlparse(clean_path).path if '://' in clean_path else clean_path
    segments = [s for s in path_only.strip("/").split("/") if s]
    
    if segments:
        last_segment = segments[-1]
        # Рубрика: путь целиком из букв (/politics, /news/economy).
        # Если где-то в пути есть цифра (дата, ID) или это /a/<id>, /show/<id> — это статья, а не хаб.
        # isalpha() уже исключает точки, поэтому проверка расширений не нужна.
        parent = segments[-2] if len(segments) > 1 else ""
        has_digit = any(ch.isdigit() for ch in path_only)
        if last_segment.isalpha() and not has_digit and parent not in ARTICLE_PARENT_SEGMENTS:
            return True
        if "currencies" in segments or "currency" in segments:
            if len(last_segment) <= 4:
                return True

    return False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_api_key():
    """Получает API ключ URLSCAN из переменных окружения или файла .env."""
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if api_key:
        return api_key
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if key.strip() == "URLSCAN_API_KEY":
                    return value.strip().strip("\"'")
    return None
