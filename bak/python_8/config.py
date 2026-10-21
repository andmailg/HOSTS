import os
import urllib3
from pathlib import Path
import re

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
MAX_CONCURRENT = 5          
MAX_URLS_PER_SITE = 4
MAX_DEPTH = 100             
TARGET_SCAN = ""

# --- Настройки для Playwright обхода (Rosbalt.ru) ---
HEADLESS_MODE = True
PAGE_TIMEOUT_MS = 30000

# Паттерны для поиска служебных разделов, хабов и мусорных путей в URL
IGNORED_PATH_PATTERNS = [
    r'/rss', 
    r'/search', 
    r'/feed', 
    r'/archive', 
    r'/tag', 
    r'/login', 
    r'/auth',
    r'/deposit',
    r'/contacts',                  # Страницы контактов
    r'cookie',                     # Политики использования cookie
    r'mediakit',                   # Медиакиты и рекламные прайсы
    r'/lenta/?$',                  # Жесткое исключение общих лент новостей (ria.ru/lenta)
    r'xmlfeeds\.php',              # СТРОГАЯ БЛОКИРОВКА RSS-ФИДА ПИКАБУ
    # --- НОВЫЕ СИСТЕМНЫЕ И ХАБОВЫЕ ПАТТЕРНЫ ---
    r'^/opinion/?$',              
    r'^/blog/personal/[^/]+/?$',  
    r'^/go(/|$)',                 
    r'^/articles/?$',             
    r'^/articles/[^/]+/?$',       
    r'^/community/[^/]+/?$',
    r'^/book/[^/]+/?$',           
    r'^/currency/?$',             
    r'^/blog/company/[^/]+/?$',   
    r'^/russia/?$',               
    r'/quiz/',                    
    r'^/region/[^/]+\.html$',     
    r'^/cookie/?$',               
    r'^/@[^/]+/?$',               
    r'^/pressreleases/?$',        
    r'^/news/?$',
    
    # --- ИСКЛЮЧЕНИЕ СЕРВИСНЫХ СТРАНИЦ ---
    r'^/map\.php$',                
    r'/rules\.php$',
    r'search\.yahoo\.com',        # Прямое исключение поддомена Yahoo Search
]

# Предварительная компиляция для ускорения работы регулярных выражений
_COMPILED_IGNORED_PATHS = [re.compile(pat, re.IGNORECASE) for pat in IGNORED_PATH_PATTERNS]

def is_ignored_path(path: str) -> bool:
    """
    Проверяет, содержит ли переданный путь (path) служебные разделы или рубрики.
    Реализует динамический анализ структуры пути для отсечения бесконечных хабов.
    """
    if not path or path == "/":
        return False
        
    clean_path = "/" + path.strip("/").lower()
    
    # 1. Проверка по жесткому списку регулярных выражений
    if any(pat.search(clean_path) for pat in _COMPILED_IGNORED_PATHS):
        return True
        
    # 2. Динамический анализ рубрик
    segments = [s for s in path.strip("/").lower().split("/") if s]
    
    if segments:
        last_segment = segments[-1]
        
        # Фиксация проскочивших рубрик (ria.ru/politics, ria.ru/lenta и т.д.):
        # Если путь короткий (состоит всего из 1 уровня вложенности) и является чисто буквенным словом — 
        # это главная страница рубрики или глобальный хаб. Фильтруем его.
        if len(segments) == 1 and last_segment.isalpha():
            return True
            
        # Если весь путь оканчивается на буквенный сегмент без цифр и знаков дефиса (не слаг статьи)
        if last_segment.isalpha() and not last_segment.endswith(('.html', '.htm', '.php', '.phtml')):
            return True
            
        # Защита от валютных хабов Рамблера и РБК (вида /currencies/usd, /currencies/eur)
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
