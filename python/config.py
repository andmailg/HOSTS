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
MAX_CONCURRENT = 5          # Сколько сайтов сканируем одновременно в API
MAX_URLS_PER_SITE = 2       # Сколько страниц берем с одного домена из urls.txt
MAX_DEPTH = 100             # Добавлено: Глобальная глубина сканирования для краулера
TARGET_SCAN = ""

# --- Настройки для Playwright обхода (Rosbalt.ru) ---
HEADLESS_MODE = True
PAGE_TIMEOUT_MS = 30000

# Паттерны для поиска служебных разделов, хабов и мусорных путей в URL (регистронезависимые)
IGNORED_PATH_PATTERNS = [
    r'/rss', 
    r'/search', 
    r'/feed', 
    r'/archive', 
    r'/tag', 
    r'/login', 
    r'/auth',
    r'/deposit',
    
    # --- НОВЫЕ СИСТЕМНЫЕ И ХАБОВЫЕ ПАТТЕРНЫ ---
    r'^/opinion/?$',              # Исключает ровно /opinion или /opinion/ (главная мнений)
    r'^/blog/personal/[^/]+/?$',  # Исключает главную страницу блога автора без статей
    r'^/go(/|$)',                 # Исключает редиректы Пикабу /go/
    r'^/articles/?$',             # Исключает общие хабы статей (например, на yuga.ru)
    r'^/articles/[^/]+/?$',       # Исключает рубрики статей первого уровня (/articles/economy)
    r'^/community/[^/]+/?$',
    r'^/book/[^/]+/?$',           # Исключает хабы каталогов CNews (например, /book/Microsoft_Office)
    r'^/currency/?$',             # Исключает главную страницу курсов валют (например, на bank.yuga.ru)
    r'^/blog/company/[^/]+/?$',   # Исключает главные страницы блогов компаний (например, /blog/company/CyberEd/)
    r'^/russia/?$',               # Исключает раздел /russia/ на interfax.ru
    r'/quiz/',                    # Исключает любые викторины /quiz/ на yuga.ru
    r'^/region/[^/]+\.html$',     # Исключает абсолютно все страницы регионов (чечня, краснодар, адыгея и др.)
    r'^/cookie/?$',               # Исключает страницу кук на interfax.ru (работает через url_parts.path)
    r'^/@[^/]+/?$',               # Обобщенное правило: исключает любые профили никнеймов (например, /@reprobank)
    r'^/pressreleases/?$',        # Исключает ровно /pressreleases или /pressreleases/ (главную ленту релизов)
    r'^/news/?$',
    
    # --- ИСКЛЮЧЕНИЕ СЕРВИСНЫХ СТРАНИЦ ---
    r'^/map\.php$',                # Строго исключает карту сайта
    r'/rules\.php$'               # Исключает rules.php в корне и в любых подпапках
]



# Предварительная компиляция для ускорения работы регулярных выражений
_COMPILED_IGNORED_PATHS = [re.compile(pat, re.IGNORECASE) for pat in IGNORED_PATH_PATTERNS]

def is_ignored_path(path: str) -> bool:
    """
    Проверяет, содержит ли переданный путь (path) служебные или мусорные разделы.
    Принимает на вход только path (например, из urlparse(url).path).
    """
    if not path:
        return False
        
    return any(pat.search(path) for pat in _COMPILED_IGNORED_PATHS)

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
