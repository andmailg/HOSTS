import os
import urllib3
from pathlib import Path

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
MAX_URLS_PER_SITE = 10       # Сколько страниц берем с одного домена из urls.txt
MAX_DEPTH = 100             # Добавлено: Глобальная глубина сканирования для краулера
TARGET_SCAN = ""

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
