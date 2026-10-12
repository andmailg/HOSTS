import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
import aiohttp
import tldextract
import urllib3

# --- Кастомный экстрактор доменов с локальным кэшем (обход SSL-ошибок) ---
TLDEXTRACT_CACHE_DIR = Path(__file__).parent / ".tldextract_cache"
TLDEXTRACT_CACHE_DIR.mkdir(exist_ok=True)
_extract = tldextract.TLDExtract(cache_dir=str(TLDEXTRACT_CACHE_DIR))

# --- Настройки путей и лимитов ---
HOSTS_FILE = Path(__file__).parent.parent / "hosts_advanced.txt"
LOG_FILE = Path(__file__).parent / "log.txt"
DEFAULT_URL_FILE = Path(__file__).parent / "urls.txt"
URLSCAN_SCAN = "https://urlscan.io/api/v1/scan/"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
URLSCAN_RESULT = "https://urlscan.io/api/v1/result/"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
SCAN_TIMEOUT = 180
POLL_INTERVAL = 20
MAX_CONCURRENT = 10

# --- БЕЛЫЙ СПИСОК ДОМЕНОВ (Исключения из блокировки) ---
STRICT_DOMAINS_WHITELIST = [
    # Глобальные сервисы и CDN
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "googleapis.com", 
    "gstatic.com", "googleusercontent.com", "google.dk", "gvt1.com",
    "youtube.com", "ytimg.com", "nflximg.net", "dmcdn.net", "rackcdn.com",
    "cloudflareinsights.com", "openfpcdn.io",
    
    # Инфраструктура Яндекса, Дзена и Mail.ru
    "yastatic.net", "avatars.mds.yandex.net", "favicon.yandex.net",
    "dzen.ru", "dzeninfra.ru", "imgsmail.ru", "mail.ru", "yandex.ru",
    
    # Медиасерверы и CDN ВКонтакте (VK)
    "vk.com", "vk.ru", "vkuser.net", "vkuserphoto.ru", "vk-portal.net", 
    "vk-cdn.net", "vk.me", "vkvd.net", "vkuseraudio.net", "vkvideo.ru",
    
    # Медиасерверы и CDN Одноклассников (OK)
    "ok.ru", "okcdn.ru", "odnoklassniki.ru", "mycdn.me",
    
    # Медиасерверы и CDN Rutube
    "rutube.ru", "static.rutube.ru", "goya.rutube.ru", "log.rutube.ru", 
    "ssp.rutube.ru", "rutubelist.ru", "blrutube.ru",
    
    # Государственные и банковские сервисы
    "mos.ru", "sberbank.ru", "sbrf.ru", "sber.ru",
    
    # Доверенные СМИ, хостинги картинок и форумы
    "thetruestory.news", "rferl.org", "fastpic.org", "imageban.ru", 
    "pic4net.com", "directupload.eu", "hostingkartinok.com", "rutracker.cc", 
    "imgchest.com", "vigo.tech", "ichef.bbci.co.uk", "static.bbci.co.uk", 
    "mybbc-analytics.files.bbci.co.uk", "static.files.bbci.co.uk", "emp.bbci.co.uk"
]

STRICT_SUBDOMAINS_BLACKLIST_PATTERNS = [
    r"^mc\.yandex\.[a-z]+$", r"^an\.yandex\.[a-z]+$", r"^ads\.yandex\.[a-z]+$",
    r"^sdk-api\.apptracer\.[a-z]+$", r"^trace-flow\.[a-z]+$", 
    r"^tracker-api\.vk-analytics\.[a-z]+$", r"^tracker-api\.my\.com$", 
    r"^telemetry\.dzen\.[a-z]+$",
    r"\.ms\.vk\.[a-z]+$",
    r"\.ms\.dzen\.[a-z]+$",
    r"^mradx\.net$", r"\.mradx\.net$",  # Полная блокировка баннерообменника Mail.ru
    r"\.appsflyersdk\.com$",
    r"^alt-ad\.mail\.ru$",
    r"\.mediascope\.mail\.ru$",
    r"^alt-aj-https\.mail\.ru$",
    r"^ads\.vk\.ru$",
    r"^target\.vk\.ru$",
    r"^ad\.mail\.ru$",
    r"^reklama\.mail\.ru$"
]

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


def _extract_domain_regex(url):
    """Простой regex-парсинг домена как fallback."""
    match = re.search(r"https?://([^/:]+)", url)
    if match:
        return match.group(1).lower()
    return None


def get_apex_domain(url):
    """Выделяет домен верхнего уровня (apex domain), например: domain.com."""
    if not url or url.startswith("data:"):
        return None
    try:
        if not url.startswith(("http://", "https://")):
            extracted = _extract(f"http://{url}")
        else:
            extracted = _extract(url)
            
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    except Exception:
        # Fallback при ошибке SSL или сети
        pass
    # Простой regex-парсинг как запасной вариант
    domain = _extract_domain_regex(url)
    if domain:
        return domain
    return None


def read_existing_hosts(file_path):
    """Считывает домены из текущего hosts-файла."""
    existing_domains = set()
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1].strip().lower()
                    if domain:
                        existing_domains.add(domain)
    return existing_domains


def sort_domains_by_level(domain_set):
    """Сортирует домены по уровням вложенности (сначала 2-й уровень, потом 3-й...)."""
    return sorted(list(domain_set), key=lambda d: (d.count("."), d))


def should_block_domain(domain, page_apex=None, score=None):
    """ЕДИНАЯ ФУНКЦИЯ ФИЛЬТРАЦИИ И ПРИНЯТИЯ РЕШЕНИЙ ПО БЛОКИРОВКЕ."""
    domain = domain.lower().strip()
    domain_apex = get_apex_domain(domain)

    # 1. Жесткий черный список (Приоритет №1) — игнорирует любые "полезные" баллы домена
    is_strict_ad = any(re.search(pat, domain, re.IGNORECASE) for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS)
    if is_strict_ad:
        return True

    # 2. Защита белого списка (Пропускаем только чистые корневые сервисы)
    if domain in STRICT_DOMAINS_WHITELIST or domain_apex in STRICT_DOMAINS_WHITELIST:
        if domain == domain_apex:
            return False
        # Поддомены из белого списка пропускаем, если они не забанены в пункте 1
        return False

    # 3. Исключения для базовых доменов текущей сканируемой страницы
    if page_apex:
        if domain == page_apex or f"www.{domain}" == page_apex or domain_apex == page_apex:
            return False

    # 4. Проверка инфраструктуры поисковиков
    if domain_apex and (domain_apex.startswith("google.") or domain_apex.startswith("yandex.")):
        if "tagmanager" in domain or "analytics" in domain:
            return True
        return False

    # 5. Анализ весов из логов сканирования
    if score is not None:
        # Если домен набрал хоть какой-то рекламный балл и при этом является сторонним (3rd-party cdn),
        # мы снижаем планку блокировки, чтобы не пропускать скрытые трекеры
        if score["ad_score"] > 0 and score["clean_score"] > 0:
            # Если это сторонний CDN-домен, подмешивающий рекламу — блокируем
            if "cdn" in domain and score["ad_score"] >= 12:
                return True
        return score["ad_score"] > score["clean_score"]

    # По умолчанию блокируем сторонние неопознанные домены
    return True

def process_scan_json(raw_data):
    """Основная логика анализа сетевого лога из ответа URLScan API."""
    if not raw_data or not isinstance(raw_data, dict):
        return {}, {}

    requests_list = raw_data.get("data", {}).get("requests", [])
    if not requests_list:
        return {}, {}

    AD_TRACKER_PATTERNS = [
        r"\/metrika\/", r"\/hit;", r"tracker\.", r"header-bidding",
        r"\/ads\/system\/", r"sync-loader", r"counter", r"analytics",
        r"gnezdo\.ru", r"fundingchoices", r"\/cm\.", r"context\.js",
        r"telemetry", r"adriver", r"bs\.serving-sys", r"advert"
    ]

    SYSTEM_ASSETS_PATTERNS = [
        r"\/dist\/client\/assets\/", r"\/dist\/client\/fonts\/", r"\/scrooge-client\/",
        r"\.hsmedia\.ru", r"\.viqeo\.tv",
        r"\.bbci\.co\.uk", r"\.bbc\.co\.uk",
        r"\.thetruestory\.news",
        r"cdn.*iportal\.ru"  # Защита медиа-серверов Городских порталов от ложных блокировок
    ]

    clean_domains = {}
    new_ad_domains = {}
    domain_verdicts = {}

    doc_url = raw_data.get("page", {}).get("url", "")
    page_apex = get_apex_domain(doc_url)

    for item in requests_list:
        req_container = item.get("request", {})
        resp_container = item.get("response", {})
        network_req = req_container.get("request", {})
        network_resp = resp_container.get("response", {})

        req_url = network_req.get("url")
        if not req_url or req_url.startswith("data:"):
            continue

        req_domain = urlparse(req_url).netloc.split(':')[0].lower().strip()
        if not req_domain:
            continue

        req_apex = get_apex_domain(req_url)
        
        initiator_data = req_container.get("initiator", {})
        initiator_type = initiator_data.get("type", "other") if isinstance(initiator_data, dict) else "other"
        mime_type = network_resp.get("mimeType", "").lower()

        if req_domain not in domain_verdicts:
            domain_verdicts[req_domain] = {"clean_score": 0, "ad_score": 0}

        is_ad_pattern = any(re.search(pattern, req_url, re.IGNORECASE) for pattern in AD_TRACKER_PATTERNS)
        is_system_asset = any(re.search(pattern, req_url, re.IGNORECASE) for pattern in SYSTEM_ASSETS_PATTERNS)

        if is_ad_pattern:
            domain_verdicts[req_domain]["ad_score"] += 30
        elif is_system_asset:
            domain_verdicts[req_domain]["clean_score"] += 20
            
        if page_apex and req_apex == page_apex:
            domain_verdicts[req_domain]["clean_score"] += 12
        else:
            domain_verdicts[req_domain]["ad_score"] += 6

        if initiator_type == "parser":
            domain_verdicts[req_domain]["clean_score"] += 5
        elif initiator_type == "script":
            domain_verdicts[req_domain]["ad_score"] += 6

        # Было: за font/woff2 со стороннего домена начислялось +10 к чистоте, 
        # что отмывало рекламные домены.
        # Стало: ассеты со сторонних доменов получают меньше баллов, если запущены скриптом.
        if page_apex and req_apex != page_apex:
            if mime_type in ["application/javascript", "text/javascript", "application/x-javascript"]:
                domain_verdicts[req_domain]["ad_score"] += 15  # Повысили штраф за сторонний JS
            elif mime_type in ["image/gif", "image/png"] and initiator_type == "script":
                domain_verdicts[req_domain]["ad_score"] += 8
            elif mime_type in ["application/json", "text/plain"]:
                domain_verdicts[req_domain]["ad_score"] += 4
            elif mime_type in ["font/woff2", "text/css", "image/svg+xml"]:
                # Даем баллы чистоты только если это не явный рекламный инициатор
                if initiator_type != "script":
                    domain_verdicts[req_domain]["clean_score"] += 10
                else:
                    domain_verdicts[req_domain]["clean_score"] += 2  # Скриптовым шрифтам веры нет

    # Распределение доменов по спискам на базе ЕДИНОЙ функции фильтрации
    for domain, score in domain_verdicts.items():
        if should_block_domain(domain, page_apex=page_apex, score=score):
            new_ad_domains[domain] = score
        else:
            clean_domains[domain] = score

    return new_ad_domains, clean_domains


async def submit_url_to_scan(target_url, api_key, session):
    """Отправляет запрос на сканирование в URLScan."""
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT, "x-api-key": api_key}
    data = {"url": target_url, "visibility": "public"}
    try:
        async with session.post(URLSCAN_SCAN, headers=headers, json=data, timeout=aiohttp.ClientTimeout(total=30), verify_ssl=False) as response:
            if response.status == 429:
                print("Превышен лимит запросов API (Rate Limit). Ожидание 60 секунд...")
                await asyncio.sleep(60)
                return await submit_url_to_scan(target_url, api_key, session)
            response.raise_for_status()
            res_json = await response.json()
            return res_json.get("uuid")
    except Exception as e:
        print(f"Ошибка отправки URL ({target_url}): {repr(e)}") # repr(e) покажет точный тип ошибки
    return None


async def poll_scan_results(uuid, api_key, session, max_wait_sec=SCAN_TIMEOUT):
    """Опрашивает API в ожидании готовности отчета."""
    result_url = f"{URLSCAN_RESULT}{uuid}/"
    headers = {"x-api-key": api_key}
    start_time = time.time()
    await asyncio.sleep(POLL_INTERVAL)
    while time.time() - start_time < max_wait_sec:
        try:
            async with session.get(result_url, headers=headers, timeout=aiohttp.ClientTimeout(total=20), verify_ssl=False) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    await asyncio.sleep(POLL_INTERVAL)
                else:
                    response.raise_for_status()
        except Exception:
            await asyncio.sleep(POLL_INTERVAL)
    return None


async def process_single_url(target_url, api_key, session, semaphore, hosts_lock, all_new_domains, all_clean_domains, failed_urls):
    """Управляет полным циклом сканирования одного URL."""
    async with semaphore:
        print(f"\n[{target_url}] Отправка на сканирование...")
        uuid = await submit_url_to_scan(target_url, api_key, session)
        if not uuid:
            async with hosts_lock:
                failed_urls.add(target_url)
            return False

        scan_data = await poll_scan_results(uuid, api_key, session)
        if not scan_data:
            async with hosts_lock:
                failed_urls.add(target_url)
            return False

        new_domains, clean_domains = process_scan_json(scan_data)
        if new_domains:
            async with hosts_lock:
                all_new_domains.update(new_domains)
        if clean_domains:
            async with hosts_lock:
                all_clean_domains.update(clean_domains)
        return True
async def main_async():
    """Точка входа: координация пула задач, агрегация данных и сохранение результатов."""
    api_key = get_api_key()
    if not api_key:
        print("Ошибка: Не найден API ключ URLSCAN_API_KEY.")
        sys.exit(1)
    else:
        print(f"API-ключ успешно считан. Длина: {len(api_key)} символов.")

    url_file = DEFAULT_URL_FILE
    if not url_file.exists():
        print(f"Файл '{url_file}' не найден.")
        sys.exit(1)

    async with aiohttp.ClientSession() as session:
        with url_file.open("r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

        if not urls:
            print(f"Файл '{url_file}' пуст.")
            sys.exit(0)

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        hosts_lock = asyncio.Lock()
        all_new_domains = {}
        all_clean_domains = {}
        failed_urls = set()
        
        tasks = [
            process_single_url(url, api_key, session, semaphore, hosts_lock, all_new_domains, all_clean_domains, failed_urls)
            for url in urls
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if r is True)
        fail_count = sum(1 for r in results if r is False)
        
        # --- ФИНАЛЬНАЯ СБОРКА И ПЕРЕПРОВЕРКА ЧЕРЕЗ ЕДИНЫЙ ФИЛЬТР ---
        existing_domains = read_existing_hosts(str(HOSTS_FILE))
        all_ad_domains = existing_domains.union(all_new_domains.keys())
        filtered_ad_domains = set()
        
        # Прогоняем абсолютно каждый домен базы через эталонную функцию фильтрации
        for domain in all_ad_domains:
            if should_block_domain(domain):
                filtered_ad_domains.add(domain)

        sorted_ad_domains = sort_domains_by_level(filtered_ad_domains)
        
        # Запись hosts-файла
        with open(HOSTS_FILE, "w", encoding="utf-8") as hosts_file:
            hosts_file.write("# [Advanced URLScan Filters Generated Advertising Blocklist]\n")
            hosts_file.write("# База дополняется автоматически, отсортирована по уровням доменов (1-2-3...)\n\n")
            for domain in sorted_ad_domains:
                hosts_file.write(f"0.0.0.0 {domain}\n")
        
        print(f"\n{'='*60}\nОБРАБОТКА ЗАВЕРШЕНА!")
        print(f"Успешно: {success_count}/{len(urls)} • Ошибки: {fail_count}/{len(urls)}")
        print(f"Новых доменов добавлено: {len(all_new_domains)} • Всего в базе: {len(sorted_ad_domains)}")
        
        # Формирование структурированного лога аналитики
        log_lines = [
            "=" * 60, "ЛОГ АНАЛИЗА URLSCAN", "=" * 60,
            f"Успешно: {success_count}/{len(urls)}", f"Ошибки: {fail_count}/{len(urls)}",
            f"Новых доменов добавлено: {len(all_new_domains)}", f"Всего в базе: {len(sorted_ad_domains)}", ""
        ]
        
        if all_new_domains:
            log_lines.append("--- ДОБАВЛЕННЫЕ РЕКЛАМНЫЕ ДОМЕНЫ ---")
            for idx, (domain, scores) in enumerate(sorted(all_new_domains.items()), 1):
                log_lines.append(f"{idx:02d}. [AD] {domain:<40} (clean: {scores['clean_score']}, ad: {scores['ad_score']})")
            log_lines.append("")
        
        if all_clean_domains:
            log_lines.append("--- ПРОПУЩЕННЫЕ ЛЕГИТИМНЫЕ ДОМЕНЫ ---")
            for idx, (domain, scores) in enumerate(sorted(all_clean_domains.items()), 1):
                log_lines.append(f"{idx:02d}. [OK] {domain:<40} (clean: {scores['clean_score']}, ad: {scores['ad_score']})")
            log_lines.append("")
            
        if failed_urls:
            log_lines.append("--- НЕ ПРОСКОНИРОВАННЫЕ URL ---")
            for idx, url in enumerate(sorted(failed_urls), 1):
                log_lines.append(f"{idx:02d}. [FAIL] {url}")
            log_lines.append("")
        
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(log_lines))
        print(f"Лог сохранён в '{LOG_FILE}'")


if __name__ == "__main__":
    asyncio.run(main_async())
