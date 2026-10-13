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

# --- Config ---
HOSTS_FILE = Path(__file__).parent.parent / "hosts_advanced.txt"
LOG_FILE = Path(__file__).parent.parent / "log.txt"
DEFAULT_URL_FILE = Path(__file__).parent / "urls.txt"
URLSCAN_SCAN = "https://urlscan.io/api/v1/scan/"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
DELAY_SEC = 3
SCAN_TIMEOUT = 180
POLL_INTERVAL = 20
MAX_CONCURRENT = 10

# Фильтры для итогового файла
STRICT_DOMAINS_WHITELIST = [
        # --- ГЛОБАЛЬНЫЕ СЕРВИСЫ И CDN ---
        "cloudflare.com", "jsdelivr.net", "unpkg.com", "googleapis.com", 
        "gstatic.com", "googleusercontent.com", "google.dk", "gvt1.com",
        "youtube.com", "ytimg.com", "nflximg.net", "dmcdn.net", "rackcdn.com",
        "cloudflareinsights.com", "openfpcdn.io",
        
        # --- ИНФРАСТРУКТУРА ЯНДЕКСА И DZEN ---
        "yastatic.net", "avatars.mds.yandex.net", "favicon.yandex.net",
        "dzen.ru", "dzeninfra.ru", "imgsmail.ru",
        
        # --- МЕДИАСЕРВЕРЫ И CDN ВКОНТАКТЕ (VK) ---
        "vk.com", "vk.ru", "vkuser.net", "vkuserphoto.ru", "vk-portal.net", 
        "vk-cdn.net", "vk.me", "vkvd.net", "vkuseraudio.net", "vkvideo.ru",
        
        # --- МЕДИАСЕРВЕРЫ И CDN ОДНОКЛАССНИКОВ (OK) ---
        "ok.ru", "okcdn.ru", "odnoklassniki.ru", "mycdn.me",
        
        # --- МЕДИАСЕРВЕРЫ И CDN RUTUBE ---
        "rutube.ru", "static.rutube.ru", "goya.rutube.ru", "log.rutube.ru", 
        "ssp.rutube.ru", "rutubelist.ru", "blrutube.ru",
        
        # --- ГОСУДАРСТВЕННЫЕ И БАНКОВСКИЕ СЕРВИСЫ ---
        "mos.ru", "sberbank.ru", "sbrf.ru", "sber.ru",
        
        # --- ДОВЕРЕННЫЕ СМИ И ИХ CDN (ИЗ КОДА) ---
        "thetruestory.news", "rferl.org", "fastpic.org", "imageban.ru", 
        "pic4net.com", "directupload.eu", "hostingkartinok.com", "rutracker.cc", 
        "imgchest.com", "vigo.tech", "ichef.bbci.co.uk", "static.bbci.co.uk", 
        "mybbc-analytics.files.bbci.co.uk", "static.files.bbci.co.uk", "emp.bbci.co.uk"
    ]

STRICT_SUBDOMAINS_BLACKLIST_PATTERNS = [
    r"mc\.yandex\.ru", r"an\.yandex\.ru", r"ads\.yandex\.ru", r"^yandex\.ru$",
    r"sdk-api\.apptracer\.ru", r"trace-flow\.ru", 
    r"tracker-api\.vk-analytics\.ru", r"tracker-api\.my\.com", 
    r"telemetry\.dzen\.ru",
    r"\.ms\.vk\.ru",
    r"\.ms\.dzen\.ru",
    r"mradx\.net",
    r"\.appsflyersdk\.com",
    r"alt-ad\.mail\.ru",
    r"\.mediascope\.mail\.ru",
    r"alt-aj-https\.mail\.ru",
    r"ads\.vk\.ru",
    r"target\.vk\.ru"
]

# Отключаем предупреждения о небезопасном HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_api_key():
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


def get_apex_domain(url):
    if not url or url.startswith("data:"):
        return None
    if not url.startswith(("http://", "https://")):
        extracted = tldextract.extract(f"http://{url}")
    else:
        extracted = tldextract.extract(url)
        
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return None


def extract_uuid(target_input):
    uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    match = re.search(uuid_pattern, target_input, re.IGNORECASE)
    if match:
        return match.group(0)
    return None


async def submit_url_to_scan(target_url, api_key, session):
    """Отправляет запрос на новое сканирование в urlscan.io и возвращает UUID."""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "x-api-key": api_key
    }
    data = {
        "url": target_url,
        "visibility": "public"
    }
    
    try:
        async with session.post(URLSCAN_SCAN, headers=headers, json=data, timeout=aiohttp.ClientTimeout(total=30), verify_ssl=False) as response:
            if response.status == 429:
                print("Превышен лимит запросов API (Rate Limit). Ожидание 60 секунд...")
                await asyncio.sleep(60)
                return await submit_url_to_scan(target_url, api_key, session)
                
            response.raise_for_status()
            res_json = await response.json()
            uuid = res_json.get("uuid")
            if uuid:
                print(f"Ссылка {target_url} успешно отправлена на сканирование. UUID: {uuid}")
                return uuid
    except asyncio.TimeoutError:
        print(f"Таймаут отправки URL на сканирование ({target_url})")
    except Exception as e:
        print(f"Ошибка отправки URL на сканирование ({target_url}): {e}")
    return None


async def poll_scan_results(uuid, api_key, session, max_wait_sec=SCAN_TIMEOUT):
    """Опрашивает API, ожидая готовности отчета сканирования."""
    result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
    headers = {"x-api-key": api_key}
    
    start_time = time.time()
    print(f"Ожидание завершения анализа для сканирования {uuid}...")
    
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
        except asyncio.TimeoutError:
            await asyncio.sleep(POLL_INTERVAL)
        except Exception:
            await asyncio.sleep(POLL_INTERVAL)
            
    print(f"Таймаут: Не удалось получить результаты для UUID {uuid} за {max_wait_sec} сек.")
    return None


async def process_single_url(target_url, api_key, session, semaphore, hosts_lock, all_new_domains, all_clean_domains, failed_urls):
    """Обрабатывает один URL: сканирование + ожидание + обработка."""
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


def read_existing_hosts(file_path):
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
    return sorted(list(domain_set), key=lambda d: (d.count("."), d))


def process_scan_json(raw_data, existing_domains=None):
    """Основная логика анализа сетевого лога и генерации блоклиста.
    Возвращает кортеж: (новые рекламные домены, пропущенные легитимные домены с весами).
    """
    if existing_domains is None:
        existing_domains = read_existing_hosts(str(HOSTS_FILE))
    if not raw_data or not isinstance(raw_data, dict):
        return {}, {}

    requests_list = raw_data.get("data", {}).get("requests", [])
    if not requests_list:
        print("Предупреждение: Лог сетевых запросов в ключе ['data']['requests'] пуст.")
        return {}, {}

    AD_TRACKER_PATTERNS = [
        r"\/metrika\/", r"\/hit;", r"tracker\.", r"header-bidding",
        r"\/ads\/system\/", r"sync-loader", r"counter", r"analytics",
        r"gnezdo\.ru", r"fundingchoices", r"\/cm\.", r"context\.js",
        r"telemetry"
    ]

    SYSTEM_ASSETS_PATTERNS = [
        r"\/dist\/client\/assets\/", r"\/dist\/client\/fonts\/", r"\/scrooge-client\/",
        r"\.hsmedia\.ru", r"\.viqeo\.tv",
        r"\.bbci\.co\.uk", r"\.bbc\.co\.uk",
        r"\.thetruestory\.news"
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

        req_domain = urlparse(req_url).netloc.split(':')[0]
        if not req_domain.strip():
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

        if page_apex and req_apex != page_apex:
            if mime_type in ["application/javascript", "text/javascript", "application/x-javascript"]:
                domain_verdicts[req_domain]["ad_score"] += 6
            elif mime_type in ["image/gif", "image/png"] and initiator_type == "script":
                domain_verdicts[req_domain]["ad_score"] += 4
            elif mime_type in ["application/json", "text/plain"]:
                domain_verdicts[req_domain]["ad_score"] += 2
            elif mime_type in ["font/woff2", "text/css", "image/svg+xml"]:
                domain_verdicts[req_domain]["clean_score"] += 10

    for domain, score in domain_verdicts.items():
        is_blacklisted = any(
            re.search(pat, domain, re.IGNORECASE)
            for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS
        )
        if is_blacklisted:
            new_ad_domains[domain] = domain_verdicts[domain]
        elif (
            domain in STRICT_DOMAINS_WHITELIST
            or domain == page_apex
            or f"www.{domain}" == page_apex
        ):
            clean_domains[domain] = domain_verdicts[domain]
        elif score["ad_score"] > score["clean_score"]:
            new_ad_domains[domain] = domain_verdicts[domain]
        else:
            clean_domains[domain] = domain_verdicts[domain]

        # --- ИСПРАВЛЕННЫЙ БЛОК ФИЛЬТРАЦИИ ---
        existing_domains = read_existing_hosts(str(HOSTS_FILE))
        all_ad_domains = existing_domains.union(new_ad_domains.keys())
        filtered_ad_domains = set()
        
        for domain in all_ad_domains:
            domain_apex = get_apex_domain(domain)
            
            # 1. ПРИОРИТЕТ БЕЛОГО СПИСКА: Если сам домен или его apex в белом списке
            if domain in STRICT_DOMAINS_WHITELIST or domain_apex in STRICT_DOMAINS_WHITELIST:
                # Исключение: блокируем только если это строго заданный рекламный поддомен
                # (например, mc.yandex.ru или ad.mail.ru), но НЕ сам корневой yandex.ru
                is_strict_ad_subdomain = any(
                    re.search(pat, domain, re.IGNORECASE) for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS
                )
                # Если это корневой домен из белого списка — пропускаем блокировку
                if domain == domain_apex and domain in STRICT_DOMAINS_WHITELIST:
                    continue
                # Если поддомен не подпадает под паттерны рекламы — пропускаем блокировку
                if not is_strict_ad_subdomain:
                    continue

            # 2. ЧЕРНЫЙ СПИСОК: Проверяем на соответствие паттернам рекламы
            is_strict_ad = any(
                re.search(pat, domain, re.IGNORECASE) for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS
            )
            if is_strict_ad:
                filtered_ad_domains.add(domain)
                continue

            # 3. Дополнительные правила для Google/Yandex (за исключением tagmanager)
            if domain_apex and (domain_apex.startswith("google.") or domain_apex.startswith("yandex.")):
                if "tagmanager" not in domain:
                    continue

            filtered_ad_domains.add(domain)

    return new_ad_domains, clean_domains


async def main_async():
    api_key = get_api_key()
    if not api_key:
        print(
            "Ошибка: Не найден API ключ URLSCAN_API_KEY ни в "
            "переменной окружения, ни в файле .env."
        )
        sys.exit(1)

    url_file = DEFAULT_URL_FILE
    output_hosts = HOSTS_FILE

    if not url_file.exists():
        print(f"Файл '{url_file}' не найден.")
        sys.exit(1)

    async with aiohttp.ClientSession() as session:
        with url_file.open("r", encoding="utf-8") as f:
            urls = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]

        if not urls:
            print(f"Файл '{url_file}' пуст или содержит только комментарии.")
            sys.exit(0)

        print(f"Найдено URL для сканирования: {len(urls)}")
        print(f"Максимальная параллельность: {MAX_CONCURRENT}")
        
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
        
        # Запись итогового hosts-файла
        existing_domains = read_existing_hosts(str(HOSTS_FILE))
        all_ad_domains = existing_domains.union(all_new_domains.keys())
        filtered_ad_domains = set()
        
        for domain in all_ad_domains:
            domain_apex = get_apex_domain(domain)
            is_strict_ad = any(
                re.search(pat, domain, re.IGNORECASE)
                for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS
            )
            if is_strict_ad:
                filtered_ad_domains.add(domain)
                continue

            if domain in STRICT_DOMAINS_WHITELIST or domain_apex in STRICT_DOMAINS_WHITELIST:
                continue

            if domain_apex and (
                domain_apex.startswith("google.") or domain_apex.startswith("yandex.")
            ):
                if "tagmanager" not in domain:
                    continue

            filtered_ad_domains.add(domain)

        sorted_ad_domains = sort_domains_by_level(filtered_ad_domains)
        
        with open(HOSTS_FILE, "w", encoding="utf-8") as hosts_file:
            hosts_file.write(
                "# [Advanced URLScan Filters Generated Advertising Blocklist]\n"
            )
            hosts_file.write(
                "# База дополняется автоматически, отсортирована по уровням доменов (1-2-3...)\n\n"
            )
            for domain in sorted_ad_domains:
                hosts_file.write(f"0.0.0.0 {domain}\n")
        
        print(f"\n{'='*60}")
        print(f"ОБРАБОТКА ЗАВЕРШЕНА!")
        print(f"Успешно: {success_count}/{len(urls)}")
        print(f"Ошибки: {fail_count}/{len(urls)}")
        print(f"Новых доменов добавлено: {len(all_new_domains)}")
        print(f"Всего в базе: {len(sorted_ad_domains)}")
        print(f"Результаты сохранены в '{HOSTS_FILE}'")
        
        # Вывод добавленных доменов
        if all_new_domains:
            print(f"\n--- СПИСОК ДОБАВЛЕННЫХ РЕКЛАМНЫХ ДОМЕНОВ ({len(all_new_domains)}) ---")
            for idx, (domain, scores) in enumerate(sorted(all_new_domains.items()), 1):
                print(f"{idx:02d}. [AD] {domain:<40} (clean: {scores['clean_score']}, ad: {scores['ad_score']})")
        
        # Вывод пропущенных легитимных доменов
        if all_clean_domains:
            print(f"\n--- СПИСОК ПРОПУЩЕННЫХ ЛЕГИТИМНЫХ ДОМЕНОВ ({len(all_clean_domains)}) ---")
            for idx, (domain, scores) in enumerate(sorted(all_clean_domains.items()), 1):
                print(f"{idx:02d}. [OK] {domain:<40} (clean: {scores['clean_score']}, ad: {scores['ad_score']})")
        
        # Вывод не просканированных seed-доменов
        if failed_urls:
            print(f"\n--- СПИСОК НЕ ПРОСКОНИРОВАННЫХ URL ({len(failed_urls)}) ---")
            for idx, url in enumerate(sorted(failed_urls), 1):
                print(f"{idx:02d}. [FAIL] {url}")
        
        # Сохранение лога в файл
        log_lines = []
        log_lines.append("=" * 60)
        log_lines.append("ЛОГ АНАЛИЗА URLSCAN")
        log_lines.append("=" * 60)
        log_lines.append(f"Успешно: {success_count}/{len(urls)}")
        log_lines.append(f"Ошибки: {fail_count}/{len(urls)}")
        log_lines.append(f"Новых доменов добавлено: {len(all_new_domains)}")
        log_lines.append(f"Всего в базе: {len(sorted_ad_domains)}")
        log_lines.append("")
        
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
        
        print(f"\nЛог сохранён в '{LOG_FILE}'")


if __name__ == "__main__":
    asyncio.run(main_async())
