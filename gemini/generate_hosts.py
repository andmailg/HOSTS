import json
import os
import re
import sys
from urllib.parse import urlparse
import requests
import tldextract
import urllib3

# Отключаем предупреждения о небезопасном HTTPS (корпоративные прокси/сертификаты)
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


def fetch_urlscan_data(scan_input):
    uuid = extract_uuid(scan_input)
    if not uuid:
        print("Ошибка: Не удалось распознать UUID сканирования.")
        sys.exit(1)

    api_key = get_api_key()
    if not api_key:
        print("Ошибка: Не найден API ключ urlscan.io.")
        sys.exit(1)

    url = f"https://urlscan.io/api/v1/result/{uuid}/"
    print(f"Скачивание данных с urlscan.io для сканирования {uuid}...")

    headers = {"x-api-key": api_key}

    try:
        response = requests.get(url, timeout=30, verify=False, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при обращении к API urlscan.io: {e}")
        sys.exit(1)


def generate_hosts_from_api(scan_input, output_hosts_path="hosts_advanced.txt"):
    scan_uuid = extract_uuid(scan_input)
    raw_data = fetch_urlscan_data(scan_input)

    requests_list = []
    if isinstance(raw_data, dict):
        requests_list = raw_data.get("data", {}).get("requests", [])

    if not requests_list:
        print("Ошибка: Лог сетевых запросов в ключе ['data']['requests'] пуст.")
        return

    # Рекламные паттерны
    AD_TRACKER_PATTERNS = [
        r"\/metrika\/", r"\/hit;", r"tracker\.", r"header-bidding",
        r"\/ads\/system\/", r"sync-loader", r"counter", r"analytics",
        r"gnezdo\.ru", r"fundingchoices", r"\/cm\.", r"context\.js"
    ]

    # Системные ассеты CDN сайта
    SYSTEM_ASSETS_PATTERNS = [
        r"\/dist\/client\/assets\/", r"\/dist\/client\/fonts\/", r"\/scrooge-client\/",
        r"\.hsmedia\.ru", r"\.viqeo\.tv"
    ]

    # Точечный список безопасных доменов статики и инфраструктуры
    STRICT_DOMAINS_WHITELIST = [
        "yastatic.net",
        "yandex.ru",
        "avatars.mds.yandex.net",
        "favicon.yandex.net",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com"
    ]

    # Жесткий черный список для поддоменов Яндекса/Google (отменяет белый список)
    STRICT_SUBDOMAINS_BLACKLIST = [
        "mc.yandex.ru", 
        "an.yandex.ru", 
        "ads.yandex.ru",
        "google.com"
    ]

    clean_domains = set()
    ad_domains = set()
    domain_verdicts = {}
    page_apex = None

    for item in requests_list:
        req_container = item.get("request", {})
        resp_container = item.get("response", {})

        network_req = req_container.get("request", {})
        network_resp = resp_container.get("response", {})

        req_url = network_req.get("url")
        if not req_url or req_url.startswith("data:"):
            continue

        req_domain = urlparse(req_url).netloc
        if not req_domain.strip():
            continue

        doc_url = req_container.get("documentURL") or raw_data.get("page", {}).get("url", "")
        page_apex = get_apex_domain(doc_url)
        req_apex = get_apex_domain(req_url)
        
        initiator_data = req_container.get("initiator", {})
        initiator_type = initiator_data.get("type", "other") if isinstance(initiator_data, dict) else "other"
        mime_type = network_resp.get("mimeType", "").lower()

        if req_domain not in domain_verdicts:
            domain_verdicts[req_domain] = {"clean_score": 0, "ad_score": 0}

        is_ad_pattern = any(re.search(pattern, req_url, re.IGNORECASE) for pattern in AD_TRACKER_PATTERNS)
        is_system_asset = any(re.search(pattern, req_url, re.IGNORECASE) for pattern in SYSTEM_ASSETS_PATTERNS)

        # --- КОРРЕКЦИЯ ВЕСОВ ---
        if is_ad_pattern:
            domain_verdicts[req_domain]["ad_score"] += 30
        elif is_system_asset:
            domain_verdicts[req_domain]["clean_score"] += 20
            
        if page_apex and req_apex == page_apex:
            domain_verdicts[req_domain]["clean_score"] += 12
        else:
            # Увеличен базовый штраф за чужой домен, чтобы срезать mts, weborama, adriver
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

    # Обработка результатов с умными фильтрами
    for domain, score in domain_verdicts.items():
        # Правило 1: Если поддомен в жестком черном списке — это реклама
        if domain in STRICT_SUBDOMAINS_BLACKLIST:
            ad_domains.add(domain)
        # Правило 2: Если домен в строгом белом списке — пропускаем
        elif domain in STRICT_DOMAINS_WHITELIST or domain == page_apex or f"www.{domain}" == page_apex:
            clean_domains.add(domain)
        # Правило 3: Стандартная проверка по весам
        elif score["ad_score"] > score["clean_score"]:
            ad_domains.add(domain)
        else:
            clean_domains.add(domain)

    # Запись в файл hosts
    with open(output_hosts_path, "w", encoding="utf-8") as hosts_file:
        hosts_file.write("# [Advanced URLScan Filters Generated Advertising Blocklist]\n")
        hosts_file.write(f"# Источник сканирования: {scan_uuid}\n\n")
        for domain in sorted(ad_domains):
            hosts_file.write(f"0.0.0.0 {domain}\n")

    # ВЫВОД ПРОПУЩЕННЫХ ДОМЕНОВ В ТЕРМИНАЛ
    print(f"\n--- СПИСОК ПРОПУЩЕННЫХ ЛЕГИТИМНЫХ ДОМЕНОВ ({len(clean_domains)}) ---")
    for idx, domain in enumerate(sorted(clean_domains), 1):
        score = domain_verdicts[domain]
        print(f"{idx:02d}. [OK] {domain:<40} (clean: {score['clean_score']}, ad: {score['ad_score']})")

    print(f"\n УСПЕШНО: Файл '{output_hosts_path}' сгенерирован!")
    print(f"Всего рекламных доменов добавлено в блоклист: {len(ad_domains)}")
    print(f"Всего легитимных доменов сайта пропущено: {len(clean_domains)}")


if __name__ == "__main__":
    TARGET_SCAN = "01a11f72-6104-7663-a988-55a46b3027b9"
    generate_hosts_from_api(TARGET_SCAN)
