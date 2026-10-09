import json
import os
import re
import sys
from urllib.parse import urlparse
import requests
import tldextract


def get_apex_domain(url):
    if not url or url.startswith("data:"):
        return None
    extracted = tldextract.extract(url)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return None


def extract_uuid(target_input):
    """Извлекает UUID сканирования из ссылки или возвращает его, если передан чистый UUID"""
    # Паттерн ищет 36-символьный UUID (например, 123e4567-e89b-12d3-a456-426655440000)
    uuid_pattern = (
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )
    match = re.search(uuid_pattern, target_input, re.IGNORECASE)
    if match:
        return match.group(0)
    return None


def fetch_urlscan_data(scan_input):
    """Скачивает JSON с подробными сетевыми запросами (devtools-логи) с urlscan.io"""
    uuid = extract_uuid(scan_input)
    if not uuid:
        print(
            "Ошибка: Не удалось распознать UUID сканирования. Введите чистый UUID или ссылку вида https://urlscan.io"
        )
        sys.exit(1)

    # Для получения полной структуры requests нам нужен эндпоинт devtools/dom
    url = f"https://urlscan.io{uuid}/"
    print(f"Скачивание данных с urlscan.io для сканирования {uuid}...")

    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 404:
            print(
                "Ошибка 404: Результат сканирования не найден. Возможно, это приватное сканирование или UUID указан неверно."
              + "\nЕсли сканирование приватное, скрипту необходимы API-заголовки авторизации."
            )
            sys.exit(1)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при обращении к API urlscan.io: {e}")
        sys.exit(1)


def generate_hosts_from_api(scan_input, output_hosts_path="hosts_advanced.txt"):
    # Извлекаем UUID для отображения в заголовке
    scan_uuid = extract_uuid(scan_input)
    
    # Получаем данные напрямую из API
    raw_data = fetch_urlscan_data(scan_input)

    # В devtools-ответе urlscan.io массив requests лежит в корне структуры или в 'requests'
    # Приводим к единому виду, совместимому с выгрузками
    requests_list = []
    if isinstance(raw_data, dict):
        requests_list = raw_data.get("requests", [])
    elif isinstance(raw_data, list):
        requests_list = raw_data

    if not requests_list:
        print(
            "Предупреждение: Лог сетевых запросов пуст или имеет нетипичную структуру."
        )

    # Паттерны для анализа
    AD_TRACKER_PATTERNS = [
        r"\/metrika\/",
        r"\/hit;",
        r"tracker\.",
        r"header-bidding",
        r"\/ads\/system\/",
        r"sync-loader",
        r"counter",
        r"analytics",
    ]

    SYSTEM_ASSETS_PATTERNS = [
        r"\/dist\/client\/assets\/",
        r"\/dist\/client\/fonts\/",
        r"\/scrooge-client\/",
    ]

    clean_domains = set()
    ad_domains = set()
    domain_verdicts = {}

    for item in requests_list:
        req_entry = item.get("request", {})
        resp_entry = item.get("response", {})

        doc_url = req_entry.get("documentURL")
        page_apex = get_apex_domain(doc_url)

        network_req = req_entry.get("request", {})
        req_url = network_req.get("url")

        if not req_url or req_url.startswith("data:"):
            continue

        req_domain = urlparse(req_url).netloc
        req_apex = get_apex_domain(req_url)
        initiator_type = req_entry.get("initiator", {}).get("type", "other")
        mime_type = resp_entry.get("response", {}).get("mimeType", "").lower()

        if req_domain not in domain_verdicts:
            domain_verdicts[req_domain] = {"clean_score": 0, "ad_score": 0}

        is_ad_pattern = any(
            re.search(pattern, req_url, re.IGNORECASE)
            for pattern in AD_TRACKER_PATTERNS
        )
        is_system_asset = any(
            re.search(pattern, req_url, re.IGNORECASE)
            for pattern in SYSTEM_ASSETS_PATTERNS
        )

        if is_ad_pattern:
            domain_verdicts[req_domain]["ad_score"] += 12
        elif is_system_asset:
            domain_verdicts[req_domain]["clean_score"] += 8
        elif req_apex == page_apex:
            domain_verdicts[req_domain]["clean_score"] += 5
        elif initiator_type == "parser":
            domain_verdicts[req_domain]["clean_score"] += 4
        elif mime_type in ["font/woff2", "text/css", "image/svg+xml"]:
            domain_verdicts[req_domain]["clean_score"] += 3
        elif (
            mime_type in ["application/javascript", "text/javascript"]
            and initiator_type == "script"
        ):
            domain_verdicts[req_domain]["ad_score"] += 1

    for domain, score in domain_verdicts.items():
        if score["ad_score"] > score["clean_score"]:
            ad_domains.add(domain)
        else:
            clean_domains.add(domain)

    with open(output_hosts_path, "w", encoding="utf-8") as hosts_file:
        hosts_file.write("# [Advanced URLScan Filters Generated Advertising Blocklist]\n")
        hosts_file.write(f"# Источник сканирования: {scan_uuid}\n\n")
        for domain in sorted(ad_domains):
            hosts_file.write(f"0.0.0.0 {domain}\n")

    print(f"\n УСПЕШНО: Файл '{output_hosts_path}' сгенерирован!")
    print(f"Всего рекламных доменов добавлено в блоклист: {len(ad_domains)}")
    print(f"Всего легитимных доменов сайта пропущено: {len(clean_domains)}")


if __name__ == "__main__":
    # Сюда можно вставить как полный URL из адресной строки браузера, так и просто UUID
    # Пример ссылки: "https://urlscan.io"
    TARGET_SCAN = "3DD1768C-43F2-6ED6-BE4C4A1FF292BDA3"  # Замените на ваш UUID

    generate_hosts_from_api(TARGET_SCAN)

### Как им пользоваться теперь:
# В переменной `TARGET_SCAN` в самом низу скрипта вы можете оставить либо чистый идентификатор сканирования (UUID) [1], либо скопировать туда **всю ссылку на результат** из браузера (например, `https://urlscan.io...`). Скрипт сам найдет регулярным выражением нужный ID, сделает фоновый запрос к API [1], заберет девелоперский лог, взвесит домены по нашей умной системе и сохранит чистый отфильтрованный `hosts_advanced.txt`.
