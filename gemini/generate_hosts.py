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
    """Получает API ключ urlscan.io из переменной окружения или файла"""
    # Приоритет: переменная окружения > файл .env в текущей директории
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if api_key:
        return api_key
    
    # Попытка прочитать из .env файла
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

    # API ключ для доступа к полным данным сканирования
    api_key = get_api_key()
    if not api_key:
        print(
            "Ошибка: Не найден API ключ urlscan.io.\n"
            "1. Зарегистрируйтесь на https://urlscan.io\n"
            "2. Получите API ключ в настройках профиля\n"
            "3. Установите переменную окружения URLSCAN_API_KEY=<ваш_ключ>\n"
            "   или создайте файл .env с содержимым: URLSCAN_API_KEY=<ваш_ключ>"
        )
        sys.exit(1)

    # Эндпоинт для получения полных данных сканирования с devtools-логами
    url = f"https://urlscan.io/api/v1/result/{uuid}/"
    print(f"Скачивание данных с urlscan.io для сканирования {uuid}...")

    headers = {"x-api-key": api_key}

    try:
        response = requests.get(url, timeout=30, verify=False, headers=headers)
        if response.status_code == 404:
            print(
                "Ошибка 404: Результат сканирования не найден. Возможно, это приватное сканирование или UUID указан неверно."
            )
            sys.exit(1)
        if response.status_code == 403:
            print(
                "Ошибка 403: Неверный API ключ или недостаточно прав.\n"
                "Проверьте правильность URLSCAN_API_KEY и уровень вашего аккаунта urlscan.io."
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
    
    # Получаем данные напрямую из API (структура v1/result)
    raw_data = fetch_urlscan_data(scan_input)

    requests_list = []
    if isinstance(raw_data, dict):
        requests_list = raw_data.get("data", {}).get("requests", [])

    if not requests_list:
        print(
            "Ошибка: Лог сетевых запросов в ключе ['data']['requests'] пуст.\n"
            "Убедитесь, что сканирование завершено успешно."
        )
        return

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
        r"gnezdo\.ru",  # ДОБАВЛЕНО: Тизерная сеть Gnezdo (блокирует и news, и fcgi5)
    ]

    SYSTEM_ASSETS_PATTERNS = [
        r"\/dist\/client\/assets\/", r"\/dist\/client\/fonts\/", r"\/scrooge-client\/",
        r"\.hsmedia\.ru", r"\.viqeo\.tv"
    ]

    clean_domains = set()
    ad_domains = set()
    domain_verdicts = {}

    for item in requests_list:
        req_container = item.get("request", {})
        resp_container = item.get("response", {})

        network_req = req_container.get("request", {})
        network_resp = resp_container.get("response", {})

        req_url = network_req.get("url")
        if not req_url or req_url.startswith("data:"):
            continue

        doc_url = req_container.get("documentURL") or raw_data.get("page", {}).get("url", "")
        page_apex = get_apex_domain(doc_url)

        req_domain = urlparse(req_url).netloc
        # ЗАЩИТА ОТ ПУСТЫХ СТРОК: Пропускаем запрос, если домен пустой
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

        # --- ТОЧНАЯ НАСТРОЙКА ВЕСОВ ---
        if is_ad_pattern:
            domain_verdicts[req_domain]["ad_score"] += 25
        elif is_system_asset:
            domain_verdicts[req_domain]["clean_score"] += 20
            
        # Свой/чужой
        if page_apex and req_apex == page_apex:
            domain_verdicts[req_domain]["clean_score"] += 12
        else:
            # ПОВЫШЕНО: Сторонний домен получает больше штрафа по умолчанию
            domain_verdicts[req_domain]["ad_score"] += 7

        # Инициатор
        if initiator_type == "parser":
            domain_verdicts[req_domain]["clean_score"] += 5
        elif initiator_type == "script":
            domain_verdicts[req_domain]["ad_score"] += 6

        # Анализ контента на чужих доменах
        if page_apex and req_apex != page_apex:
            # ПОВЫШЕНО: Чужие JS скрипты штрафуются жестче
            if mime_type in ["application/javascript", "text/javascript", "application/x-javascript"]:
                domain_verdicts[req_domain]["ad_score"] += 8
            elif mime_type in ["image/gif", "image/png"] and initiator_type == "script":
                domain_verdicts[req_domain]["ad_score"] += 5
            elif mime_type in ["application/json", "text/plain"]:
                domain_verdicts[req_domain]["ad_score"] += 3
            elif mime_type in ["font/woff2", "text/css", "image/svg+xml"]:
                domain_verdicts[req_domain]["clean_score"] += 10


    # Распределение доменов по спискам
    for domain, score in domain_verdicts.items():
        if score["ad_score"] > score["clean_score"]:
            ad_domains.add(domain)
        else:
            clean_domains.add(domain)

    # Запись в файл hosts
    with open(output_hosts_path, "w", encoding="utf-8") as hosts_file:
        hosts_file.write("# [Advanced URLScan Filters Generated Advertising Blocklist]\n")
        hosts_file.write(f"# Источник сканирования: {scan_uuid}\n\n")
        for domain in sorted(ad_domains):
            hosts_file.write(f"0.0.0.0 {domain}\n")

    # --- НОВОЕ: ВЫВОД ПРОПУЩЕННЫХ ДОМЕНОВ В ЛОГ ТЕРМИНАЛА ---
    print(f"\n--- СПИСОК ПРОПУЩЕННЫХ ЛЕГИТИМНЫХ ДОМЕНОВ ({len(clean_domains)}) ---")
    for idx, domain in enumerate(sorted(clean_domains), 1):
        # Дополнительно выводим набранные баллы для наглядности
        score = domain_verdicts[domain]
        print(f"{idx:02d}. [OK] {domain:<35} (clean: {score['clean_score']}, ad: {score['ad_score']})")

    print(f"\n УСПЕШНО: Файл '{output_hosts_path}' сгенерирован!")
    print(f"Всего рекламных доменов добавлено в блоклист: {len(ad_domains)}")
    print(f"Всего легитимных доменов сайта пропущено: {len(clean_domains)}")




if __name__ == "__main__":
    # Сюда можно вставить как полный URL из адресной строки браузера, так и просто UUID
    # Пример ссылки: "https://urlscan.io"
    TARGET_SCAN = "01a11f72-6104-7663-a988-55a46b3027b9"  # Замените на ваш UUID

    generate_hosts_from_api(TARGET_SCAN)

### Как им пользоваться теперь:
# В переменной `TARGET_SCAN` в самом низу скрипта вы можете оставить либо чистый идентификатор сканирования (UUID) [1], либо скопировать туда **всю ссылку на результат** из браузера (например, `https://urlscan.io...`). Скрипт сам найдет регулярным выражением нужный ID, сделает фоновый запрос к API [1], заберет девелоперский лог, взвесит домены по нашей умной системе и сохранит чистый отфильтрованный `hosts_advanced.txt`.
