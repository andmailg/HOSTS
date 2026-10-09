#!/usr/bin/env python3
"""adblock-generator.py — Сканирует сайты через urlscan.io и извлекает рекламные домены"""

import sys
import re
import os
import time
import json
import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError
from pathlib import Path
from typing import Optional, Set, Dict, Any

# --- Config ---
ADBLOCK_FILE = Path(__file__).parent / "hosts_auto.txt"
DEFAULT_URL_FILE = Path(__file__).parent / "urls.txt"
WHITELIST_FILE = Path(__file__).parent / "whitelist.txt"
URLSCAN_SCAN = "https://urlscan.io/api/v1/scan/"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdBlockBot/1.0"
DELAY_SEC = 3
API_KEY = os.environ.get("URLSCAN_API_KEY", "")


def load_whitelist() -> Set[str]:
    """Загружает белый список доменов."""
    whitelist: Set[str] = set()
    if WHITELIST_FILE.exists():
        for line in WHITELIST_FILE.read_text(encoding="utf-8").splitlines():
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                whitelist.add(domain)
    return whitelist


# --- Logging ---
def log(msg: str, color: str = "white"):
    colors = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m", "cyan": "\033[96m", "white": "\033[97m"}
    reset = "\033[0m"
    prefix = f"\033[90m{time.strftime('%H:%M:%S')}\033[0m"
    print(f"{prefix} {colors.get(color, '')}{msg}{reset}")


# --- URL Helpers ---
def ensure_scheme(url: str) -> str:
    """Добавляет https:// если схема отсутствует."""
    if re.match(r'^https?://', url, re.I):
        return url
    return f"https://{url}"


# --- URLScan API ---
def urlscan_request(method: str, url: str, data: Optional[bytes] = None,
                    headers: Optional[dict] = None, timeout: int = 30) -> Any:
    """Делает HTTP запрос к urlscan.io с правильной обработкой ошибок."""
    if headers is None:
        headers = {"Content-Type": "application/json"}
    headers["User-Agent"] = USER_AGENT
    if API_KEY:
        headers["API-Key"] = API_KEY

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")
        except Exception:
            pass
        log(f"HTTP {e.code} {e.reason}: {body[:200]}", "red")
        return None
    except URLError as e:
        log(f"Ошибка сети: {e.reason}", "red")
        return None
    except json.JSONDecodeError as e:
        log(f"Ошибка парсинга JSON: {e}", "red")
        return None


def send_to_urlscan(url: str, timeout_sec: int = 180, poll_interval: int = 10) -> Optional[dict]:
    """Отправляет URL на сканирование и ждёт результата.
    
    Для стабильности:
    - Делает 3 попытки получить результат с увеличивающимися интервалами
    - Проверяет полноту данных (минимум 5 запросов или наличие page.domains)
    - Возвращает только проверенный результат
    """
    payload = json.dumps({"url": url}).encode("utf-8")
    result = urlscan_request("POST", URLSCAN_SCAN, payload)

    if result is None:
        return None

    if result.get("message") != "Submission successful":
        log(f"Ошибка отправки: {result}", "red")
        return None

    uuid = result["uuid"]
    log(f"Scan ID: {uuid} — ожидание (timeout: {timeout_sec}с)...", "cyan")

    # Результат urlscan.io становится доступен через ~60 секунд
    result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
    
    start = time.time()
    retries = 0
    min_polls_before_check = 8  # Минимум опросов перед проверкой полноты (~80с)
    max_empty_results = 3  # Максимум пустых результатов подряд
    
    while time.time() - start < timeout_sec:
        retries += 1
        remaining = int(timeout_sec - (time.time() - start))
        log(f"  Опрос #{retries} (осталось ~{remaining}с)...", "yellow")
        time.sleep(poll_interval)

        data = urlscan_request("GET", result_url)

        if data is None:
            continue

        # Проверяем, есть ли данные
        if "requests" not in data and "page" not in data:
            log(f"  Ответ без данных: {list(data.keys())[:5]}", "yellow")
            continue

        # Проверяем полноту данных
        request_count = len(data.get("requests", []))
        has_page_domains = bool(data.get("page", {}).get("domains"))
        has_lists = bool(data.get("lists", {}).get("domains"))
        total_domains = len(data.get("lists", {}).get("domains", []))
        
        log(f"  Данные: {request_count} запросов, page.domains={has_page_domains}, lists.domains={has_lists} ({total_domains} доменов)", "cyan")
        
        # Результат считается полным если:
        # - есть lists.domains (это самый полный источник) — возвращаем сразу
        if has_lists and total_domains > 0:
            log(f"  Результат полон через lists.domains! ({total_domains} доменов)", "green")
            return data
        
        # - прошло достаточно времени (>= min_polls_before_check опросов)
        # - есть хотя бы 5 запросов ИЛИ есть page.domains
        if retries >= min_polls_before_check and (request_count >= 5 or has_page_domains):
            log(f"  Результат проверен и полон! ({request_count} запросов)", "green")
            return data
        
        # Если прошло 80% времени и данные есть — возвращаем
        elapsed_ratio = (time.time() - start) / timeout_sec
        if elapsed_ratio > 0.8 and (request_count > 0 or has_page_domains or has_lists):
            log(f"  Прошло 80% времени, возвращаем что есть ({request_count} запросов, {total_domains} доменов)", "yellow")
            return data

    log(f"Таймаут ({timeout_sec}с) после {retries} опросов", "red")
    return None


# --- Domain Extraction ---
def add_domains(source: dict, found: dict, exclude: Set[str]):
    """
    Извлекает уникальные домены исключительно из готового агрегированного 
    массива lists.domains ответа urlscan.io.
    """
    if not isinstance(source, dict):
        return

    # Получаем плоский массив всех зафиксированных доменов
    domains_list = source.get("lists", {}).get("domains", [])
    
    if isinstance(domains_list, list):
        for raw_domain in domains_list:
            if raw_domain and isinstance(raw_domain, str):
                # Очищаем от пробелов и отсекаем порт, если он есть (например, "domain.com:443" -> "domain.com")
                domain = raw_domain.strip().lower().split(':')[0]
                
                # Записываем, если домена нет в белом списке
                if domain and domain not in exclude:
                    found[domain] = True


def write_adblock(found: dict):
    sorted_domains = sorted(found.keys())
    new_entries = []

    # Читаем существующие домены
    existing = set()
    if ADBLOCK_FILE.exists():
        for line in ADBLOCK_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    existing.add(parts[1].lower())

    for domain in sorted_domains:
        if domain.lower() not in existing:
            new_entries.append(f"0.0.0.0 {domain}")

    if not new_entries:
        log("Новых доменов не найдено", "yellow")
        return

    with open(ADBLOCK_FILE, "a", encoding="utf-8") as f:
        f.write("\n" + "\n".join(new_entries) + "\n")
    log(f"Добавлено {len(new_entries)} доменов в {ADBLOCK_FILE}", "green")


# --- Main ---
def main():
    log("=== AdBlock Generator (urlscan.io) ===", "green")

    # Загрузка URL
    url_file = DEFAULT_URL_FILE
    if len(sys.argv) > 1:
        url_file = Path(sys.argv[1])
    if not url_file.exists():
        log(f"Файл не найден: {url_file}", "red")
        sys.exit(1)

    urls = [ensure_scheme(line.strip()) for line in url_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    log(f"Загружено {len(urls)} URL из {url_file}", "green")

    # Параметры
    scan_timeout = 180
    poll_interval = 60

    if len(sys.argv) > 2:
        scan_timeout = int(sys.argv[2])
    if len(sys.argv) > 3:
        poll_interval = int(sys.argv[3])

    log(f"Параметры: timeout={scan_timeout}с, poll={poll_interval}с", "cyan")

    # Загружаем whitelist
    whitelist = load_whitelist()
    if whitelist:
        log(f"Whitelist загружена: {len(whitelist)} доменов", "cyan")

    found: Dict[str, bool] = {}
    seed_domains: Set[str] = set()

    for start_url in urls:
        seed_host = urllib.parse.urlparse(start_url).netloc
        seed_domains.add(seed_host)
        exclude = seed_domains | whitelist
        log(f"\n{'='*60}", "cyan")
        log(f"Обработка: {start_url}", "green")

        # 1. URLScan — пробуем новый скан
        result = send_to_urlscan(start_url, scan_timeout, poll_interval)
        if result:
            add_domains(result, found, exclude)
            log(f"  Доменов найдено: {len(found)}", "green")
        else:
            log("  Новый скан не удался — ищем существующие...", "yellow")
            # Fallback: ищем существующие сканы домена
            # Берём 5 последних сканов и объединяем данные для максимальной полноты
            existing = urlscan_request("GET", f"{URLSCAN_SEARCH}?q=domain:{seed_host}&size=5&sort=-@time")
            if existing:
                hits = existing.get("hits", {}).get("hits", [])
                if hits:
                    log(f"  Найдено {len(hits)} существующих сканов, объединяем данные...", "cyan")
                    for hit in hits:
                        source = hit.get("_source", {})
                        # Считаем только если в скане есть данные
                        if source and (source.get("requests") or source.get("page")):
                            old_count = len(found)
                            add_domains(source, found, exclude)
                            new_count = len(found)
                            if new_count > old_count:
                                log(f"    Добавлено {new_count - old_count} доменов", "green")
                            else:
                                log(f"    Нет новых доменов", "yellow")
                    log(f"  Объединённый результат, всего доменов: {len(found)}", "green")
                else:
                    log("  Существующих сканов не найдено", "yellow")
            else:
                log("  Ошибка поиска существующих сканов", "red")
        time.sleep(DELAY_SEC)

    log(f"{'='*60}", "green")
    log(f"Найдено уникальных доменов: {len(found)}", "green")
    write_adblock(found)
    log("=== Готово ===", "green")


if __name__ == "__main__":
    main()
