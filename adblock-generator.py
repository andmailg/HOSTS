#!/usr/bin/env python3
"""adblock-generator.py — Обходит сайты через urlscan.io и наполняет adblock.txt"""

import sys
import re
import time
import json
import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional, List, Set, Dict, Any

# --- Config ---
ADBLOCK_FILE = Path(__file__).parent / "adblock_auto.txt"
DEFAULT_URL_FILE = Path(__file__).parent / "urls.txt"
URLSCAN_SCAN = "https://urlscan.io/api/v1/scan/"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdBlockBot/1.0"
DELAY_SEC = 3
API_KEY = "01a11b20-0d0f-72bc-a329-dfb6c8d04352"  # ← Вставь свой API ключ urlscan.io (получить на https://urlscan.io/user/profile/)


# --- Logging ---
def log(msg: str, color: str = "white"):
    colors = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m", "cyan": "\033[96m", "white": "\033[97m"}
    reset = "\033[0m"
    prefix = f"\033[90m{time.strftime('%H:%M:%S')}\033[0m"
    print(f"{prefix} {colors.get(color, '')}{msg}{reset}")


# --- URL Helpers ---
def get_base_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def is_same_site(url1: str, url2: str) -> bool:
    u1, u2 = urllib.parse.urlparse(url1), urllib.parse.urlparse(url2)
    return u1.netloc == u2.netloc and u1.scheme == u2.scheme


def ensure_scheme(url: str) -> str:
    """Добавляет https:// если схема отсутствует."""
    if re.match(r'^https?://', url, re.I):
        return url
    return f"https://{url}"


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def is_internal(link: str, base_url: str, seed_host: str) -> bool:
    if re.match(r'^(mailto:|javascript:|#|tel:)', link, re.I):
        return False
    if re.match(r'^https?://', link, re.I):
        if not is_same_site(link, base_url):
            return False
        return urllib.parse.urlparse(link).netloc == seed_host
    return True


# --- HTML Link Extractor ---
class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attrs_dict = dict(attrs)
            href = attrs_dict.get("href", "")
            if href:
                self.links.append(href)


def extract_links(html: str, base_url: str, seed_host: str) -> List[str]:
    parser = LinkExtractor()
    parser.feed(html)
    links = []
    for href in parser.links:
        href = re.sub(r'#.*$', '', href)
        if re.match(r'^https?://', href, re.I):
            if is_internal(href, base_url, seed_host):
                links.append(normalize_url(href))
        elif href.startswith("/"):
            links.append(f"{get_base_url(base_url)}{href}")
        else:
            links.append(f"{get_base_url(base_url)}/{href}")
    return links


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
    """Отправляет URL на сканирование и ждёт результата."""
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
    # Бесплатный аккаунт не поддерживает поиск по _id — используем result endpoint
    result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
    
    start = time.time()
    retries = 0
    while time.time() - start < timeout_sec:
        retries += 1
        remaining = int(timeout_sec - (time.time() - start))
        log(f"  Опрос #{retries} (осталось ~{remaining}с)...", "yellow")
        time.sleep(poll_interval)

        # Прямой запрос к result endpoint
        data = urlscan_request("GET", result_url)

        # 404 = скан ещё не готов — продолжаем опрос
        if data is None:
            continue

        # 200 — результат готов
        if "requests" in data or "page" in data:
            log(f"  Результат получен на опросе #{retries}! ({len(data.get('requests', []))} запросов)", "green")
            return data
        else:
            log(f"  Ответ без данных: {list(data.keys())[:5]}", "yellow")

    log(f"Таймаут ({timeout_sec}с) после {retries} опросов", "red")
    return None


# --- Domain Extraction ---
def extract_domains_from_url(url: str) -> Optional[str]:
    """Извлекает хост из URL."""
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return None


def add_domains(source: dict, found: dict):
    """Извлекает домены из результата urlscan.io (search или result API)."""
    # 1. request.domains — основной источник
    request = source.get("request", {})
    if isinstance(request, dict):
        for d in request.get("domains", []):
            if d:
                found[d.lower()] = True

        # request.url
        domain = extract_domains_from_url(request.get("url", ""))
        if domain:
            found[domain] = True

        # request.body — ищем домены в теле запроса
        body = request.get("body", "")
        if body:
            for m in re.finditer(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', body):
                d = m.group(1).lower()
                if d and not d.isdigit() and not d.endswith('.ru.') and not d.endswith('.com.'):
                    found[d] = True

    # 2. page.domains — домены страницы
    page = source.get("page", {})
    if isinstance(page, dict):
        for d in page.get("domains", []):
            if d:
                found[d.lower()] = True

        # page.url
        domain = extract_domains_from_url(page.get("url", ""))
        if domain:
            found[domain] = True

        # page.details.resources — URL ресурсов
        details = page.get("details", {})
        if isinstance(details, dict):
            for res_url in details.get("resources", []):
                domain = extract_domains_from_url(res_url)
                if domain:
                    found[domain] = True
    
    # 3. task — дополнительная информация
    task = source.get("task", {})
    if isinstance(task, dict):
        # task.url
        domain = extract_domains_from_url(task.get("url", ""))
        if domain:
            found[domain] = True
        
        # task.domain
        if task.get("domain"):
            found[task["domain"].lower()] = True
    
    # 4. requests — массив загруженных ресурсов
    requests_list = source.get("requests", [])
    if isinstance(requests_list, list):
        for req in requests_list:
            if isinstance(req, dict):
                # req.request.url
                req_info = req.get("request", {})
                if isinstance(req_info, dict):
                    url = req_info.get("url", "")
                    if url:
                        domain = extract_domains_from_url(url)
                        if domain:
                            found[domain] = True
                    # req.request.domain
                    if req_info.get("domain"):
                        found[req_info["domain"].lower()] = True


# --- Adblock File ---
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
    max_depth = 1
    max_pages = 50
    scan_timeout = 180
    poll_interval = 10

    if len(sys.argv) > 2:
        max_depth = int(sys.argv[2])
    if len(sys.argv) > 3:
        max_pages = int(sys.argv[3])
    if len(sys.argv) > 4:
        scan_timeout = int(sys.argv[4])
    if len(sys.argv) > 5:
        poll_interval = int(sys.argv[5])

    log(f"Параметры: depth={max_depth}, pages={max_pages}, timeout={scan_timeout}с, poll={poll_interval}с", "cyan")

    found: Dict[str, bool] = {}
    visited: Set[str] = set()
    seed_hosts: Set[str] = set()

    for start_url in urls:
        seed_host = urllib.parse.urlparse(start_url).netloc
        seed_hosts.add(seed_host)
        log(f"\n{'='*60}", "cyan")
        log(f"Обработка: {start_url}", "green")

        # 1. URLScan — пробуем новый скан
        result = send_to_urlscan(start_url, scan_timeout, poll_interval)
        if result:
            add_domains(result, found)
            log(f"  Доменов найдено: {len(found)}", "green")
        else:
            log("  Новый скан не удался — ищем существующие...", "yellow")
            # Fallback: ищем существующие сканы домена
            existing = urlscan_request("GET", f"{URLSCAN_SEARCH}?q=domain:{seed_host}&size=1&sort=-time")
            if existing:
                hits = existing.get("hits", {}).get("hits", [])
                if hits:
                    source = hits[0].get("_source", {})
                    add_domains(source, found)
                    log(f"  Найден существующий скан, доменов: {len(found)}", "green")
                else:
                    log("  Существующих сканов не найдено", "yellow")
            else:
                log("  Ошибка поиска существующих сканов", "red")
        time.sleep(DELAY_SEC)

        # 2. Crawling
        if max_depth > 0:
            log(f"Обход сайта {seed_host} (глубина до {max_depth})...", "cyan")
            visited.add(start_url)  # Исключаем дубль сканирования seed-URL
            queue = [(start_url, 0)]
            depth_map = {start_url: 0}
            processed = 0

            while queue and processed < max_pages:
                current, depth = queue.pop(0)
                if current in visited:
                    continue
                if depth_map.get(current, 0) > max_depth:
                    continue

                log(f"\n[{processed + 1}/{max_pages}] Глубина {depth}: {current}", "yellow")

                scan_result = send_to_urlscan(current, scan_timeout, poll_interval)
                if scan_result:
                    add_domains(scan_result, found)
                visited.add(current)
                processed += 1
                time.sleep(DELAY_SEC)

                if depth < max_depth:
                    base = get_base_url(current)
                    links = extract_links(current, base, seed_host)
                    for link in links:
                        if link not in visited and link not in depth_map:
                            depth_map[link] = depth + 1
                            queue.append((link, depth + 1))

            log(f"Обход завершён: {processed} страниц", "green")

    # Исключаем seed-домены (сам сканируемый сайт и его поддомены)
    filtered = {d: True for d in found if not any(d == sh or d.endswith('.' + sh) for sh in seed_hosts)}
    excluded = len(found) - len(filtered)
    if excluded:
        log(f"Исключено seed-доменов: {excluded}", "yellow")

    log(f"{'='*60}", "green")
    log(f"Найдено уникальных доменов: {len(found)} (после фильтрации: {len(filtered)})", "green")
    write_adblock(filtered)
    log("=== Готово ===", "green")


if __name__ == "__main__":
    main()
