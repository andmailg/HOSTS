#!/usr/bin/env python3
"""whitelist_analyzer.py — Модуль анализа доменов и работы с whitelist.txt

Загружает whitelist, извлекает apex-домены, анализирует JSON-данные urlscan.io
и фильтрует рекламные домены с учётом белого списка.
"""

import json
import re
import time
from pathlib import Path
from typing import Set, Dict, Any, Optional
from urllib.parse import urlparse

try:
    import tldextract
except ImportError:
    tldextract = None


# --- Config ---
WHITELIST_FILE = Path(__file__).parent / "whitelist.txt"

# --- Mime-типы ---
CLEAN_MIME_TYPES = {"text/html", "image/svg+xml", "font/woff2"}
AD_MIME_TYPES = {"application/javascript", "text/javascript", "image/gif"}


# --- Logging ---
def log(msg: str, color: str = "white"):
    """Выводит сообщение с цветовой маркировкой."""
    colors = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m", "cyan": "\033[96m", "white": "\033[97m"}
    reset = "\033[0m"
    prefix = f"\033[90m{time.strftime('%H:%M:%S')}\033[0m"
    print(f"{prefix} {colors.get(color, '')}{msg}{reset}")


def load_whitelist() -> Set[str]:
    """Загружает белый список доменов из whitelist.txt."""
    whitelist: Set[str] = set()
    if WHITELIST_FILE.exists():
        for line in WHITELIST_FILE.read_text(encoding="utf-8").splitlines():
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                whitelist.add(domain)
    return whitelist


def get_apex_domain(url: Optional[str]) -> Optional[str]:
    """Извлекает apex-домен (например, 'fontanka.ru' из 'https://hsmedia.ru...')"""
    if not url or url.startswith("data:"):
        return None

    if tldextract is None:
        # Fallback: простая извлечение без tldextract
        parsed = urlparse(url)
        netloc = parsed.netloc.split(":")[0].lower()
        parts = netloc.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return netloc if netloc else None

    extracted = tldextract.extract(url)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return None


def analyze_domains(json_file_path: str, whitelist: Optional[Set[str]] = None) -> Dict[str, Set[str]]:
    """Анализирует JSON-файл urlscan.io и возвращает чистые и рекламные домены.

    Args:
        json_file_path: Путь к JSON-файлу с данными urlscan.io
        whitelist: Белый список доменов (если None, загружается из файла)

    Returns:
        Словарь с ключами "clean" и "ad", каждый содержит Set[str]
    """
    if whitelist is None:
        whitelist = load_whitelist()

    # Загружаем файл данных
    with open(json_file_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    requests_list = raw_data.get("data", {}).get("requests", [])

    clean_domains: Set[str] = set()
    ad_domains: Set[str] = set()

    for item in requests_list:
        # urlscan.io иногда дублирует структуру или содержит вложенные массивы запросов
        # Извлекаем основной запрос
        req_entry = item.get("request", {})
        resp_entry = item.get("response", {})

        # 1. Определяем базовый/целевой домен страницы
        doc_url = req_entry.get("documentURL")
        page_apex = get_apex_domain(doc_url)

        # Переходим к параметрам конкретного сетевого запроса
        network_req = req_entry.get("request", {})
        req_url = network_req.get("url")

        if not req_url or req_url.startswith("data:"):
            continue

        req_domain = urlparse(req_url).netloc.split(":")[0].lower()
        req_apex = get_apex_domain(req_url)

        # Извлекаем тип инициатора и Mime-Type
        initiator_type = req_entry.get("initiator", {}).get("type", "other")
        mime_type = resp_entry.get("response", {}).get("mimeType", "").lower()

        # Если mimeType пустой в response, попробуем поискать в заголовках
        if not mime_type:
            headers = resp_entry.get("response", {}).get("headers", {})
            # Приводим ключи заголовков к нижнему регистру для надежности
            headers_low = {k.lower(): v for k, v in headers.items()}
            content_type = headers_low.get("content-type", "")
            mime_type = content_type.split(";")[0].strip()

        # --- ЛОГИКА ФИЛЬТРАЦИИ ---

        is_clean = False

        # Правило 1: Совпадение Apex-домена с целевым сайтом
        if page_apex and req_apex == page_apex:
            is_clean = True

        # Правило 3: Запрос инициирован парсером (до того, как начали выполняться JS-рекламные скрипты)
        elif initiator_type == "parser":
            is_clean = True

        # Правило 2: Анализ Mime-типов (если тип контента строго не-рекламный)
        elif mime_type in CLEAN_MIME_TYPES:
            is_clean = True

        # Дополнительная проверка на явные рекламные маркеры
        # (Рекламные Mime-типы на чужих доменах)
        if mime_type in AD_MIME_TYPES and req_apex != page_apex:
            is_clean = False

        # Распределяем результат
        if is_clean:
            if req_domain not in ad_domains:
                clean_domains.add(req_domain)
        else:
            ad_domains.add(req_domain)
            if req_domain in clean_domains:
                clean_domains.remove(req_domain)

    # Фильтрация по whitelist: убираем из ad_domains домены из whitelist
    if whitelist:
        ad_domains -= whitelist
        clean_domains |= whitelist

    return {
        "clean": clean_domains,
        "ad": ad_domains,
    }


def print_results(results: Dict[str, Set[str]]):
    """Выводит результаты анализа в консоль."""
    clean_domains = results.get("clean", set())
    ad_domains = results.get("ad", set())

    print(f"--- НАЙДЕНО НЕ-РЕКЛАМНЫХ ДОМЕНОВ ({len(clean_domains)}) ---")
    for domain in sorted(clean_domains):
        print(f"[Чистый] {domain}")

    print(f"\n--- НАЙДЕНО РЕКЛАМНЫХ/ТРЕКИНГОВЫХ ДОМЕНОВ ({len(ad_domains)}) ---")
    for domain in sorted(ad_domains):
        print(f"[Реклама] {domain}")


if __name__ == "__main__":
    import sys

    json_file = sys.argv[1] if len(sys.argv) > 1 else "your_file.json"
    results = analyze_domains(json_file)
    print_results(results)
