#!/usr/bin/env python3
"""blacklist_analyzer.py — Модуль фильтрации и генерации блек-листа рекламных доменов

Содержит функции для:
- Проверки доменов на принадлежность к seed-доменам
- Извлечения рекламных доменов из данных urlscan.io с фильтрацией
- Записи отфильтрованных доменов в файл hosts_auto.txt
"""

from pathlib import Path
from typing import Set

# Импорт для доступа к whitelist
import whitelist_analyzer

# --- Config ---
ADBLOCK_FILE = Path(__file__).parent / "hosts_auto.txt"


def is_seed_or_subdomain(domain: str, seed_domains: Set[str]) -> bool:
    """Проверяет, является ли домен seed-доменом или его поддоменом."""
    domain = domain.lower()
    for seed in seed_domains:
        if domain == seed or domain.endswith(f".{seed}"):
            return True
    return False


def add_domains(source: dict, found: dict, exclude: Set[str], seed_domains: Set[str]):
    """
    Извлекает уникальные домены исключительно из готового агрегированного 
    массива lists.domains ответа urlscan.io.
    Исключает домены из whitelist и seed-домены (включая поддомены).
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
                
                # Записываем, если домена нет в белом списке и он не seed-домен/поддомен
                if domain and domain not in exclude and not is_seed_or_subdomain(domain, seed_domains):
                    found[domain] = True


def write_adblock(found: dict):
    """Записывает найденные рекламные домены в hosts_auto.txt."""
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
        whitelist_analyzer.log("Новых доменов не найдено", "yellow")
        return

    with open(ADBLOCK_FILE, "a", encoding="utf-8") as f:
        f.write("\n" + "\n".join(new_entries) + "\n")
    
    whitelist_analyzer.log(f"Добавлено {len(new_entries)} доменов в {ADBLOCK_FILE}", "green")
