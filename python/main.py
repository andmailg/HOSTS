import asyncio
import sys
import os
import argparse
from urllib.parse import urlparse

import aiohttp

from config import HOSTS_FILE, LOG_FILE, DEFAULT_URL_FILE, MAX_CONCURRENT, MAX_DEPTH, TARGET_SCAN, get_api_key
from filters import should_block_domain, sort_domains_by_level
from crawler import run_external_crawler_for_urls
from urlscan_client import process_single_url

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

async def main_async():
    api_key = get_api_key()
    if not api_key: 
        print("Ошибка: Не найден API ключ URLSCAN_API_KEY.")
        sys.exit(1)

    # Настройка парсера аргументов командной строки
    parser = argparse.ArgumentParser(description="URLScan Scanner with SiteOne Crawler Integration")
    parser.add_argument("--crawl", action="store_true", help="Запустить краулер для углубленного сбора ссылок")
    parser.add_argument("--max-depth", type=int, default=MAX_DEPTH, help="Глубина краулера для каждого исходного сайта")
    parser.add_argument("--max-reqs-per-sec", type=int, default=1, help="Лимит запросов краулера в секунду")
    args = parser.parse_args()

    # Считываем исходный файл с адресами (seed URLs)
    if not DEFAULT_URL_FILE.exists(): 
        print(f"Ошибка: Исходный файл '{DEFAULT_URL_FILE}' не найден.")
        sys.exit(1)
        
    with DEFAULT_URL_FILE.open("r", encoding="utf-8") as f:
        seed_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not seed_urls:
        print(f"Файл '{DEFAULT_URL_FILE}' пуст. Нечего обрабатывать.")
        sys.exit(0)

    if TARGET_SCAN:
        print(f"[Внимание] Обнаружен принудительный TARGET_SCAN: {TARGET_SCAN}. Обычный обход пропущен.")

    # --- Выбор режима работы и сбор ссылок ---
    # Автоматическая проверка: если MAX_DEPTH из config.py не равен 0, принудительно включаем краулер
    is_crawl_active = args.crawl or MAX_DEPTH != 0
    
    # Словарь для связи исходного URL и ссылок, которые из него достал краулер
    crawl_relations = {}

    if is_crawl_active:
        # Режим 1: Работа с чистым Python-краулером без использования внешних .exe и Node.js утилит
        current_depth = args.max_depth if args.max_depth != 0 else 1
        
        # Получаем плоский список всех собранных ссылок
        all_crawled_urls = run_external_crawler_for_urls(seed_urls, max_depth=current_depth, max_reqs=args.max_reqs_per_sec)
        
        # Заполняем связи для логов
        for seed in seed_urls:
            normalized_seed = seed if seed.startswith(('http://', 'https://')) else f'https://{seed}'
            seed_domain = urlparse(normalized_seed).netloc
            
            # СПЕЦИАЛЬНАЯ ЛОГИКА ДЛЯ ДЗЕНА:
            # Если сид является сюжетом Дзена, забираем из общего пула все ссылки, которые НЕ принадлежат другим сидам
            if "dzen.ru" in normalized_seed:
                other_seeds_domains = {urlparse(s if s.startswith(('http://', 'https://')) else f'https://{s}').netloc for s in seed_urls if "dzen.ru" not in s}
                crawled_for_seed = [u for u in all_crawled_urls if urlparse(u).netloc not in other_seeds_domains and urlparse(u).netloc != seed_domain]
                # Если краулер ничего не достал, оставим сам Дзен
                if not crawled_for_seed:
                    crawled_for_seed = [normalized_seed]
            else:
                # Стандартная логика для обычных сайтов (строгое совпадение домена)
                crawled_for_seed = [u for u in all_crawled_urls if urlparse(u).netloc == seed_domain]
            
            # Ограничиваем количество подстраниц до 2 штук (как у вас в конфиге)
            crawl_relations[seed] = crawled_for_seed[:2] if crawled_for_seed else [normalized_seed]
    else:
        # Режим 2: Прямая отправка без краулера (MAX_DEPTH == 0 и флаг --crawl отсутствует)
        print("\n[Пул] Краулер отключен (MAX_DEPTH = 0). Будут отправлены только исходные адреса.")
        for seed in seed_urls:
            normalized_seed = seed if seed.startswith(('http://', 'https://')) else f'https://{seed}'
            crawl_relations[seed] = [normalized_seed]

    # Создаем плоский список уникальных URL для отправки по API
    urls_to_scan = list(set(url for sublist in crawl_relations.values() for url in sublist))
    print(f"[Пул] Подготовлено уникальных страниц для URLScan API: {len(urls_to_scan)}")

    # --- Асинхронная отправка пула собранных ссылок в URLScan ---
    all_new_domains, all_clean_domains, failed_urls = {}, {}, set()

    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        hosts_lock = asyncio.Lock()
        tasks = [
            process_single_url(u, api_key, session, semaphore, hosts_lock, all_new_domains, all_clean_domains, failed_urls) 
            for u in urls_to_scan
        ]
        scan_raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        
    # Формируем карту результатов для быстрого поиска UUID по URL подстраницы
    url_to_uuid_map = {}
    success_count = 0
    for r in scan_raw_results:
        if isinstance(r, dict):
            url_to_uuid_map[r["url"]] = {"uuid": r["uuid"], "status": r["status"]}
            if r["status"]: 
                success_count += 1

    fail_count = len(urls_to_scan) - success_count

    # --- СБОРКА И ФИНАЛЬНАЯ ЗАПИСЬ HOSTS ---
    existing_domains = read_existing_hosts(str(HOSTS_FILE))
    filtered_ad_domains = {d for d in existing_domains.union(all_new_domains.keys()) if should_block_domain(d)}
    sorted_ad_domains = sort_domains_by_level(filtered_ad_domains)
    
    with open(HOSTS_FILE, "w", encoding="utf-8") as h_file:
        for domain in sorted_ad_domains: 
            h_file.write(f"0.0.0.0 {domain}\n")
    
    # --- СБОРКА И ЗАПИСЬ ФАЙЛА СТРУКТУРИРОВАННЫХ ЛОГОВ ---
    log_lines = [
        "="*60, "ЛОГ АНАЛИЗА URLSCAN (CRAWLER MAP)", "="*60, 
        f"Всего отправлено подстраниц: {success_count}/{len(urls_to_scan)} • Сбои: {fail_count}/{len(urls_to_scan)}", ""
    ]
    
    # Секция древовидной группировки Исходник -> Подстраницы -> UUID
    log_lines.append("--- ИДЕНТИФИКАТОРЫ СЕССИЙ С КРАУЛЕРОМ (ГРУППИРОВКА) ---")
    for s_idx, seed in enumerate(seed_urls, 1):
        log_lines.append(f"\n{s_idx:02d}. [SEED] {seed}")
        sub_urls = crawl_relations.get(seed, [])
        
        for u_idx, sub_url in enumerate(sub_urls, 1):
            scan_info = url_to_uuid_map.get(sub_url, {"uuid": "Не отправлялся", "status": False})
            marker = "[OK]" if scan_info["status"] else "[FAIL]"
            log_lines.append(f"    ├── {u_idx:02d}. {marker} {sub_url}")
            log_lines.append(f"    └── UUID: {scan_info['uuid']}")
            
    log_lines.append("\n" + "="*60)
    
    final_ad_log, final_clean_log = {}, {}
    merged_scans = {**all_clean_domains, **all_new_domains}
    
    for d, s in merged_scans.items():
        if should_block_domain(d, score=s): 
            final_ad_log[d] = s
        else: 
            final_clean_log[d] = s

    if final_ad_log:
        log_lines.append("--- ДОБАВЛЕННЫЕ РЕКЛАМНЫЕ ДОМЕНЫ ---")
        for i, (d, s) in enumerate(sorted(final_ad_log.items()), 1): 
            log_lines.append(f"{i:02d}. [AD] {d:<40} (clean: {s['clean_score']}, ad: {s['ad_score']})")
            
    if final_clean_log:
        log_lines.append("\n--- ПРОПУЩЕННЫЕ ЛЕГИТИМНЫЕ ДОМЕНЫ ---")
        for i, (d, s) in enumerate(sorted(final_clean_log.items()), 1): 
            log_lines.append(f"{i:02d}. [OK] {d:<40} (clean: {s['clean_score']}, ad: {s['ad_score']})")

    with open(LOG_FILE, "w", encoding="utf-8") as f: 
        f.write("\n".join(log_lines))
        
    print(f"\nГотово! Результаты обработки сохранены в '{LOG_FILE}'")

if __name__ == "__main__":
    asyncio.run(main_async())
