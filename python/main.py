import asyncio
import sys
import os
import argparse
import re
from urllib.parse import urlparse

import aiohttp

from config import HOSTS_FILE, LOG_FILE, DEFAULT_URL_FILE, MAX_CONCURRENT, MAX_URLS_PER_SITE, MAX_DEPTH, TARGET_SCAN, get_api_key
from filters import should_block_domain, sort_domains_by_level, get_apex_domain, normalize_and_detect_dynamic_domain
from crawler import run_external_crawler_for_urls
from urlscan_client import process_single_url

def read_existing_hosts(file_path):
    """Считывает домены из текущего hosts-файла с нормализацией строк."""
    existing_domains = set()
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): 
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    # Извлекаем домен, очищаем от пробелов и приводим к нижнему регистру
                    domain = parts[1].strip().lower()
                    if domain: 
                        existing_domains.add(domain)
    return existing_domains

async def main_async():
    api_key = get_api_key()
    if not api_key: 
        print("Ошибка: Не найден API ключ URLSCAN_API_KEY.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="URLScan Scanner with SiteOne Crawler Integration")
    parser.add_argument("--crawl", action="store_true", help="Запустить краулер для углубленного сбора ссылок")
    parser.add_argument("--max-depth", type=int, default=MAX_DEPTH, help="Глубина краулера для каждого исходного сайта")
    parser.add_argument("--max-reqs-per-sec", type=int, default=1, help="Лимит запросов краулера в секунду")
    args = parser.parse_args()

    all_new_domains, all_clean_domains, failed_urls = {}, {}, set()
    url_to_uuid_map = {}
    crawl_relations = {}
    urls_to_scan = []
    success_count = 0
    fail_count = 0

    if DEFAULT_URL_FILE.exists():
        with DEFAULT_URL_FILE.open("r", encoding="utf-8") as f:
            seed_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    else:
        seed_urls = []

    if TARGET_SCAN:
        print(f"[Внимание] Обнаружен принудительный TARGET_SCAN: {TARGET_SCAN}. Обычный обход пропущен.")
        print(f"[{TARGET_SCAN}] Получение готовых результатов из URLScan...")
        
        from urlscan_client import poll_scan_results, process_scan_json
        
        async with aiohttp.ClientSession() as session:
            scan_data = await poll_scan_results(TARGET_SCAN, api_key, session)
            
        if scan_data:
            target_url = scan_data.get("page", {}).get("url", "Указанный UUID")
            print(f"[{TARGET_SCAN}] Результаты успешно получены для страницы: {target_url}")
            
            new_domains, clean_domains = process_scan_json(scan_data)
            if new_domains: all_new_domains.update(new_domains)
            if clean_domains: all_clean_domains.update(clean_domains)
            
            url_to_uuid_map[target_url] = {"uuid": TARGET_SCAN, "status": True}
            crawl_relations[target_url] = [target_url]
            seed_urls = [target_url]
            success_count = 1
        else:
            print(f"Ошибка: Не удалось получить данные для UUID {TARGET_SCAN}.")
            sys.exit(1)
    else:
        if not seed_urls:
            print(f"Файл '{DEFAULT_URL_FILE}' пуст или отсутствует. Нечего обрабатывать.")
            sys.exit(0)

        is_crawl_active = args.crawl or MAX_DEPTH != 0

        if is_crawl_active:
            current_depth = args.max_depth if args.max_depth != 0 else 1
            all_crawled_urls = await run_external_crawler_for_urls(
                seed_urls, 
                max_depth=current_depth, 
                max_reqs=args.max_reqs_per_sec,
                max_urls_per_seed=MAX_URLS_PER_SITE
            )
            
            for seed in seed_urls:
                normalized_seed = seed if seed.startswith(('http://', 'https://')) else f'https://{seed}'
                seed_domain = urlparse(normalized_seed).netloc.lower()
                seed_apex = get_apex_domain(normalized_seed)
                
                if "dzen.ru" in normalized_seed:
                    crawled_for_seed = [u for u in all_crawled_urls if "dzen.ru/a/" in u or "dzen.ru/news/show/" in u]
                    if not crawled_for_seed:
                        crawled_for_seed = [normalized_seed]
                    crawl_relations[seed] = crawled_for_seed[:MAX_URLS_PER_SITE]
                
                elif "mail.ru" in seed_domain or "sportmail.ru" in seed_domain:
                    crawled_for_seed = [u for u in all_crawled_urls if urlparse(u).netloc.lower() == seed_domain]
                    deep_articles = [u for u in crawled_for_seed if urlparse(u).path not in ["", "/"]]
                    if deep_articles: crawled_for_seed = deep_articles
                    if not crawled_for_seed: crawled_for_seed = [normalized_seed]
                    crawl_relations[seed] = crawled_for_seed[:MAX_URLS_PER_SITE]
                    
                elif seed_apex in ["gazeta.ru", "kp.ru"]:
                    crawled_for_seed = [u for u in all_crawled_urls if get_apex_domain(u) == seed_apex]
                    deep_articles = [u for u in crawled_for_seed if urlparse(u).path not in ["", "/"]]
                    if deep_articles: 
                        crawled_for_seed = deep_articles
                        
                    if not crawled_for_seed: 
                        crawled_for_seed = [normalized_seed]
                    crawl_relations[seed] = crawled_for_seed[:MAX_URLS_PER_SITE]

                elif seed_apex == "rosbalt.ru":
                    crawled_for_seed = [u for u in all_crawled_urls if get_apex_domain(u) == "rosbalt.ru"]
                    deep_articles = [u for u in crawled_for_seed if urlparse(u).path not in ["", "/"]]
                    if deep_articles: crawled_for_seed = deep_articles
                    if not crawled_for_seed: crawled_for_seed = [normalized_seed]
                    crawl_relations[seed] = crawled_for_seed[:MAX_URLS_PER_SITE]
                    
                else:
                    crawled_for_seed = [u for u in all_crawled_urls if get_apex_domain(u) == seed_apex]
                    crawl_relations[seed] = crawled_for_seed[:MAX_URLS_PER_SITE] if crawled_for_seed else [normalized_seed]
        else:
            print("\n[Пул] Краулер отключен (MAX_DEPTH = 0). Будут отправлены только исходные адреса.")
            for seed in seed_urls:
                normalized_seed = seed if seed.startswith(('http://', 'https://')) else f'https://{seed}'
                crawl_relations[seed] = [normalized_seed]

        urls_to_scan = list(set(url for sublist in crawl_relations.values() for url in sublist))
        print(f"[Пул] Подготовлено уникальных страниц для URLScan API: {len(urls_to_scan)}")

        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(MAX_CONCURRENT)
            hosts_lock = asyncio.Lock()
            tasks = [
                process_single_url(u, api_key, session, semaphore, hosts_lock, all_new_domains, all_clean_domains, failed_urls) 
                for u in urls_to_scan
            ]
            scan_raw_results = await asyncio.gather(*tasks, return_exceptions=True)
            
        for r in scan_raw_results:
            if isinstance(r, dict):
                url_to_uuid_map[r["url"]] = {"uuid": r["uuid"], "status": r["status"]}
                if r["status"]: 
                    success_count += 1

        fail_count = len(urls_to_scan) - success_count

    # =========================================================================
    # СБОРКА И ФИНАЛЬНАЯ ЗАПИСЬ HOSTS И ЛОГОВ (ОБНОВЛЕННАЯ ЛОГИКА)
    # =========================================================================
    # 1. Считываем старые заблокированные домены
    existing_domains = read_existing_hosts(str(HOSTS_FILE))
    
    # 2. Фильтруем СТАРЫЕ домены по ОБНОВЛЕННЫМ правилам (без учета старого скоринга)
    # Если по новым правилам домен теперь разрешен, он НЕ попадет в valid_existing_ad
    valid_existing_ad = {d for d in existing_domains if should_block_domain(d, score=None)}
    
    # 3. Фильтруем НОВЫЕ домены, полученные в текущей сессии (с учетом их свежего скоринга)
    current_session_ad = {d for d, s in all_new_domains.items() if should_block_domain(d, score=s)}
    
    # 4. Объединяем валидные старые и новые рекламные домены
    raw_combined = valid_existing_ad.union(current_session_ad)
    
    # 5. Нормализуем объединенный список (схлопываем динамические хэши)
    normalized_combined = set()
    for d in raw_combined:
        is_dyn, norm_d = normalize_and_detect_dynamic_domain(d)
        normalized_combined.add(norm_d)
        
    # 6. Финальная контрольная фильтрация очищенного списка
    filtered_ad_domains = {d for d in normalized_combined if should_block_domain(d, score=all_new_domains.get(d))}
    
    # 7. Сортировка и запись в файл hosts
    sorted_ad_domains = sort_domains_by_level(filtered_ad_domains)
    
    with open(HOSTS_FILE, "w", encoding="utf-8") as h_file:
        for domain in sorted_ad_domains: 
            h_file.write(f"0.0.0.0 {domain}\n")
    
    total_total = len(urls_to_scan) if not TARGET_SCAN else 1
    log_lines = [
        "="*60, "ЛОГ АНАЛИЗА URLSCAN (CRAWLER MAP)", "="*60, 
        f"Всего обработано подстраниц: {success_count}/{total_total} • Сбои: {fail_count}/{total_total}", ""
    ]
    
    log_lines.append("--- ИДЕНТИФИКАТОРЫ СЕССИЙ URLSCAN (ГРУППИРОВКА) ---")
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
