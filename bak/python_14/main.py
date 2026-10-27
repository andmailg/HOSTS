import asyncio
import sys
import os
import argparse
import re
from urllib.parse import urlparse

import aiohttp

from config import HOSTS_FILE, LOG_FILE, DEFAULT_URL_FILE, MAX_CONCURRENT, MAX_URLS_PER_SITE, MAX_DEPTH, TARGET_SCAN, get_api_key
from filters import should_block_domain, sort_domains_by_level, get_apex_domain, normalize_and_detect_dynamic_domain, is_same_site, is_confident_ad, classify_session
from crawler import run_external_crawler_for_urls
from urlscan_client import process_single_url, collect_scan_verdicts, merge_scan_verdicts

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
    parser.add_argument("--max-depth", type=int, default=MAX_DEPTH, help="0 — отключить краулер и сканировать только сами сиды; любое другое значение — краулер включён (обход идёт на один уровень, глубина не используется)")
    parser.add_argument("--max-reqs-per-sec", type=int, default=1, help="Лимит запросов краулера в секунду")
    args = parser.parse_args()

    domain_stats, failed_urls = {}, set()   # очки всех страниц сессии суммируются в domain_stats
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
        
        from urlscan_client import poll_scan_results
        
        async with aiohttp.ClientSession() as session:
            scan_data = await poll_scan_results(TARGET_SCAN, api_key, session)
            
        if scan_data:
            target_url = scan_data.get("page", {}).get("url", "Указанный UUID")
            print(f"[{TARGET_SCAN}] Результаты успешно получены для страницы: {target_url}")
            
            verdicts, _ = collect_scan_verdicts(scan_data)
            merge_scan_verdicts(domain_stats, verdicts)
            
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

        is_crawl_active = args.crawl or args.max_depth != 0

        if is_crawl_active:
            all_crawled_urls = await run_external_crawler_for_urls(
                seed_urls, 
                max_reqs=args.max_reqs_per_sec
            )
            
            # =========================================================================
            # УНИВЕРСАЛЬНАЯ АВТОМАТИЧЕСКАЯ ГРУППИРОВКА ССЫЛОК ПО ИСХОДНЫМ САЙТАМ
            # =========================================================================
            for seed in seed_urls:
                normalized_seed = seed if seed.startswith(('http://', 'https://')) else f'https://{seed}'
                seed_apex = get_apex_domain(normalized_seed)
                
                if not seed_apex:
                    crawl_relations[seed] = [normalized_seed]
                    continue

                # 1. Отбираем только те ссылки, которые принадлежат этому же apex-домену
                # (связанные домены вроде sportmail.ru для mail.ru задаются в config.RELATED_APEXES)
                crawled_for_seed = [u for u in all_crawled_urls if is_same_site(u, seed_apex)]

                # 2. Фильтруем "глубокие" страницы (статьи), отсекая главную страницу и пустые хабы
                deep_articles = [u for u in crawled_for_seed if urlparse(u).path not in ["", "/"]]
                
                # Особое правило для Дзена: нам нужны только статьи (/a/) или новости (/news/show/)
                if seed_apex == "dzen.ru":
                    deep_articles = [u for u in crawled_for_seed if "/a/" in urlparse(u).path or "/news/show/" in urlparse(u).path]

                # Если нашли глубокие статьи — берем их, если нет — оставляем то, что нашли, либо сам seed
                final_urls = deep_articles if deep_articles else crawled_for_seed
                if not final_urls:
                    final_urls = [normalized_seed]

                # Ограничиваем количество подстраниц для одного сайта согласно лимитам из config
                crawl_relations[seed] = final_urls[:MAX_URLS_PER_SITE]
        else:
            print("\n[Пул] Краулер отключен (--max-depth 0). Будут отправлены только исходные адреса.")
            for seed in seed_urls:
                normalized_seed = seed if seed.startswith(('http://', 'https://')) else f'https://{seed}'
                crawl_relations[seed] = [normalized_seed]

        urls_to_scan = list(set(url for sublist in crawl_relations.values() for url in sublist))
        print(f"[Пул] Подготовлено уникальных страниц для URLScan API: {len(urls_to_scan)}")

        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(MAX_CONCURRENT)
            hosts_lock = asyncio.Lock()
            tasks = [
                process_single_url(u, api_key, session, semaphore, hosts_lock, domain_stats, failed_urls) 
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
    # СБОРКА И ФИНАЛЬНАЯ ЗАПИСЬ HOSTS И ЛОГОВ (ОБНОВЛЕННАЯ ЛОГИКА С NEED_REVIEW)
    # =========================================================================
    # 0. Единое решение по каждому домену на основе очков со ВСЕХ страниц (+ группировка реплик сервиса)
    all_new_domains, all_clean_domains = classify_session(domain_stats)

    # 1. Считываем старые заблокированные домены
    existing_domains = read_existing_hosts(str(HOSTS_FILE))
    
    # 2. Фильтруем СТАРЫЕ домены по ОБНОВЛЕННЫМ правилам (без учета старого скоринга)
    valid_existing_ad = {d for d in existing_domains if should_block_domain(d, score=None)}
    
    # 3. Фильтруем НОВЫЕ домены, полученные в текущей сессии 
    # ВАЖНО: В hosts идёт «строгий бан» (см. filters.is_confident_ad): clean_score == 0, ЛИБО
    # ad_score > clean_score*STRICT_BAN_RATIO + STRICT_BAN_MARGIN, ЛИБО явный чёрный список
    # (у ad.mail.ru на странице mail.ru clean_score > 0 из-за бонуса «свой apex», но это реклама)
    current_session_ad = {d for d, s in all_new_domains.items() if is_confident_ad(d, s)}
    
    # 4. Объединяем валидные старые и новые жесткие рекламные домены
    raw_combined = valid_existing_ad.union(current_session_ad)
    
    # 5. Нормализуем список (схлопываем динамические хэши)
    normalized_combined = set()
    for d in raw_combined:
        is_dyn, norm_d = normalize_and_detect_dynamic_domain(d)
        normalized_combined.add(norm_d)
        
    # 6. Финальная контрольная фильтрация для hosts (только явный бан)
    filtered_ad_domains = {
        d for d in normalized_combined 
        if should_block_domain(d, score=all_new_domains.get(d)) 
        and is_confident_ad(d, all_new_domains.get(d))
    }
    
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
            scan_info = url_to_uuid_map.get(sub_url, {"uuid": None, "status": False})
            marker = "[OK]" if scan_info["status"] else "[FAIL]"
            log_lines.append(f"    ├── {u_idx:02d}. {marker} {sub_url}")
            
            if scan_info["uuid"]:
                log_lines.append(f"    └── Ссылка: https://urlscan.io/result/{scan_info['uuid']}/")
            else:
                log_lines.append(f"    └── Ссылка: Не отправлялся / Ошибка")
            
    log_lines.append("\n" + "="*60)
    
    # Решение уже принято в classify_session: домен либо в ad, либо в clean (не в обоих сразу)
    final_ad_log, final_clean_log = all_new_domains, all_clean_domains

    def fmt_scores(s):
        extra = f", pages: {s.get('pages', 1)}"
        if s.get("group", 1) > 1: extra += f", группа x{s['group']}"
        if s.get("hint"): extra += ", name-hint"
        return f"(clean: {s['clean_score']}, ad: {s['ad_score']}{extra})"

    # ВЫВОД ЗАБЛОКИРОВАННЫХ ДОМЕНОВ С СЕПАРАЦИЕЙ НА ЖЕСТКИЙ BAN И NEED_REVIEW
    if final_ad_log:
        log_lines.append("--- ДОБАВЛЕННЫЕ РЕКЛАМНЫЕ ДОМЕНЫ ---")
        ad_counter = 1
        review_counter = 1
        
        # Сначала выводим чистый рекламный мусор (clean_score == 0)
        log_lines.append("\n[ КАТЕГОРИЯ: СТРОГИЙ БАН (100% РЕКЛАМА / ТРЕКЕРЫ) ]")
        for d, s in sorted(final_ad_log.items()):
            if is_confident_ad(d, s):
                log_lines.append(f"{ad_counter:02d}. [AD] {d:<40} {fmt_scores(s)}")
                ad_counter += 1
                
        # Затем выводим кандидатов на ручной разбор (заблокированы по скорингу, но есть заметные признаки полезности)
        log_lines.append("\n[ КАТЕГОРИЯ: КАНДИДАТЫ НА БЕЛЫЙ СПИСОК (ПЛЕЕРЫ/ВИДЖЕТЫ?) ]")
        for d, s in sorted(final_ad_log.items()):
            if not is_confident_ad(d, s):
                log_lines.append(f"{review_counter:02d}. [NEED_REVIEW] {d:<40} {fmt_scores(s)} -> Обрати внимание!")
                review_counter += 1
            
    if final_clean_log:
        log_lines.append("\n--- НЕ ЗАБЛОКИРОВАНО В ЭТОМ ЗАПУСКЕ (недостаточно признаков рекламы; это не гарантия легитимности) ---")
        for i, (d, s) in enumerate(sorted(final_clean_log.items()), 1): 
            log_lines.append(f"{i:02d}. [OK] {d:<40} {fmt_scores(s)}")

    with open(LOG_FILE, "w", encoding="utf-8") as f: 
        f.write("\n".join(log_lines))
    
    print("\n" + "=" * 60)
    print("ПОДРОБНЫЙ ЛОГ (log.txt):")
    print("=" * 60)
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        print(f.read())
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main_async())
