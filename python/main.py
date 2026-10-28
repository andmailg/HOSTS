import asyncio
import sys
import os
import argparse
import re
from urllib.parse import urlparse

import aiohttp

from config import HOSTS_FILE, ADBLOCK_FILE, LOG_FILE, DEFAULT_URL_FILE, MAX_CONCURRENT, MAX_URLS_PER_SITE, MAX_DEPTH, TARGET_SCAN, get_api_key
from filters import should_block_domain, sort_domains_by_level, get_apex_domain, normalize_and_detect_dynamic_domain, is_same_site, classify_session
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

def finalize_domains(domain_stats, existing_domains):
    """
    Сборка итогового списка. Возвращает (final_domains, ad_log, review_log, clean_log).
      ad_log     — домены, заблокированные по итогам текущей сессии (идут в hosts);
      review_log — спорные: НЕ блокируются, показываются в логе для ручного решения;
      clean_log  — не заблокированы.
    final_domains = (прежние записи hosts, прошедшие перепроверку) + (BLOCK текущей сессии), схлопнутые
    через normalize_and_detect_dynamic_domain и перепроверенные.
    """
    # 0. Единое решение по каждому домену на основе очков со ВСЕХ страниц (+ группировка реплик сервиса)
    ad_log, review_log, clean_log = classify_session(domain_stats)

    # 1. Старые записи hosts перепроверяем по ОБНОВЛЁННЫМ правилам (score=None — статистики нет)
    valid_existing_ad = {d for d in existing_domains if should_block_domain(d, score=None)}

    # 2. Объединяем со ВСЕМИ BLOCK-решениями текущей сессии (раньше часть из них отсекалась
    #    «строгим баном» и оседала в NEED_REVIEW, то есть реклама оставалась незаблокированной)
    raw_combined = valid_existing_ad | set(ad_log)

    # 3. Схлопываем одноразовые хэш-поддомены (hosts не умеет wildcard)
    normalized = set()
    for d in raw_combined:
        _, norm_d = normalize_and_detect_dynamic_domain(d)
        normalized.add(norm_d)

    # 4. Контрольная перепроверка только для схлопнутых/старых имён: у них нет статистики,
    #    а у BLOCK-решений сессии она уже учтена в classify_session
    final = {d for d in normalized if d in ad_log or should_block_domain(d, score=None)}
    return sort_domains_by_level(final), ad_log, review_log, clean_log

def minimize_for_adblock(domains):
    """Для adblock.txt правило ||domain^ уже покрывает все поддомены — вложенные записи не нужны."""
    domain_set = set(domains)
    result = []
    for d in domains:
        labels = d.split(".")
        if any(".".join(labels[i:]) in domain_set for i in range(1, len(labels) - 1)):
            continue
        result.append(d)
    return result

def write_hosts_and_adblock(domains):
    """hosts.txt (0.0.0.0 домен, каждый хост явно: wildcard в hosts нет) и adblock.txt
    (||домен^ — в синтаксисе AdGuard/uBlock блокирует домен и все его поддомены, в том числе хэш-хосты)."""
    with open(HOSTS_FILE, "w", encoding="utf-8") as h_file:
        for domain in domains:
            h_file.write(f"0.0.0.0 {domain}\n")
    with open(ADBLOCK_FILE, "w", encoding="utf-8") as a_file:
        a_file.write("! Title: HOSTS adblock (auto-generated)\n! Каждое правило блокирует домен и ВСЕ его поддомены\n")
        for domain in minimize_for_adblock(domains):
            a_file.write(f"||{domain}^\n")

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
    # СБОРКА И ФИНАЛЬНАЯ ЗАПИСЬ HOSTS / ADBLOCK И ЛОГОВ
    # =========================================================================
    existing_domains = read_existing_hosts(str(HOSTS_FILE))
    sorted_ad_domains, all_new_domains, all_review_domains, all_clean_domains = finalize_domains(domain_stats, existing_domains)
    write_hosts_and_adblock(sorted_ad_domains)

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
    
    # Решение уже принято в classify_session: домен ровно в одной из трёх категорий
    def fmt_scores(s):
        extra = f", pages: {s.get('pages', 1)}"
        if s.get("strong"): extra += f", strong: {s['strong']}"
        if s.get("group", 1) > 1: extra += f", группа x{s['group']}"
        if s.get("hint"): extra += ", name-hint"
        return f"(clean: {s['clean_score']}, ad: {s['ad_score']}{extra})"

    log_lines.append("--- ЗАБЛОКИРОВАНО В ЭТОМ ЗАПУСКЕ (hosts.txt / adblock.txt) ---")
    for i, (d, s) in enumerate(sorted(all_new_domains.items()), 1):
        log_lines.append(f"{i:02d}. [AD] {d:<40} {fmt_scores(s)}")
    log_lines.append(f"\nИтого в hosts.txt: {len(sorted_ad_domains)} доменов (с учётом прежних записей и схлопнутых хэш-поддоменов)")

    if all_review_domains:
        log_lines.append("\n--- НА РУЧНОЙ РАЗБОР (НЕ заблокированы: похоже на рекламу, но блок может сломать сайт/плеер) ---")
        log_lines.append("Решение: реклама -> добавить в AD_APEX_BLACKLIST / EXTRA_BLACKLIST_PATTERNS (filters.py); легитимный -> оставить.")
        for i, (d, s) in enumerate(sorted(all_review_domains.items()), 1):
            log_lines.append(f"{i:02d}. [REVIEW] {d:<40} {fmt_scores(s)}")

    if all_clean_domains:
        log_lines.append("\n--- НЕ ЗАБЛОКИРОВАНО В ЭТОМ ЗАПУСКЕ (недостаточно признаков рекламы; это не гарантия легитимности) ---")
        for i, (d, s) in enumerate(sorted(all_clean_domains.items()), 1):
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
