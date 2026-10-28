import asyncio
import time
import re
from urllib.parse import urlparse
import aiohttp
from config import URLSCAN_SCAN, URLSCAN_RESULT, SCAN_TIMEOUT, POLL_INTERVAL, USER_AGENT
from filters import get_apex_domain, should_block_domain, url_is_strong_ad, url_is_tracker, url_is_system_asset

def collect_scan_verdicts(raw_data):
    """
    Разбор одного JSON-результата urlscan. Возвращает (domain_verdicts, page_apex):
    СЫРЫЕ очки по каждому хосту без вердикта «реклама/нет» — решение принимается позже по всей сессии
    (classify_session), иначе результат зависит от того, на какой странице хост попался.
    """
    if not raw_data or not isinstance(raw_data, dict): return {}, None
    requests_list = raw_data.get("data", {}).get("requests", [])
    if not requests_list: return {}, None

    domain_verdicts = {}

    # Безопасное последовательное отсечение параметров и хэшей от URL документа
    raw_doc_url = raw_data.get("page", {}).get("url", "")
    doc_url = raw_doc_url.split('?')[0].split('#')[0]
    page_apex = get_apex_domain(doc_url)

    for item in requests_list:
        req_url = item.get("request", {}).get("request", {}).get("url")
        if not req_url or req_url.startswith("data:"): continue

        try: req_domain = urlparse(req_url).netloc.split(':')[0].lower().strip()
        except Exception: continue
        if not req_domain: continue

        req_apex = get_apex_domain(req_url)
        initiator_type = item.get("request", {}).get("initiator", {}).get("type") or "other"
        mime_type = (item.get("response", {}).get("response", {}).get("mimeType") or "").lower()

        if req_domain not in domain_verdicts:
            domain_verdicts[req_domain] = {"clean_score": 0, "ad_score": 0, "strong": 0, "pages": 1, "own_site": False}
        v = domain_verdicts[req_domain]

        # Признаки в самом URL. «strong» — специфичные рекламные пути/параметры (pagead, openrtb, usersync, gdpr=...),
        # именно они отличают рекламу от обычного стороннего скрипта (CDN, виджет, API).
        if url_is_strong_ad(req_url):
            v["ad_score"] += 40
            v["strong"] += 1
        elif url_is_tracker(req_url): v["ad_score"] += 30
        elif url_is_system_asset(req_url): v["clean_score"] += 20

        if page_apex and req_apex == page_apex:
            v["clean_score"] += 12
            v["own_site"] = True
        else: v["ad_score"] += 6
        # Подключённый парсером СКРИПТ стороннего домена — это обычно рекламный тег, а не «чистый» ресурс:
        # бонус +5 к clean даём только за не-JS ресурсы (картинки, css, шрифты, документы).
        is_js = mime_type in ("application/javascript", "text/javascript", "application/x-javascript")
        if initiator_type == "parser":
            if not is_js or (page_apex and req_apex == page_apex): v["clean_score"] += 5
        elif initiator_type == "script": v["ad_score"] += 6

        if page_apex and req_apex != page_apex:
            if mime_type in ["application/javascript", "text/javascript", "application/x-javascript"]: v["ad_score"] += 15
            elif mime_type in ["image/gif", "image/png"] and initiator_type == "script": v["ad_score"] += 8
            elif mime_type in ["font/woff2", "text/css"] and initiator_type != "script": v["clean_score"] += 10

    return domain_verdicts, page_apex

def merge_scan_verdicts(session_stats, page_verdicts):
    """Суммирует очки страницы в общую статистику сессии (раньше результат последней страницы затирал предыдущие)."""
    for d, v in page_verdicts.items():
        s = session_stats.setdefault(d, {"clean_score": 0, "ad_score": 0, "strong": 0, "pages": 0, "own_site": False})
        s["clean_score"] += v["clean_score"]
        s["ad_score"] += v["ad_score"]
        s["strong"] += v.get("strong", 0)
        s["pages"] += 1
        s["own_site"] = s["own_site"] or v["own_site"]

def process_scan_json(raw_data):
    """Классификация ОДНОЙ страницы (для отладки/обратной совместимости). Для сессии используйте
    collect_scan_verdicts + merge_scan_verdicts + filters.classify_session."""
    verdicts, page_apex = collect_scan_verdicts(raw_data)
    new_ad_domains, clean_domains = {}, {}
    for domain, score in verdicts.items():
        if should_block_domain(domain, page_apex=page_apex, score=score): new_ad_domains[domain] = score
        else: clean_domains[domain] = score
    return new_ad_domains, clean_domains

async def submit_url_to_scan(target_url, api_key, session, _retries=3):
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT, "x-api-key": api_key}
    try:
        async with session.post(URLSCAN_SCAN, headers=headers, json={"url": target_url, "visibility": "public"}, timeout=aiohttp.ClientTimeout(total=30), ssl=False) as response:
            if response.status == 429:
                if _retries <= 0:
                    print(f"Лимит запросов (429), попытки исчерпаны: {target_url}")
                    return None
                await asyncio.sleep(60)
                return await submit_url_to_scan(target_url, api_key, session, _retries - 1)
            response.raise_for_status()
            return (await response.json()).get("uuid")
    except Exception as e: print(f"Ошибка отправки URL ({target_url}): {repr(e)}")
    return None

async def poll_scan_results(uuid, api_key, session):
    start_time = time.time()
    await asyncio.sleep(POLL_INTERVAL)
    while time.time() - start_time < SCAN_TIMEOUT:
        try:
            async with session.get(f"{URLSCAN_RESULT}{uuid}/", headers={"x-api-key": api_key}, timeout=aiohttp.ClientTimeout(total=20), ssl=False) as response:
                if response.status == 200: return await response.json()
                elif response.status != 404: response.raise_for_status()
        except Exception: pass
        await asyncio.sleep(POLL_INTERVAL)
    return None

async def process_single_url(target_url, api_key, session, semaphore, hosts_lock, domain_stats, failed_urls):
    async with semaphore:
        # 1. Отправляем URL на сканирование
        print(f"[{target_url}] Отправка на сканирование...", flush=True)
        uuid = await submit_url_to_scan(target_url, api_key, session)
        
        if not uuid:
            print(f"[{target_url}] Отправка на сканирование... [FAIL] (Не удалось получить UUID)", flush=True)
            async with hosts_lock: 
                failed_urls.add(target_url)
            return {"status": False, "url": target_url, "uuid": None}
            
        # 2. Опрашиваем API и ждем завершения анализа страницы
        scan_data = await poll_scan_results(uuid, api_key, session)
        
        if not scan_data:
            # Если urlscan.io не успел обработать страницу за отведенный таймаут
            print(f"[{target_url}] Отправка на сканирование... [TIMEOUT] | Ссылка: https://urlscan.io/result/{uuid}/", flush=True)
            async with hosts_lock: 
                failed_urls.add(target_url)
            return {"status": False, "url": target_url, "uuid": uuid}
            
        # 3. Успешное завершение: парсим домены и выводим статус вместе с постоянной ссылкой
        print(f"[{target_url}] Отправка на сканирование... [SUCCESS] | Ссылка: https://urlscan.io/result/{uuid}/", flush=True)
        
        verdicts, _ = collect_scan_verdicts(scan_data)
        async with hosts_lock:
            merge_scan_verdicts(domain_stats, verdicts)
            
        return {"status": True, "url": target_url, "uuid": uuid}

