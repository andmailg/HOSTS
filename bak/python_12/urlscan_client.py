import asyncio
import time
import re
from urllib.parse import urlparse
import aiohttp
from config import URLSCAN_SCAN, URLSCAN_RESULT, SCAN_TIMEOUT, POLL_INTERVAL, USER_AGENT
from filters import get_apex_domain, should_block_domain, AD_TRACKER_PATTERNS, SYSTEM_ASSETS_PATTERNS

def process_scan_json(raw_data):
    if not raw_data or not isinstance(raw_data, dict): return {}, {}
    requests_list = raw_data.get("data", {}).get("requests", [])
    if not requests_list: return {}, {}

    clean_domains, new_ad_domains, domain_verdicts = {}, {}, {}
    
    # ИСПРАВЛЕНО: Безопасное последовательное отсечение параметров и хэшей от URL документа
    raw_doc_url = raw_data.get("page", {}).get("url", "")
    doc_url = raw_doc_url.split('?')[0].split('#')[0]
    page_apex = get_apex_domain(doc_url)

    for item in requests_list:
        req_url = item.get("request", {}).get("request", {}).get("url")
        if not req_url or req_url.startswith("data:"): continue
        
        # ИСПРАВЛЕНО: Сначала берем первый элемент списка, затем применяем методы строки .lower().strip()
        try: req_domain = urlparse(req_url).netloc.split(':')[0].lower().strip()
        except Exception: continue
        if not req_domain: continue
        
        req_apex = get_apex_domain(req_url)
        initiator_type = item.get("request", {}).get("initiator", {}).get("type", "other")
        mime_type = item.get("response", {}).get("response", {}).get("mimeType", "").lower()

        if req_domain not in domain_verdicts: domain_verdicts[req_domain] = {"clean_score": 0, "ad_score": 0}
        
        if any(re.search(p, req_url, re.IGNORECASE) for p in AD_TRACKER_PATTERNS): domain_verdicts[req_domain]["ad_score"] += 30
        elif any(re.search(p, req_url, re.IGNORECASE) for p in SYSTEM_ASSETS_PATTERNS): domain_verdicts[req_domain]["clean_score"] += 20
            
        if page_apex and req_apex == page_apex: domain_verdicts[req_domain]["clean_score"] += 12
        else: domain_verdicts[req_domain]["ad_score"] += 6
        if initiator_type == "parser": domain_verdicts[req_domain]["clean_score"] += 5
        elif initiator_type == "script": domain_verdicts[req_domain]["ad_score"] += 6

        if page_apex and req_apex != page_apex:
            if mime_type in ["application/javascript", "text/javascript", "application/x-javascript"]: domain_verdicts[req_domain]["ad_score"] += 15
            elif mime_type in ["image/gif", "image/png"] and initiator_type == "script": domain_verdicts[req_domain]["ad_score"] += 8
            elif mime_type in ["font/woff2", "text/css"] and initiator_type != "script": domain_verdicts[req_domain]["clean_score"] += 10

    for domain, score in domain_verdicts.items():
        if should_block_domain(domain, page_apex=page_apex, score=score): new_ad_domains[domain] = score
        else: clean_domains[domain] = score
    return new_ad_domains, clean_domains

async def submit_url_to_scan(target_url, api_key, session):
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT, "x-api-key": api_key}
    try:
        async with session.post(URLSCAN_SCAN, headers=headers, json={"url": target_url, "visibility": "public"}, timeout=aiohttp.ClientTimeout(total=30), ssl=False) as response:
            if response.status == 429:
                await asyncio.sleep(60)
                return await submit_url_to_scan(target_url, api_key, session)
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

async def process_single_url(target_url, api_key, session, semaphore, hosts_lock, all_new_domains, all_clean_domains, failed_urls):
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
            print(f"[{target_url}] Отправка на сканирование... [TIMEOUT] | Ссылка: https://urlscan.io{uuid}/", flush=True)
            async with hosts_lock: 
                failed_urls.add(target_url)
            return {"status": False, "url": target_url, "uuid": uuid}
            
        # 3. Успешное завершение: парсим домены и выводим статус вместе с постоянной ссылкой
        print(f"[{target_url}] Отправка на сканирование... [SUCCESS] | Ссылка: https://urlscan.io{uuid}/", flush=True)
        
        new_domains, clean_domains = process_scan_json(scan_data)
        async with hosts_lock:
            if new_domains: all_new_domains.update(new_domains)
            if clean_domains: all_clean_domains.update(clean_domains)
            
        return {"status": True, "url": target_url, "uuid": uuid}

