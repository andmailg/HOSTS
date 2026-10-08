import os
import re
import sys
import time
from datetime import datetime, timedelta

import requests

# ====================== НАСТРОЙКИ ======================
API_KEY = os.getenv("URLSCAN_API_KEY")
OUTPUT_FILE = "adblock_auto.txt"
CLEAN_OUTPUT_FILE = "adblock_clean.txt"
DAYS_TO_KEEP = 30
DEBUG_MODE = os.getenv("URLSCAN_DEBUG", "").lower() in ("1", "true", "yes")
URLS_FILE = "urls.txt"

# Ключевые слова для фильтрации рекламных/трекерных доменов
KEYWORDS = [
    # Рекламные сети
    "adsense", "adserv", "adnetwork", "adserver", "adtech",
    "doubleclick", "googlesyndication", "googleadservices",
    "googleads", "adfox", "adroll", "adspeed", "adswizz",
    "adsystem", "adtarget", "adtelligence",
    "adadvisor", "adblade", "addthis",
    "adform", "adgeneration", "adhese", "adikteev",
    "adkernel", "admeld", "admixer",
    "admon", "adnami", "adnetics", "adnotch",
    "adreactor", "adreporting", "adriver",
    "adscale", "adsdk",
    "adskeeper", "adsnative", "adsupply",
    "adsymptotic", "adtelligent", "adthrive",
    "adtilt", "adtng", "adtrace", "adtraction",
    "adtrue", "adunit", "adview", "adwatch",
    "adwork", "adworld", "adxpansion", "adxpremium",
    "admatic", "admost", "adnanny", "adobe-target",
    "adpone", "adreacts",
    # Аналитика и трекинг
    "analytics", "analytic", "trackclick", "trackeur",
    "trackme", "tracknet", "trackdis", "tracker",
    "trackers", "tracking", "telemetry", "telemet",
    "metricle", "metrilo", "metrics", "monitor",
    "beacon", "pixel", "retarget", "retargeting",
    # Рекламные технологии
    "campaign", "advertising", "advert", "monetiz",
    "popunder", "popads", "popcash", "propeller",
    "pushnotif", "push-notification", "pushengage",
    "invitemedia", "trafficjunky", "exoclick",
    "clickadhoc", "monetag", "adsterra", "plugrush",
    "richmedia", "media.net", "revcontent", "outbrain",
    "taboola", "contentabc", "recommended",
    # Российские рекламные сети
    "al-ads", "al-adtech", "advantag", "adriver",
    "bidvolution", "buzzoola", "kinja", "gstat",
    "gstatic", "yastatic", "yandexads",
    "sberads", "sbermarket",
]

KEYWORDS_REGEX = re.compile(r"(" + "|".join(re.escape(k) for k in KEYWORDS) + r")", re.IGNORECASE)

# Легитимные домены, которые всегда исключаем
WHITELIST = {
    "google.", "yandex.", "vk.com", "mail.ru", "urlscan.io", "github.",
    "microsoft.", "amazon.", "cloudflare.", "akamai.", "fastly.",
    "facebook.", "twitter.", "linkedin.", "apple.", "cdn.",
    "doubleclick.", "googlesyndication.", "googleadservices.",
    "googletagmanager.", "google-analytics.", "adservice.",
    "godaddy.", "namecheap.", "registrar.",
    "mta-sts.", "smtp.", "mail.", "email.",
    "rf.gd", "netlify.app", "vercel.app", "pages.dev",
    "azurestaticapps.net", "firebaseapp.com",
    "wordpress.", "wixsite.", "square.space",
    "canadapost", "post-bancogalicia",
    "apple-academy", "hallmeadschool",
    "tomtom.com", "orbis.tomtom",
    "stagingplatform",
}

ADBLOCK_SYNTAX_REGEX = re.compile(r"^\|\|[a-z0-9\.\-]+\^$")


def load_target_domains():
    """Загружает целевые домены из urls.txt"""
    targets = []
    if not os.path.exists(URLS_FILE):
        print(f"⚠️ Файл {URLS_FILE} не найден.")
        return targets

    with open(URLS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                targets.append(domain)

    print(f"📋 Целевые домены ({len(targets)}): {', '.join(targets)}")
    return targets


def get_scan_uuid(target):
    """Ищет UUID последнего скана целевого домена"""
    headers = {
        "User-Agent": "andmailg-HOSTS-tracker-updater/2.3",
        "X-API-Key": API_KEY or "",
    }
    
    try:
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{target}", "size": 1, "sort": "-time"},
            headers=headers,
            timeout=30,
        )
        
        if r.status_code == 200:
            data = r.json()
            if data.get("results"):
                return data["results"][0]["_id"]
    except Exception as e:
        print(f"  ⚠️ Ошибка поиска UUID: {e}")
    
    return None


def fetch_scan_resources(scan_uuid):
    """Получает все загруженные ресурсы из скана"""
    headers = {
        "User-Agent": "andmailg-HOSTS-tracker-updater/2.3",
        "X-API-Key": API_KEY or "",
    }
    
    domains = set()
    
    try:
        # Получаем данные скана
        r = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_uuid}/",
            headers=headers,
            timeout=60,
        )
        
        if r.status_code == 403:
            print("  ⚠️ 403: нужен API ключ для доступа к результатам")
            return domains
        
        if r.status_code != 200:
            print(f"  ⚠️ Ошибка получения скана: {r.status_code}")
            return domains
        
        scan_data = r.json()
        
        # Извлекаем все запросы
        requests_data = scan_data.get("requests", [])
        print(f"  📊 Найдено запросов: {len(requests_data)}")
        
        for req in requests_data:
            request_info = req.get("request", {})
            response_info = req.get("response", {})
            
            url = request_info.get("url", "")
            method = request_info.get("method", "")
            domain = request_info.get("domain", "")
            
            if not url and not domain:
                continue
            
            # Извлекаем домен из URL
            if not domain:
                match = re.match(r'https?://([^/]+)', url)
                if match:
                    domain = match.group(1).lower()
            
            if domain:
                domains.add(domain)
        
        print(f"  ✅ Уникальных доменов из скана: {len(domains)}")
        
    except Exception as e:
        print(f"  ❌ Ошибка: {e}")
    
    return domains


def filter_ad_domains(domains):
    """Фильтрует рекламные/трекерные домены"""
    ad_domains = set()
    
    for domain in domains:
        domain = domain.lower().strip()
        
        if not domain or "." not in domain or len(domain) < 5:
            continue
        
        # Пропускаем из whitelist
        if any(whitelisted in domain for whitelisted in WHITELIST):
            continue
        
        # Проверяем ключевые слова
        if KEYWORDS_REGEX.search(domain):
            ad_domains.add(domain)
    
    return ad_domains


def is_valid_domain(domain):
    """Проверяет домен по ключевым словам и whitelist"""
    domain = domain.lower().strip()
    if not domain or "." not in domain or len(domain) < 5:
        return False
    if not KEYWORDS_REGEX.search(domain):
        return False
    if any(whitelisted in domain for whitelisted in WHITELIST):
        return False
    return True


def main():
    today_str = time.strftime("%Y-%m-%d")
    cutoff_date = datetime.now() - timedelta(days=DAYS_TO_KEEP)

    # Загружаем целевые домены
    targets = load_target_domains()
    if not targets:
        print("❌ Нет целевых доменов в urls.txt")
        sys.exit("No target domains found")

    all_ad_domains = set()
    
    for target in targets:
        target = target.strip().lower()
        if not target:
            continue
        
        print(f"\n🔍 Обработка: {target}")
        
        # Получаем UUID скана
        scan_uuid = get_scan_uuid(target)
        if not scan_uuid:
            print(f"  ⚠️ Сканы не найдены")
            continue
        
        print(f"  UUID скана: {scan_uuid}")
        
        # Получаем ресурсы скана
        scan_domains = fetch_scan_resources(scan_uuid)
        
        # Фильтруем рекламные
        ad_domains = filter_ad_domains(scan_domains)
        print(f"  🎯 Рекламных/трекерных: {len(ad_domains)}")
        
        all_ad_domains.update(ad_domains)
    
    print(f"\n📊 Итого рекламных доменов: {len(all_ad_domains)}")
    
    if not all_ad_domains:
        print("⚠️ Рекламные домены не найдены")
        return
    
    # Загружаем старые записи
    tracked_domains = {}
    old_filtered = 0
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("||") and " ! " in line:
                    parts = line.split(" ! ", 1)
                    if len(parts) != 2:
                        continue
                    rule, date_str = parts
                    domain = rule[2:-1]
                    if not domain:
                        continue
                    try:
                        datetime.strptime(date_str, "%Y-%m-%d")
                    except ValueError:
                        date_str = today_str
                    if is_valid_domain(domain):
                        tracked_domains[domain] = date_str
                    else:
                        old_filtered += 1

    print(f"🗑️ Отфильтровано старых: {old_filtered}")

    # Обновляем дату
    for domain in all_ad_domains:
        tracked_domains[domain] = today_str

    # Фильтруем по возрасту
    active_domains = {}
    removed_count = 0
    for domain, last_seen in tracked_domains.items():
        if datetime.strptime(last_seen, "%Y-%m-%d") >= cutoff_date:
            active_domains[domain] = last_seen
        else:
            removed_count += 1

    # Валидация синтаксиса
    invalid_rules = [f"||{d}^" for d in active_domains if not ADBLOCK_SYNTAX_REGEX.match(f"||{d}^")]
    if invalid_rules:
        print(f"❌ Ошибка валидации: {invalid_rules[:5]}")
        sys.exit("Invalid rules detected")

    # Запись adblock файлов
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Target Ads & Trackers Blocklist (With Metadata)\n")
        f.write(f"! Last Updated: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"! Active domains: {len(active_domains)}\n\n")
        for domain in sorted(active_domains.keys()):
            f.write(f"||{domain}^ ! {active_domains[domain]}\n")

    with open(CLEAN_OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Target Ads & Trackers Blocklist (Clean Version)\n")
        f.write(f"! Last Updated: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"! Total domains: {len(active_domains)}\n\n")
        for domain in sorted(active_domains.keys()):
            f.write(f"||{domain}^\n")

    # Генерация hosts-файла
    HOSTS_FILE = "hosts_adblock.txt"
    with open(HOSTS_FILE, "w", encoding="utf-8") as f:
        f.write("# Target Ads & Trackers Blocklist (Hosts format)\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"# Total domains: {len(active_domains)}\n\n")
        f.write("127.0.0.1 localhost\n")
        f.write("::1 localhost\n\n")
        for domain in sorted(active_domains.keys()):
            f.write(f"127.0.0.1 {domain}\n")

    print(f"✅ Успешно обновлено!")
    print(f"   Активных доменов: {len(active_domains)}")
    print(f"   Удалено старых: {removed_count}")
    print(f"   Файлы: {OUTPUT_FILE}, {CLEAN_OUTPUT_FILE}, {HOSTS_FILE}")


if __name__ == "__main__":
    main()
