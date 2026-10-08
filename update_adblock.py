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

# urlscan.io больше не присваивает теги "ads"/"tracking" — ищем по ключевым словам в домене
QUERY = "date:>now-7d"
PAGE_SIZE = 10000

# Ключевые слова для фильтрации доменов (реклама, трекеры, аналитика)
# Избегаем слишком коротких/общих (типа "ad", "track") — дают много ложных срабатываний
KEYWORDS = [
    # Рекламные сети и платформы
    "adsense", "adserv", "adnetwork", "adserver", "adtech",
    "doubleclick", "googlesyndication", "googleadservices",
    "googleads", "adfox", "adroll", "adspeed", "adswizz",
    "adsystem", "adtarget", "adtelligence",
    "adadvisor", "adblade", "adcolizon", "addthis",
    "adform", "adgeneration", "adhese", "adikteev",
    "adkernel", "adleade", "admeld", "admixer",
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
]

# Регулярка для поиска ключевых слов в домене
KEYWORDS_REGEX = re.compile(r"(" + "|".join(re.escape(k) for k in KEYWORDS) + r")", re.IGNORECASE)

# Легитимные домены/поддомены, которые всегда исключаем
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
# Валидация adblock-синтаксиса: ||domain^ — допускает любые TLD
ADBLOCK_SYNTAX_REGEX = re.compile(r"^\|\|[a-z0-9\.\-]+\^$")

# =====================================================


def fetch_urlscan_domains():
    """Собирает домены из urlscan.io и фильтрует по ключевым словам"""
    domains = set()
    total_scanned = 0
    matched = 0

    try:
        headers = {
            "User-Agent": "andmailg-HOSTS-tracker-updater/2.3",
            "X-API-Key": API_KEY or "",
        }

        url = "https://urlscan.io/api/v1/search/"
        verify_ssl = True

        # Запрашиваем все публичные сканы за последние 30 дней
        params = {
            "q": QUERY,
            "size": PAGE_SIZE,
        }

        # Функция для выполнения запроса с SSL fallback
        def do_request(url, params, headers):
            nonlocal verify_ssl
            try:
                return requests.get(url, headers=headers, params=params, timeout=60, verify=True)
            except requests.exceptions.SSLError as ssl_err:
                print("⚠️ SSL-проверка не удалась (возможно, корпоративный антивирус).")
                print("   Повторная попытка без проверки сертификата...")
                try:
                    resp = requests.get(url, headers=headers, params=params, timeout=60, verify=False)
                    verify_ssl = False
                    return resp
                except requests.exceptions.SSLError:
                    print("❌ SSL-ошибка при повторной попытке.")
                    sys.exit(f"SSL error (both verified and unverified failed): {ssl_err}")

        # Paginated request — urlscan.io возвращает has_more + search_after
        import time as _time
        page_num = 0
        max_pages = 5  # максимум страниц (при PAGE_SIZE=10000 должно хватить 1-2)
        while page_num < max_pages:
            response = do_request(url, params, headers)
            page_num += 1

            # Обработка ошибок API
            if response.status_code == 429:
                wait_time = 60
                print(f"⏳ Лимит запросов (429). Ждём {wait_time} сек...")
                _time.sleep(wait_time)
                page_num -= 1  # не считаем этот запрос
                continue

            if response.status_code in (401, 403):
                print(f"❌ Ошибка авторизации ({response.status_code}). Проверьте URLSCAN_API_KEY!")
                sys.exit(f"Authorization failed ({response.status_code})")

            if response.status_code != 200:
                print(f"❌ API вернул код {response.status_code}")
                print(response.text[:500])
                sys.exit(f"Unexpected API response: {response.status_code}")

            if "application/json" not in response.headers.get("Content-Type", ""):
                print("❌ Ожидался JSON, получен HTML!")
                sys.exit("Invalid content type")

            data = response.json()
            results = data.get("results", [])
            total = data.get("total", 0)
            has_more = data.get("has_more", False)

            if DEBUG_MODE:
                print(f"\n🔍 DEBUG page {page_num}: total={total}, returned={len(results)}, has_more={has_more}")
                print(f"🔍 DEBUG: verify_ssl={verify_ssl}")

            # Фильтрация результатов по ключевым словам
            for result in results:
                total_scanned += 1
                page = result.get("page", {})
                domain = page.get("domain")

                if not domain:
                    continue

                domain = domain.lower().strip()

                # Пропускаем пустые и слишком короткие домены
                if not domain or "." not in domain or len(domain) < 5:
                    continue

                # Проверяем ключевые слова
                if not KEYWORDS_REGEX.search(domain):
                    continue

                # Пропускаем из whitelist
                if any(whitelisted in domain for whitelisted in WHITELIST):
                    continue

                domains.add(domain)
                matched += 1

            if not has_more:
                break

            # Задержка между страницами
            _time.sleep(1)

            # Получаем search_after для следующей страницы
            last_result = results[-1]
            sort_val = last_result.get("sort")
            if not sort_val:
                print("⚠️ has_more=True, но нет sort для pagination. Остановка.")
                break

            # urlscan.io ожидает строку, join массива [timestamp, uuid]
            params["search_after"] = ",".join(str(s) for s in sort_val)

        print(f"📊 Просканировано доменов: {total_scanned}")
        print(f"🎯 Нашлось совпадений: {matched}")
        print(f"✅ Уникальных доменов: {len(domains)}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Сетевая ошибка: {e}")
        sys.exit(f"Network error: {e}")
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        sys.exit(f"Critical error: {e}")

    return domains


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

    print("🔄 Сбор свежих рекламных доменов из urlscan.io...")

    new_domains = fetch_urlscan_domains()
    if not new_domains:
        print("⚠️ Новые домены не найдены. Возможно, API изменил формат ответа.")
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
                    # Фильтруем старые домены по тем же правилам
                    if is_valid_domain(domain):
                        tracked_domains[domain] = date_str
                    else:
                        old_filtered += 1

    print(f"🗑️ Отфильтровано старых доменов: {old_filtered}")

    # Обновляем дату
    for domain in new_domains:
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

    # Запись файлов
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

    print(f"✅ Успешно обновлено!")
    print(f"   Активных доменов: {len(active_domains)}")
    print(f"   Удалено старых: {removed_count}")


if __name__ == "__main__":
    main()