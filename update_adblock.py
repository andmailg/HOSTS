import os
import re
import sys
import time
from datetime import datetime, timedelta

import certifi
import requests

# ====================== НАСТРОЙКИ ======================
API_KEY = os.getenv("URLSCAN_API_KEY")
OUTPUT_FILE = "adblock_auto.txt"
CLEAN_OUTPUT_FILE = "adblock_clean.txt"
DAYS_TO_KEEP = 30

QUERY = '(task.tags:"ads" OR task.tags:"tracking") AND date:>now-24h'

TLD_REGEX = re.compile(r"\.(ru|com|net)$", re.IGNORECASE)
KEYWORDS_REGEX = re.compile(r"(ad|ads|analytics|metrics|tracker|telemetry)", re.IGNORECASE)

WHITELIST = {"google.", "yandex.", "vk.com", "mail.ru", "urlscan.io", "github."}
ADBLOCK_SYNTAX_REGEX = re.compile(r"^\|\|[a-z0-9\-\.]+\.(ru|com|net)\^$")

# =====================================================


def fetch_urlscan_domains():
    """Безопасно запрашивает свежие рекламные и трекерные домены"""
    domains = set()

    try:
        headers = {
            "User-Agent": "andmailg-HOSTS-tracker-updater/2.3",
            "X-API-Key": API_KEY or "",
        }

        # ЕДИНСТВЕННЫЙ надёжный эндпоинт (всегда работает)
        params = {
            "q": QUERY,
            "size": 100,
        }

        response = requests.get(
            "https://urlscan.io/api/v1/search/",
            headers=headers,
            params=params,
            timeout=30,
            verify=certifi.where(),
        )

        # Обработка ошибок API
        if response.status_code == 429:
            print("❌ Превышен лимит запросов (429).")
            sys.exit("API Rate Limit exceeded")

        if response.status_code in (401, 403):
            print(f"❌ Ошибка авторизации ({response.status_code}). Проверьте URLSCAN_API_KEY!")
            sys.exit(f"Authorization failed ({response.status_code})")

        if response.status_code != 200:
            print(f"❌ API вернул код {response.status_code}")
            print("Сервер ответил:")
            print(response.text[:500])
            sys.exit(f"Unexpected API response: {response.status_code}")

        if "application/json" not in response.headers.get("Content-Type", ""):
            print("❌ Ожидался JSON, получен HTML!")
            print("--- НАЧАЛО ОТВЕТА ---")
            print(response.text[:300])
            print("--- КОНЕЦ ОТВЕТА ---")
            sys.exit("Invalid content type")

        data = response.json()

        for result in data.get("results", []):
            page = result.get("page", {})
            domain = page.get("domain")

            if domain:
                domain = domain.lower().strip()

                # Проверяем зоны
                if "." in domain and TLD_REGEX.search(domain):
                    if KEYWORDS_REGEX.search(domain):
                        if not any(whitelisted in domain for whitelisted in WHITELIST):
                            domains.add(domain)

    except requests.exceptions.RequestException as e:
        print(f"❌ Сетевая ошибка: {e}")
        sys.exit(f"Network error: {e}")
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        sys.exit(f"Critical error: {e}")

    return domains


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
                    tracked_domains[domain] = date_str

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