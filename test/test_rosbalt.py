import re
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup
from bs4.element import Tag
from playwright.sync_api import sync_playwright, Error as PlaywrightError

# =====================================================================
# НАСТРОЙКИ СКРИПТА
# =====================================================================
START_URL = "https://rosbalt.ru"
MAX_ARTICLES = 5          # None — обработать все найденные статьи
PAUSE_SECONDS = 2         # Пауза между запросами (лучше поставить 2-3 для стабильности)
PAGE_TIMEOUT_MS = 30_000

# Режим работы браузера: 
# False — для локальной отладки (видно окно браузера)
# True  — для работы в фоне / на сервере (Docker, Linux CLI)
HEADLESS_MODE = True  
# =====================================================================


def is_rosbalt_host(hostname):
    """Проверяет, относится ли адрес к rosbalt.ru."""
    hostname = (hostname or "").lower().removeprefix("www.")
    return hostname == "rosbalt.ru" or hostname.endswith(".rosbalt.ru")


def is_excluded_external_host(hostname):
    """Домены, которые не нужно добавлять в результат."""
    hostname = (hostname or "").lower().removeprefix("www.")
    excluded = (
        "yandex.ru",
        "yastatic.net",
        "google.com",
        "googletagmanager.com",
        "google-analytics.com",
    )
    return any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in excluded
    )


def clean_url(url):
    """Удаляет query-параметры и фрагмент URL."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def is_interstitial_page(html):
    """Быстро распознаёт промежуточную заглушку без парсинга DOM."""
    html_lower = html.lower()
    return (
        'name="robots" content="noindex, noarchive"' in html_lower
        and "gorizontal-vertikal" in html_lower
        and "data:image/gif;base64," in html_lower
    )


def find_article_body(soup):
    """
    Ищет основной текст статьи.
    Проверяет микроразметку itemprop и специфичные для Росбалта классы.
    """
    body = soup.select_one('[itemprop="articleBody"]')
    if body:
        return body

    candidates = soup.select("div.content-blocks.kind-common")
    if candidates:
        return max(
            candidates,
            key=lambda element: len(element.get_text(" ", strip=True)),
        )

    return None


def print_possible_article_containers(soup):
    """Выводит структуру страницы, если основной текст не был найден."""
    print("[DEBUG] Текст не найден. Возможные контейнеры на странице:")
    candidates = soup.select(
        "article, main, [class*='text'], [class*='content'], [class*='article']"
    )
    seen = set()
    for element in candidates[:15]:
        classes = " ".join(element.get("class", []))
        text_length = len(element.get_text(" ", strip=True))
        key = (element.name, classes, element.get("id", ""))
        if key not in seen and text_length > 0:
            seen.add(key)
            print(f"  <{element.name} class={classes!r} id={element.get('id', '')!r} длина_текста={text_length}>")


def debug_rosbalt_two_levels(start_url):
    article_pattern = re.compile(r"^/news/\d{4}-\d{2}-\d{2}/.+-\d+/?$")

    print("=" * 70)
    print(f"1-Й УРОВЕНЬ: Загрузка главной страницы {start_url}")
    print("=" * 70)

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=HEADLESS_MODE)
            
            context = None
            try:
                # Настройка чистых заголовков для мимикрии под обычного пользователя
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    locale="ru-RU",
                    extra_http_headers={"Accept-Language": "ru,en;q=0.9"}
                )
                page = context.new_page()

                response = page.goto(start_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                page.wait_for_timeout(4000)  # Даем время на выполнение внутренних скриптов сайта

                html = page.content()
                soup = BeautifulSoup(html, "html.parser")

                print(f"[DEBUG] HTTP Статус: {response.status if response else 'Нет ответа'}")
                print(f"[DEBUG] Реальный URL: {page.url}")
                print(f"[DEBUG] Title: {page.title()}")

                if is_interstitial_page(html):
                    print("[ОШИБКА] Обнаружена страница-заглушка (noindex). Сбор остановлен.")
                    return

                # Сбор ссылок на статьи
                article_urls = []
                seen_articles = set()

                for tag in soup.find_all("a", href=True):
                    full_url = urljoin(page.url, str(tag["href"]))
                    parts = urlsplit(full_url)

                    if parts.scheme not in ("http", "https") or not is_rosbalt_host(parts.hostname):
                        continue
                    if not article_pattern.match(parts.path):
                        continue

                    clean = clean_url(full_url)
                    if clean not in seen_articles:
                        seen_articles.add(clean)
                        article_urls.append(clean)

                print(f"[ИНФО] Всего валидных ссылок на статьи найдено: {len(article_urls)}")
                urls_to_process = article_urls if MAX_ARTICLES is None else article_urls[:MAX_ARTICLES]

                external_links = set()
                processed_articles = 0

                print("\n" + "=" * 70)
                print("2-Й УРОВЕНЬ: Извлечение внешних ссылок из найденных статей")
                print("=" * 70)

                for article_url in urls_to_process:
                    print(f"\n[Обработка страницы] {article_url}")
                    time.sleep(PAUSE_SECONDS)

                    try:
                        page.goto(article_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                        page.wait_for_timeout(2000)

                        article_html = page.content()
                        
                        if is_interstitial_page(article_html):
                            print("[ПРЕДУПРЕЖДЕНИЕ] На странице статьи сработала заглушка. Пропуск.")
                            continue

                        article_soup = BeautifulSoup(article_html, "html.parser")
                        article_body = find_article_body(article_soup)

                        if article_body is None:
                            print("[ПРЕДУПРЕЖДЕНИЕ] Основной текст статьи не распознан.")
                            print_possible_article_containers(article_soup)
                            continue

                        processed_articles += 1

                        # Сбор только контекстных внешних ссылок (внутри текста новости)
                        for tag in article_body.find_all("a", href=True):
                            link = urljoin(article_url, str(tag["href"]))
                            parts = urlsplit(link)

                            if parts.scheme not in ("http", "https") or not parts.hostname:
                                continue
                            if is_rosbalt_host(parts.hostname) or is_excluded_external_host(parts.hostname):
                                continue
                            
                            # Игнорируем статику
                            if parts.path.lower().endswith((
                                ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", 
                                ".css", ".js", ".ico", ".woff", ".woff2"
                            )):
                                continue

                            # Игнорируем редиректы новостных сетей (SMI2 и др.)
                            hostname = parts.hostname.lower().removeprefix("www.")
                            if hostname == "smi2.ru" and parts.path.startswith("/newdata/"):
                                continue

                            external_links.add(link)

                    except PlaywrightError as exc:
                        print(f"[ОШИБКА] Не удалось открыть статью {article_url}: {exc}")

                print("\n" + "=" * 70)
                print(f"ИТОГОВЫЙ СТАТУС:")
                print(f"  - Успешно обработано статей с текстом: {processed_articles} из {len(urls_to_process)}")
                print(f"  - Уникальных внешних ссылок собрано: {len(external_links)}")
                print("=" * 70)

                for link in sorted(external_links):
                    print(link)

            finally:
                if context is not None:
                    context.close()
                browser.close()

    except PlaywrightError as exc:
        print(f"[КРИТИЧЕСКАЯ ОШИБКА] Ошибка инициализации Playwright: {exc}")


if __name__ == "__main__":
    debug_rosbalt_two_levels(START_URL)
