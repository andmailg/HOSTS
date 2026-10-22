import re
import asyncio
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import aiohttp  # Заменили requests на асинхронный клиент

from config import MAX_DEPTH, is_ignored_path, HEADLESS_MODE, PAGE_TIMEOUT_MS
from filters import get_apex_domain

# Отключаем предупреждения об отсутствии SSL-верификации для корпоративных сетей
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_interstitial_page(html):
    """Быстро распознаёт промежуточную заглушку Росбалта без парсинга DOM."""
    html_lower = html.lower()
    return (
        'name="robots" content="noindex, noarchive"' in html_lower
        and "gorizontal-vertikal" in html_lower
        and "data:image/gif;base64," in html_lower
    )

async def crawl_rosbalt_async(normalized_seed, max_depth):
    """Асинхронный сбор ссылок для Росбалта с использованием Async API Playwright."""
    current_seed_urls = set()
    try:
        from playwright.async_api import async_playwright
        
        print(f" -> [Playwright Async] Запуск браузера для {normalized_seed}...")
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=HEADLESS_MODE)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                locale="ru-RU",
                extra_http_headers={"Accept-Language": "ru,en;q=0.9"}
            )
            page = await context.new_page()
            await page.goto(normalized_seed, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            await page.wait_for_timeout(4000)
            
            html = await page.content()
            if is_interstitial_page(html):
                print("[ОШИБКА] Обнаружена страница-заглушка Росбалта (noindex). Сбор прерван.")
                current_seed_urls.add(normalized_seed)
            else:
                soup = BeautifulSoup(html, "html.parser")
                article_pattern = re.compile(r"^/news/\d{4}-\d{2}-\d{2}/.+-\d+/?$")
                
                for tag in soup.find_all("a", href=True):
                    full_url = urljoin(page.url, str(tag["href"]))
                    parts = urlsplit(full_url)
                    
                    if parts.scheme in ("http", "https") and get_apex_domain(full_url) == "rosbalt.ru":
                        if article_pattern.match(parts.path):
                            if is_ignored_path(parts.path):
                                continue
                            clean_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
                            current_seed_urls.add(clean_url)
            await context.close()
            await browser.close()
    except Exception as e:
        print(f" -> [Ошибка Playwright Async] Не удалось обойти {normalized_seed}: {repr(e)}")
        current_seed_urls.add(normalized_seed)
    
    return current_seed_urls

async def run_external_crawler_for_urls(url_list, max_depth=MAX_DEPTH, max_reqs=1, max_urls_per_seed=2):
    """
    Универсальный асинхронный краулер с автоматическим fallback на YandexBot.
    Если сайт блокирует Chrome, отдает пустую страницу или падает по таймауту,
    скрипт делает повторный запрос под видом поискового робота.
    """
    aggregated_urls = set()
    total_seeds = len(url_list)
    delay = 1.0 / max_reqs if max_reqs > 0 else 1.0
    
    print(f"\n[Кроулер] Запуск сканирования для {total_seeds} адресов...")
    
    timeout_settings = aiohttp.ClientTimeout(total=20, connect=5, sock_read=15)
    
    # Базовый профиль Chrome для первой попытки (без br)
    chrome_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive"
    }
    
    # Профиль YandexBot для гарантированного сбора контента (Дзен, Газета.ру и др.)
    yandex_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.7,en;q=0.3",
        "Accept-Encoding": "gzip, deflate"
    }
    
    async with aiohttp.ClientSession(
        timeout=timeout_settings,
        max_line_size=65536,   
        max_field_size=65536   
    ) as session:
        
        for idx, target_url in enumerate(url_list, 1):
            normalized_seed = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
            seed_apex = get_apex_domain(normalized_seed)
            
            print(f"[{idx}/{total_seeds}] Сканирование: {normalized_seed} (Глубина: {max_depth})")
            
            if max_depth == 0:
                aggregated_urls.add(normalized_seed)
                continue
                
            current_seed_urls = set()
            
            if seed_apex == "rosbalt.ru":
                rosbalt_urls = await crawl_rosbalt_async(normalized_seed, max_depth)
                current_seed_urls.update(rosbalt_urls)
                aggregated_urls.update(current_seed_urls)
                await asyncio.sleep(delay)
                continue

            # Внутренняя функция для парсинга HTML-контента
            def parse_links(html_str):
                found_urls = set()
                soup = BeautifulSoup(html_str, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = str(a_tag['href']).strip()
                    if href.startswith('#') or href.startswith('javascript:'):
                        continue
                        
                    base_url = "https://dzen.ru" if seed_apex == "dzen.ru" else normalized_seed
                    full_url = urljoin(base_url, href)
                    clean_url = full_url.split('?')[0].split('#')[0]
                    url_parts = urlparse(clean_url)

                    if is_ignored_path(clean_url) or is_ignored_path(url_parts.path):
                        continue  
                        
                    if "p=cnews_menu" in full_url or "market." in url_parts.netloc:
                        continue

                    req_apex = get_apex_domain(clean_url)
                    
                    if seed_apex == "dzen.ru":
                        if "/a/" in url_parts.path or "/news/show/" in url_parts.path:
                            found_urls.add(clean_url)
                    elif seed_apex in ["mail.ru", "sportmail.ru", "gazeta.ru", "kp.ru", "ria.ru", "rambler.ru"]:
                        req_domain = url_parts.netloc.lower()
                        if seed_apex in req_domain or "mail.ru" in req_domain:
                            if not any(clean_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                                found_urls.add(clean_url)
                    else:
                        if seed_apex and req_apex == seed_apex:
                            if any(clean_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                                continue
                            found_urls.add(clean_url)
                return found_urls

            # --- ПОПЫТКА 1: Браузерный Chrome ---
            use_fallback = False
            headers = chrome_headers.copy()
            headers["Referer"] = f"https://{seed_apex or 'google.com'}/"
            
            try:
                async with session.get(normalized_seed, headers=headers, ssl=False) as response:
                    if response.status >= 400:
                        print(f" -> Chrome вернул статус {response.status}. Переключение на fallback...")
                        use_fallback = True
                    else:
                        html_content = await response.text()
                        current_seed_urls = parse_links(html_content)
                        
                        if not current_seed_urls:
                            print(" -> Chrome не нашел ссылок (пустая лента/защита). Переключение на fallback...")
                            use_fallback = True
            except (asyncio.TimeoutError, Exception) as e:
                print(f" -> Ошибка при обходе через Chrome ({repr(e)}). Переключение на fallback...")
                use_fallback = True

            # --- ПОПЫТКА 2: FALLBACK НА YANDEXBOT ---
            if use_fallback:
                print(f" -> Запуск fallback-запроса через YandexBot к {normalized_seed}")
                fb_headers = yandex_headers.copy()
                fb_headers["Referer"] = f"https://{seed_apex or 'yandex.ru'}/"
                
                try:
                    async with session.get(normalized_seed, headers=fb_headers, ssl=False) as response:
                        if response.status < 400:
                            html_content = await response.text()
                            fallback_urls = parse_links(html_content)
                            if fallback_urls:
                                current_seed_urls.update(fallback_urls)
                                print(f" -> Fallback успешен! Найдено ссылок: {len(fallback_urls)}")
                        else:
                            print(f" -> Fallback тоже отклонен сервером, статус: {response.status}")
                except Exception as e:
                    print(f" -> Ошибка во время выполнения fallback: {repr(e)}")

            # Если совсем ничего не нашли, сохраняем хотя бы seed
            if not current_seed_urls:
                current_seed_urls.add(normalized_seed)
                
            print(f" -> Успешно извлечено ссылок для сессии: {len(current_seed_urls)}")
            aggregated_urls.update(current_seed_urls)
            await asyncio.sleep(delay)  
                
    print(f"[Кроулер] Всего уникальных адресов собрано для всех сайтов: {len(aggregated_urls)}")
    return list(aggregated_urls)


