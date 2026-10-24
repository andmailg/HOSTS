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
    Универсальный трехступенчатый асинхронный краулер без привязки к конкретным сайтам.
    Этап 1: Быстрый запрос (aiohttp + Chrome headers)
    Этап 2: Полноценный браузер (Playwright Async для JS-динамики и обхода заглушек)
    Этап 3: Поисковый робот (Fallback на YandexBot при блокировках)
    """
    aggregated_urls = set()
    total_seeds = len(url_list)
    delay = 1.0 / max_reqs if max_reqs > 0 else 1.0
    
    print(f"\n[Кроулер] Запуск 3-ступенчатого сканирования для {total_seeds} адресов...")
    
    timeout_settings = aiohttp.ClientTimeout(total=20, connect=5, sock_read=15)
    
    # Профили заголовков
    chrome_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    yandex_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.7,en;q=0.3",
        "Accept-Encoding": "gzip, deflate"
    }
    
    async with aiohttp.ClientSession(timeout=timeout_settings, max_line_size=65536, max_field_size=65536) as session:
        for idx, target_url in enumerate(url_list, 1):
            normalized_seed = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
            seed_apex = get_apex_domain(normalized_seed)
            
            print(f"\n[{idx}/{total_seeds}] Анализ: {normalized_seed}")
            
            if max_depth == 0:
                aggregated_urls.add(normalized_seed)
                continue
                
            current_seed_urls = set()

            # Универсальная функция парсинга ссылок
            def parse_links(html_str):
                """
                Универсальный разбор HTML-контента и извлечение целевых ссылок.
                Автоматически поддерживает поддомены крупных медиахолдингов 
                и отсекает технический мусор.
                """
                found_urls = set()
                soup = BeautifulSoup(html_str, 'html.parser')
                
                # Список расширений статических файлов для фильтрации медиа-мусора
                MEDIA_EXTENSIONS = (
                    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico', 
                    '.css', '.js', '.woff', '.woff2', '.mp4', '.mp3'
                )

                for a_tag in soup.find_all('a', href=True):
                    href = str(a_tag['href']).strip()
                    
                    # Отсекаем якорные ссылки и JS-заглушки
                    if href.startswith('#') or href.startswith('javascript:'): 
                        continue
                        
                    # Собираем абсолютный URL
                    base_url = "https://dzen.ru" if seed_apex == "dzen.ru" else normalized_seed
                    full_url = urljoin(base_url, href)
                    
                    # Безопасно очищаем URL от GET-параметров и хэшей
                    clean_url = full_url.split('?')[0].split('#')[0]
                    
                    # Фильтруем пустые строки или ссылки, не содержащие http-протокол (например, mailto:, tel:)
                    if not clean_url.startswith(('http://', 'https://')):
                        continue
                        
                    url_parts = urlparse(clean_url)
                    
                    # Проверяем технические исключения и служебные разделы (из config.py)
                    if is_ignored_path(clean_url) or is_ignored_path(url_parts.path): 
                        continue  
                    if "p=cnews_menu" in full_url or "market." in url_parts.netloc: 
                        continue
                        
                    req_apex = get_apex_domain(clean_url)
                    
                    # --- СЦЕНАРИЙ 1: Платформа Дзен (требует строгого отбора путей статей) ---
                    if seed_apex == "dzen.ru":
                        if "/a/" in url_parts.path or "/news/show/" in url_parts.path:
                            found_urls.add(clean_url)
                            
                    # --- СЦЕНАРИЙ 2: Все остальные сайты мира (универсальный алгоритм) ---
                    else:
                        # Проверяем принадлежность ссылки к исходному сайту.
                        # Условие 'seed_apex in netloc' автоматически подхватывает любые глубокие поддомены 
                        # (например: sportmail.ru для mail.ru, pro.rbc.ru для rbc.ru, auto.rambler.ru для rambler.ru)
                        netloc_lower = url_parts.netloc.lower()
                        if seed_apex and (req_apex == seed_apex or seed_apex in netloc_lower):
                            
                            # Отсекаем ссылки, которые ведут напрямую на картинки, видео, шрифты или скрипты
                            if not clean_url.lower().endswith(MEDIA_EXTENSIONS):
                                found_urls.add(clean_url)
                                
                return found_urls

            # -----------------------------------------------------------------
            # СТУПЕНЬ 1: Быстрый HTTP-запрос (aiohttp + Chrome headers)
            # -----------------------------------------------------------------
            step_2_needed = False
            print(" -> [Ступень 1] Запрос через обычный aiohttp (Chrome-имитация)...")
            headers = chrome_headers.copy()
            headers["Referer"] = f"https://{seed_apex or 'google.com'}/"
            
            try:
                async with session.get(normalized_seed, headers=headers, ssl=False) as response:
                    if response.status >= 400:
                        print(f"    ├─ Статус {response.status}. Переход на Ступень 2.")
                        step_2_needed = True
                    else:
                        html_content = await response.text()
                        current_seed_urls = parse_links(html_content)
                        if not current_seed_urls:
                            print("    ├─ Ссылок не найдено (динамический контент или защита). Переход на Ступень 2.")
                            step_2_needed = True
                        else:
                            print(f"    └─ Успех на Ступени 1! Собрано ссылок: {len(current_seed_urls)}")
            except Exception as e:
                print(f"    ├─ Сетевая ошибка ({type(e).__name__}). Переход на Ступень 2.")
                step_2_needed = True

            # -----------------------------------------------------------------
            # СТУПЕНЬ 2: Браузерный движок Playwright (JS-рендеринг)
            # -----------------------------------------------------------------
            step_3_needed = False
            if step_2_needed:
                print(" -> [Ступень 2] Запуск Playwright (Chromium)...")
                try:
                    from playwright.async_api import async_playwright
                    async with async_playwright() as playwright:
                        browser = await playwright.chromium.launch(headless=HEADLESS_MODE)
                        context = await browser.new_context(
                            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                            locale="ru-RU",
                            extra_http_headers={"Accept-Language": "ru,en;q=0.9"}
                        )
                        page = await context.new_page()
                        await page.goto(normalized_seed, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                        await page.wait_for_timeout(4000) # Даем время на выполнение JS и раскрытие ленты
                        
                        html_content = await page.content()
                        playwright_urls = parse_links(html_content)
                        
                        if not playwright_urls:
                            print("    ├─ Playwright не обнаружил ссылок. Переход на Ступень 3.")
                            step_3_needed = True
                        else:
                            current_seed_urls.update(playwright_urls)
                            print(f"    └─ Успех на Ступени 2! Собрано ссылок: {len(playwright_urls)}")
                            
                        await context.close()
                        await browser.close()
                except Exception as e:
                    print(f"    ├─ Ошибка Playwright ({type(e).__name__}). Переход на Ступень 3.")
                    step_3_needed = True

            # -----------------------------------------------------------------
            # СТУПЕНЬ 3: Маскировка под YandexBot (Финальный обход защит)
            # -----------------------------------------------------------------
            if step_2_needed and step_3_needed:
                print(" -> [Ступень 3] Запуск финала: Запрос под видом YandexBot...")
                fb_headers = yandex_headers.copy()
                fb_headers["Referer"] = f"https://{seed_apex or 'yandex.ru'}/"
                
                try:
                    async with session.get(normalized_seed, headers=fb_headers, ssl=False) as response:
                        if response.status < 400:
                            html_content = await response.text()
                            fallback_urls = parse_links(html_content)
                            if fallback_urls:
                                current_seed_urls.update(fallback_urls)
                                print(f"    └─ Успех на Ступени 3! Добавлено роботом: {len(fallback_urls)}")
                            else:
                                print("    └─ Робот успешно зашел, но полезных ссылок на странице нет.")
                        else:
                            print(f"    └─ Сервер отклонил поискового робота, статус: {response.status}")
                except Exception as e:
                    print(f"    └─ Ошибка Ступени 3 (Fallback): {type(e).__name__}")

            # Если контент вытащить не удалось, сохраняем хотя бы сам исходный адрес
            if not current_seed_urls:
                current_seed_urls.add(normalized_seed)
                
            aggregated_urls.update(current_seed_urls)
            await asyncio.sleep(delay)  
                
    print(f"\n[Кроулер] Всего уникальных адресов собрано для всех сайтов: {len(aggregated_urls)}")
    return list(aggregated_urls)



