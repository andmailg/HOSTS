import re
import requests
import urllib3
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit
from config import MAX_DEPTH
from filters import get_apex_domain
from config import is_ignored_path

# Отключаем предупреждения об отсутствии SSL-верификации
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
        from config import HEADLESS_MODE, PAGE_TIMEOUT_MS
        
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
                            # Проверка на служебные пути
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

# ВАЖНО: Делаем всю основную функцию run_external_crawler_for_urls асинхронной (async def)
async def run_external_crawler_for_urls(url_list, max_depth=MAX_DEPTH, max_reqs=1, max_urls_per_seed=2):
    """
    Универсальный асинхронный краулер с поддержкой поддоменов Mail.ru, Gazeta, KP, 
    асинхронного Playwright для Росбалта, а также с фильтрацией хабов/рубрик для Yuga, Interfax и SecurityLab.
    """
    aggregated_urls = set()
    total_seeds = len(url_list)
    delay = 1.0 / max_reqs if max_reqs > 0 else 1.0
    
    print(f"\n[Кроулер] Запуск сканирования для {total_seeds} адресов...")
    
    for idx, target_url in enumerate(url_list, 1):
        normalized_seed = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        seed_domain = urlparse(normalized_seed).netloc.lower()
        seed_apex = get_apex_domain(normalized_seed)
        
        print(f"[{idx}/{total_seeds}] Сканирование: {normalized_seed} (Глубина: {max_depth})")
        
        if max_depth == 0:
            aggregated_urls.add(normalized_seed)
            continue
            
        current_seed_urls = set()
        
        # --- ВЕТКА ROSBALT (ВЫЗЫВАЕМ АСИНХРОННЫЙ ПЛЕЙРАЙТ) ---
        if seed_apex == "rosbalt.ru":
            rosbalt_urls = await crawl_rosbalt_async(normalized_seed, max_depth)
            current_seed_urls.update(rosbalt_urls)
                
        # --- КЛАССИЧЕСКИЙ СБОР ДЛЯ ОСТАЛЬНЫХ САЙТОВ (ЧЕРЕЗ REQUESTS) ---
        else:
            if seed_apex in ["mail.ru", "sportmail.ru", "dzen.ru", "gazeta.ru", "kp.ru"]:
                headers = {
                    "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "ru,en-US;q=0.7,en;q=0.3",
                    "Referer": f"https://{seed_apex}"
                }
            else:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8"
                }
            
            try:
                # Синхронный requests.get внутри async цикла допустим, так как это последовательный подготовительный этап
                response = requests.get(normalized_seed, headers=headers, timeout=10, verify=False)
                if response.status_code >= 400:
                    print(f" -> [Пропущено] Код ответа сервера: {response.status_code}")
                    current_seed_urls.add(normalized_seed)
                    aggregated_urls.update(current_seed_urls)
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for a_tag in soup.find_all('a', href=True):
                    href = str(a_tag['href']).strip()
                    if href.startswith('#') or href.startswith('javascript:'):
                        continue
                        
                    base_url = "https://dzen.ru" if seed_apex == "dzen.ru" else normalized_seed
                    full_url = urljoin(base_url, href)
                    
                    # ПАРСИНГ ПУТИ ДЛЯ ФИЛЬТРАЦИИ RSS/SEARCH/ХАБОВ
                    url_parts = urlparse(full_url)
                    
                    # 1. Глобальная фильтрация по паттернам путей (убирает /opinion/, /go/, /rss и т.д.)
                    if is_ignored_path(url_parts.path):
                        continue  
                        
                    # 2. Дополнительная фильтрация параметров (для cnews_menu и маркетплейсов)
                    if "p=cnews_menu" in url_parts.query or url_parts.netloc.startswith("market."):
                        continue

                    req_apex = get_apex_domain(full_url)
                    path = url_parts.path.lower().rstrip('/')
                    
                    if seed_apex == "dzen.ru":
                        if "/a/" in full_url or "/news/show/" in full_url:
                            # Очищаем URL от параметров (?) и от хэш-комментариев (#)
                            clean_url = full_url.split('?')[0].split('#')[0]
                            current_seed_urls.add(clean_url)
                            
                    elif seed_apex in ["mail.ru", "sportmail.ru", "gazeta.ru", "kp.ru"]:
                        req_domain = urlparse(full_url).netloc.lower()
                        if seed_apex in req_domain or "mail.ru" in req_domain:
                            if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                                # Очищаем ссылки Mail, Gazeta, KP от utm-меток и параметров
                                current_seed_urls.add(full_url.split('?')[0])
                                
                    else:
                        # Стандартный режим для Interfax, Yuga, SecurityLab и др.
                        if seed_apex and req_apex == seed_apex:
                            if any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                                continue

                            # Очищаем URL от ?utm_source=top и других GET-параметров перед добавлением
                            clean_url = full_url.split('?')[0]
                            current_seed_urls.add(clean_url)
                                
            except Exception as e:
                print(f" -> [Предупреждение] Ошибка при обходе {target_url}: {repr(e)}")
        
        if not current_seed_urls:
            current_seed_urls.add(normalized_seed)
            
        print(f" -> Успешно извлечено ссылок для сессии: {len(current_seed_urls)}")
        aggregated_urls.update(current_seed_urls)
        await asyncio.sleep(delay)  # Заменили синхронный time.sleep на асинхронный
            
    print(f"[Кроулер] Всего уникальных адресов собрано для всех сайтов: {len(aggregated_urls)}")
    return list(aggregated_urls)
