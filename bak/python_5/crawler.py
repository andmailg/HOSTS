import re
import sys
import time
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from config import MAX_DEPTH
from filters import get_apex_domain

# Отключаем предупреждения об отсутствии SSL-верификации
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_external_crawler_for_urls(url_list, max_depth=MAX_DEPTH, max_reqs=1, max_urls_per_seed=2):
    """
    Универсальный Python-краулер с поддержкой поддоменов Mail.ru.
    """
    aggregated_urls = set()
    total_seeds = len(url_list)
    delay = 1.0 / max_reqs if max_reqs > 0 else 1.0
    
    print(f"\n[Кроулер Python] Запуск сканирования для {total_seeds} адресов...")
    
    for idx, target_url in enumerate(url_list, 1):
        normalized_seed = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        seed_domain = urlparse(normalized_seed).netloc.lower()
        seed_apex = get_apex_domain(normalized_seed)
        
        print(f"[{idx}/{total_seeds}] Сканирование: {normalized_seed} (Глубина: {max_depth})")
        
        if max_depth == 0:
            aggregated_urls.add(normalized_seed)
            continue
            
        current_seed_urls = set()
        
        # Задаем заголовки поискового робота для VK-экосистемы, Дзена, Газеты и КП
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
                req_apex = get_apex_domain(full_url)
                
                # ФИЛЬТРАЦИЯ 1: Правила для Дзена (ищем статьи /a/ и показы новостей)
                if seed_apex == "dzen.ru":
                    if "/a/" in full_url or "/news/show/" in full_url:
                        current_seed_urls.add(full_url.split('?')[0])
                        
                # ФИЛЬТРАЦИЯ 2: Правила для экосистемы Mail.ru
                elif seed_apex in ["mail.ru", "sportmail.ru"]:
                    req_domain = urlparse(full_url).netloc.lower()
                    if "mail.ru" in req_domain or "sportmail.ru" in req_domain:
                        if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                            current_seed_urls.add(full_url.split('?')[0])
                            
                # ФИЛЬТРАЦИЯ 3: Правила для экосистем gazeta.ru и kp.ru
                elif seed_apex in ["gazeta.ru", "kp.ru"]:
                    req_domain = urlparse(full_url).netloc.lower()
                    if seed_apex in req_domain:
                        if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                            current_seed_urls.add(full_url.split('?')[0]) # Срезаем query-параметры
                            
                # ФИЛЬТРАЦИЯ 4: Правила для обычных классических сайтов
                else:
                    if seed_apex and req_apex == seed_apex:
                        if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                            current_seed_urls.add(full_url)
                            
        except Exception as e:
            print(f" -> [Предупреждение] Ошибка при обходе {target_url}: {repr(e)}")
        
        # Умные фоллбэки на случай пустой разметки
        if not current_seed_urls:
            current_seed_urls.add(normalized_seed)
            
        print(f" -> Успешно извлечено ссылок для сессии: {len(current_seed_urls)}")
        aggregated_urls.update(current_seed_urls)
        time.sleep(delay)
            
    print(f"[Кроулер] Всего уникальных адресов собрано для всех сайтов: {len(aggregated_urls)}")
    return list(aggregated_urls)
