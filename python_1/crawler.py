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

def run_external_crawler_for_urls(url_list, max_depth=MAX_DEPTH, max_reqs=1):
    """
    Чистый Python-краулер с поддержкой извлечения статей Дзена 2-го уровня.
    """
    aggregated_urls = set()
    total_seeds = len(url_list)
    delay = 1.0 / max_reqs if max_reqs > 0 else 1.0
    
    # Используем User-Agent, при котором Дзен стабильно отдает HTML-разметку
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.7,en;q=0.3"
    }
    
    print(f"\n[Кроулер Python] Запуск сканирования для {total_seeds} адресов...")
    
    for idx, target_url in enumerate(url_list, 1):
        normalized_seed = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        seed_apex = get_apex_domain(normalized_seed)
        seed_domain = urlparse(normalized_seed).netloc
        
        print(f"[{idx}/{total_seeds}] Сканирование: {normalized_seed} (Глубина: {max_depth})")
        
        if max_depth == 0:
            aggregated_urls.add(normalized_seed)
            continue
            
        filtered = set()
        
        try:
            response = requests.get(normalized_seed, headers=headers, timeout=10, verify=False)
            if response.status_code >= 400:
                print(f" -> [Пропущено] Код ответа сервера: {response.status_code}")
                aggregated_urls.add(normalized_seed)
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = str(a_tag['href']).strip()
                if not href:
                    continue
                full_url = urljoin("https://dzen.ru" if "dzen.ru" in normalized_seed else normalized_seed, href)
                req_apex = get_apex_domain(full_url)
                
                # СПЕЦИАЛЬНЫЙ СБОР ДЛЯ ДЗЕНА: Вытаскиваем статьи /a/ и показы новостей
                if "dzen.ru" in normalized_seed:
                    if "/a/" in full_url or "/news/show/" in full_url:
                        clean_url = full_url.split('?')[0]
                        filtered.add(clean_url)
                else:
                    # Стандартный сбор для остальных сайтов (по совпадению apex_domain)
                    if seed_apex and req_apex == seed_apex:
                        if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                            filtered.add(full_url)
                            
        except Exception as e:
            print(f" -> [Предупреждение] Ошибка при обходе {target_url}: {repr(e)}")
            
        if filtered:
            aggregated_urls.update(filtered)
            if "dzen.ru" in normalized_seed:
                print(f" -> Найдено внутренних статей Дзена: {len(filtered)}")
        else:
            aggregated_urls.add(normalized_seed)
            
        time.sleep(delay)
            
    print(f"[Кроулер] Всего уникальных адресов собрано для отправки в URLScan: {len(aggregated_urls)}")
    return list(aggregated_urls)
