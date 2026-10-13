import re
import sys
import time
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from config import MAX_DEPTH

# Отключаем предупреждения об отсутствии SSL-верификации (актуально для корпоративных сетей)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_external_crawler_for_urls(url_list, max_depth=MAX_DEPTH, max_reqs=1):
    """
    Краулер на чистом Python для работы в Windows без прав администратора.
    Служит полной заменой внешней утилиты siteone-crawler.
    """
    aggregated_urls = set()
    total_seeds = len(url_list)
    
    # Считаем паузу между запросами на основе переданного лимита max_reqs_per_sec
    delay = 1.0 / max_reqs if max_reqs > 0 else 1.0
    
    print(f"\n[Кроулер Python] Запуск локального сканирования для {total_seeds} адресов...")
    
    for idx, target_url in enumerate(url_list, 1):
        normalized_seed = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        seed_domain = urlparse(normalized_seed).netloc
        
        print(f"[{idx}/{total_seeds}] Сканирование: {normalized_seed} (Глубина: {max_depth})")
        
        # Если глубина установлена в 0, просто добавляем исходный URL и идем дальше
        if max_depth == 0:
            aggregated_urls.add(normalized_seed)
            continue
            
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            # Скачиваем главную страницу
            response = requests.get(normalized_seed, headers=headers, timeout=8, verify=False)
            
            # Если сайт вернул ошибку доступности (например 403 или 404), не парсим его подстраницы
            if response.status_code >= 400:
                print(f" -> [Пропущено] Сайт вернул код ответа {response.status_code}")
                aggregated_urls.add(normalized_seed)
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            filtered = set()
            for a_tag in soup.find_all('a', href=True):
                full_url = urljoin(normalized_seed, str(a_tag['href']))
                
                if urlparse(full_url).netloc == seed_domain:
                    if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                        filtered.add(full_url)
            
            # Если ссылки найдены — добавляем их, если страница пустая — добавляем хотя бы сам корень
            if filtered:
                aggregated_urls.update(filtered)
                print(f" -> Найдено и нормализовано внутренних подстраниц: {len(filtered)}")
            else:
                aggregated_urls.add(normalized_seed)
                print(" -> Подстраницы не найдены, добавлен базовый URL.")
                
        except Exception as e:
            print(f" -> [Предупреждение] Ошибка при обходе {target_url}: {repr(e)}")
            aggregated_urls.add(normalized_seed)
            
        # Задержка для соблюдения лимита запросов в секунду
        time.sleep(delay)
            
    print(f"[Кроулер] Всего уникальных адресов собрано для отправки в URLScan: {len(aggregated_urls)}")
    return list(aggregated_urls)
