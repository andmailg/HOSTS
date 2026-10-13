import re
import sys
import time
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from config import MAX_DEPTH
from filters import get_apex_domain  # Используем функцию проекта для извлечения домена

# Отключаем предупреждения об отсутствии SSL-верификации
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_dzen_story_links(story_url, headers):
    """
    Извлекает ссылки на новости из сюжета Дзена напрямую через его JSON API.
    """
    story_links = set()
    # Регулярное выражение для поиска ID сюжета (поддерживает UUID и обычные ID)
    story_id_match = re.search(r'/story/([a-f0-9\-]+)', story_url)
    
    if not story_id_match:
        return story_links
        
    story_id = story_id_match.group(1)
    # Официальный endpoint внутреннего API Дзена для мобильных/веб лаунчеров
    api_url = f"https://dzen.ru/news/story{story_id}"
    
    try:
        print(f" -> [API Дзен] Запрос данных сюжета {story_id}...")
        response = requests.get(api_url, headers=headers, timeout=10, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            # Извлекаем ссылки на оригинальные статьи СМИ из массива документов сюжета
            for doc in data.get("docs", []):
                url = doc.get("url")
                if url:
                    story_links.add(url)
                    
            # Дополнительная проверка альтернативной структуры ответа (на случай смены схемы)
            for item in data.get("items", []):
                url = item.get("url")
                if url:
                    story_links.add(url)
        else:
            print(f" -> [Предупреждение] API Дзена вернуло код: {response.status_code}")
            
    except Exception as e:
        print(f" -> [Предупреждение] Ошибка при обращении к API Дзена: {repr(e)}")
        
    return story_links

def run_external_crawler_for_urls(url_list, max_depth=MAX_DEPTH, max_reqs=1):
    """
    Краулер на чистом Python с поддержкой нативного API Дзена.
    """
    aggregated_urls = set()
    total_seeds = len(url_list)
    delay = 1.0 / max_reqs if max_reqs > 0 else 1.0
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html, */*"
    }
    
    print(f"\n[Кроулер Python] Запуск сканирования для {total_seeds} адресов...")
    
    for idx, target_url in enumerate(url_list, 1):
        normalized_seed = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        seed_apex = get_apex_domain(normalized_seed)
        
        print(f"[{idx}/{total_seeds}] Сканирование: {normalized_seed} (Глубина: {max_depth})")
        
        if max_depth == 0:
            aggregated_urls.add(normalized_seed)
            continue
            
        filtered = set()
        
        # ПЕРЕХВАТ СЮЖЕТОВ ДЗЕНА
        if "dzen.ru/news/story" in normalized_seed:
            dzen_links = extract_dzen_story_links(normalized_seed, headers)
            filtered.update(dzen_links)
            print(f" -> Из сюжета Дзена через API успешно извлечено новостей: {len(dzen_links)}")
        
        # ОБЫЧНЫЙ HTML-ПАРСИНГ ДЛЯ ОСТАЛЬНЫХ САЙТОВ
        else:
            try:
                response = requests.get(normalized_seed, headers=headers, timeout=8, verify=False)
                if response.status_code >= 400:
                    print(f" -> [Пропущено] Код ответа сервера: {response.status_code}")
                    aggregated_urls.add(normalized_seed)
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for a_tag in soup.find_all('a', href=True):
                    full_url = urljoin(normalized_seed, str(a_tag['href']))
                    req_apex = get_apex_domain(full_url)
                    
                    # Проверка по apex-домену позволяет собирать ссылки на поддоменах
                    if seed_apex and req_apex == seed_apex:
                        if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                            filtered.add(full_url)
                            
            except Exception as e:
                print(f" -> [Предупреждение] Ошибка при обходе {target_url}: {repr(e)}")
                
        if filtered:
            aggregated_urls.update(filtered)
            # Если это Дзен, выводим сколько всего подстраниц пойдет в URLScan
            if "dzen.ru" in normalized_seed:
                print(f" -> Всего подготовлено ссылок Дзена: {len(filtered)}")
        else:
            aggregated_urls.add(normalized_seed)
            
        time.sleep(delay)
            
    print(f"[Кроулер] Всего уникальных адресов собрано для отправки в URLScan: {len(aggregated_urls)}")
    return list(aggregated_urls)
