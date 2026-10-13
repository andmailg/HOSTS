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
    Извлекает ссылки на статьи Дзена 2-го уровня (/a/ и /news/show/) из HTML-версии сюжета.
    """
    story_links = set()
    
    # Маскируемся под Яндекс.Бот, чтобы Дзен отдал чистый текстовый HTML без JS-защиты и SSO
    bot_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.7,en;q=0.3"
    }
    
    try:
        print(f" -> [HTML Дзен] Парсинг текстовой версии сюжета...")
        response = requests.get(story_url, headers=bot_headers, timeout=10, verify=False)
        
        if response.status_code != 200:
            print(f" -> [Предупреждение] Дзен вернул код ответа: {response.status_code}")
            return story_links
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Находим все внутренние ссылки Дзена на статьи (/a/) или карточки новостей (/news/show/)
        for a_tag in soup.find_all('a', href=True):
            href = str(a_tag['href']).strip()
            full_url = urljoin("https://dzen.ru", href)
            
            if "/a/" in full_url or "/news/show/" in full_url:
                # Очищаем URL от UTM и трекинговых параметров для красивого вывода в URLScan
                clean_url = full_url.split('?')[0]
                story_links.add(clean_url)
                
    except Exception as e:
        print(f" -> [Предупреждение] Ошибка при обходе структуры Дзена: {repr(e)}")
        
    return story_links

def run_external_crawler_for_urls(url_list, max_depth=MAX_DEPTH, max_reqs=1, max_urls_per_seed=2):
    """
    Краулер на чистом Python с поддержкой извлечения статей Дзена 2-го уровня.
    """
    aggregated_urls = set()
    total_seeds = len(url_list)
    delay = 1.0 / max_reqs if max_reqs > 0 else 1.0
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
    }
    
    print(f"\n[Кроулер Python] Запуск сканирования для {total_seeds} адресов...")
    
    for idx, target_url in enumerate(url_list, 1):
        normalized_seed = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        seed_apex = get_apex_domain(normalized_seed)
        
        print(f"[{idx}/{total_seeds}] Сканирование: {normalized_seed} (Глубина: {max_depth})")
        
        if max_depth == 0:
            aggregated_urls.add(normalized_seed)
            continue
            
        current_seed_urls = set()
        
        # 1. ПЕРЕХВАТ СЮЖЕТОВ И СТАТЕЙ ДЗЕНА
        if "dzen.ru" in normalized_seed:
            dzen_links = extract_dzen_story_links(normalized_seed, headers)
            current_seed_urls.update(list(dzen_links)[:max_urls_per_seed])
        
        # 2. ОБЫЧНЫЙ HTML-ПАРСИНГ ДЛЯ ОСТАЛЬНЫХ САЙТОВ пула
        else:
            try:
                response = requests.get(normalized_seed, headers=headers, timeout=10, verify=False)
                if response.status_code >= 400:
                    current_seed_urls.add(normalized_seed)
                    aggregated_urls.update(current_seed_urls)
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for a_tag in soup.find_all('a', href=True):
                    if len(current_seed_urls) >= max_urls_per_seed:
                        break
                        
                    href = str(a_tag['href']).strip()
                    if href.startswith('#') or href.startswith('javascript:'):
                        continue
                        
                    full_url = urljoin(normalized_seed, href)
                    req_apex = get_apex_domain(full_url)
                    
                    if seed_apex and req_apex == seed_apex:
                        if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.woff2', '.js', '.ico', '.svg', '.webp']):
                            current_seed_urls.add(full_url)
                            
            except Exception as e:
                print(f" -> [Предупреждение] Ошибка при обходе {target_url}: {repr(e)}")
        
        # Умный фоллбек для SPA-порталов, если ссылки не собрались
        if not current_seed_urls:
            if seed_apex == "dzen.ru":
                print(" -> [Фоллбек] В сюжете Дзена ссылок не найдено, берем исходный URL.")
                current_seed_urls.add(normalized_seed)
            elif seed_apex == "mail.ru":
                print(" -> [Фоллбек] Mail.ru вернул пустой HTML. Генерируем разделы Новости и Спорт.")
                current_seed_urls.add("https://mail.ru")
                current_seed_urls.add("https://sportmail.ru")

        if not current_seed_urls:
            current_seed_urls.add(normalized_seed)
            
        # Обновляем итоговый агрегированный пул
        valid_batch = list(current_seed_urls)[:max_urls_per_seed]
        if seed_apex == "dzen.ru":
            print(f" -> Всего подготовлено страниц Дзена для пула: {len(valid_batch)}")
            
        aggregated_urls.update(valid_batch)
        time.sleep(delay)
            
    print(f"[Кроулер] Всего уникальных адресов собрано для всех сайтов: {len(aggregated_urls)}")
    return list(aggregated_urls)
