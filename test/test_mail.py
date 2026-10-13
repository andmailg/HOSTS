import re
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Отключаем предупреждения об отсутствии SSL-верификации для корпоративных сетей
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def debug_mail_ru(seed_url="https://news.mail.ru"):
    print("=" * 70)
    print(f"ИСХОДНЫЙ URL: {seed_url}")
    print("=" * 70)
    
    # Маскируемся под Яндекс.Бот для получения полной текстовой версии (SSR) со всеми ссылками
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.7,en;q=0.3",
        "Referer": "https://mail.ru"
    }
    
    try:
        print("[ИНФО] Запрос к Mail.ru под видом поискового робота...")
        response = requests.get(seed_url, headers=headers, timeout=10, verify=False)
        print(f"[ИНФО] Статус-код ответа сервера: {response.status_code}")
        
        if response.status_code != 200:
            print(f"[ОШИБКА] Сервер вернул ошибку {response.status_code}")
            return
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        found_links = set()
        subdomains = set()
        
        # Парсим все ссылки на странице
        for a_tag in soup.find_all('a', href=True):
            href = str(a_tag['href']).strip()
            
            # Пропускаем якоря и js-скрипты
            if href.startswith('#') or href.startswith('javascript:'):
                continue
                
            full_url = urljoin(seed_url, href)
            parsed_url = urlparse(full_url)
            netloc = parsed_url.netloc.lower()
            
            # Фильтруем ссылки, чтобы собирать только внутренние проекты экосистемы mail.ru
            if "mail.ru" in netloc or "sportmail.ru" in netloc:
                # Исключаем прямые ссылки на статические медиа-ресурсы
                if not any(full_url.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff2', '.ico']):
                    # Очищаем от параметров для наглядности отладки
                    clean_url = full_url.split('?')[0]
                    found_links.add(clean_url)
                    subdomains.add(netloc)
        
        # Выводим найденные уникальные поддомены/проекты
        print("\n" + "-" * 70)
        print(f"[УСПЕХ] Обнаружено уникальных поддоменов/проектов Mail.ru: {len(subdomains)}")
        print("-" * 70)
        for sub in sorted(subdomains):
            print(f"  • {sub}")
            
        # Выводим примеры найденных страниц для URLScan
        print("\n" + "-" * 70)
        print(f"[УСПЕХ] Всего извлечено внутренних URL: {len(found_links)}")
        print("-" * 70)
        
        # Показываем первые 15 ссылок для проверки структуры
        for idx, url in enumerate(sorted(found_links)[:15], 1):
            print(f"  [{idx:02d}] {url}")
            
        if len(found_links) > 15:
            print(f"  ... и еще {len(found_links) - 15} ссылок.")
            
        print("\n" + "=" * 70)
        print(f"ИТОГ ТЕСТА: Маскировка под робота позволяет собрать {len(found_links)} страниц вместо жесткого фоллбэка.")
        print("=" * 70)
        
    except Exception as e:
        print(f"[КРИТИЧЕСКАЯ ОШИБКА] Ошибка при парсинге Mail.ru: {repr(e)}")

if __name__ == "__main__":
    debug_mail_ru()
