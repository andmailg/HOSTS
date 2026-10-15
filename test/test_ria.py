import re
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Отключаем предупреждения об отсутствии SSL-верификации для корпоративных сетей
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def debug_ria_ru(seed_url="https://ria.ru"):
    print("=" * 70)
    print(f"ИСХОДНЫЙ URL: {seed_url}")
    print("=" * 70)
    
    # Маскируемся под Яндекс.Бот для корректного получения SSR-версии со всеми ссылками
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.7,en;q=0.3",
        "Referer": "https://yandex.ru"
    }
    
    try:
        print("[ИНФО] Запрос к ria.ru под видом поискового робота...")
        response = requests.get(seed_url, headers=headers, timeout=10, verify=False)
        print(f"[ИНФО] Статус-код ответа сервера: {response.status_code}")
        
        if response.status_code != 200:
            print(f"[ОШИБКА] Сервер вернул ошибку {response.status_code}")
            return
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        found_links = set()
        categories = set()
        
        # Парсим все ссылки на странице
        for a_tag in soup.find_all('a', href=True):
            href = str(a_tag['href']).strip()
            
            # Пропускаем якоря, javascript-ссылки и формы авторизации
            if href.startswith('#') or href.startswith('javascript:') or 'login' in href:
                continue
                
            full_url = urljoin(seed_url, href)
            parsed_url = urlparse(full_url)
            netloc = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            # Фильтруем ссылки: собираем только внутренние ресурсы экосистемы РИА Новости
            if "ria.ru" in netloc:
                # Исключаем статические файлы, картинки и файлы приложений (AppStore/RuStore)
                extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff2', '.ico', '.apk']
                if not any(path.endswith(e) for e in extensions):
                    # Очищаем от UTM-меток и параметров для чистоты отладки
                    clean_url = full_url.split('?')[0]
                    found_links.add(clean_url)
                    
                    # Выделяем первый сегмент пути как категорию/рубрику (например, /politics/, /economy/)
                    path_parts = [p for p in path.split('/') if p]
                    if path_parts:
                        categories.add(path_parts[0])
        
        # Выводим найденные уникальные рубрики
        print("\n" + "-" * 70)
        print(f"[УСПЕХ] Обнаружено уникальных разделов/рубрик ria.ru: {len(categories)}")
        print("-" * 70)
        for cat in sorted(categories):
            print(f"  • /{cat}/")
            
        # Выводим примеры найденных страниц для проверки структуры
        print("\n" + "-" * 70)
        print(f"[УСПЕХ] Всего извлечено внутренних URL: {len(found_links)}")
        print("-" * 70)
        
        # Показываем первые 15 ссылок
        for idx, url in enumerate(sorted(found_links)[:15], 1):
            print(f"  [{idx:02d}] {url}")
            
        if len(found_links) > 15:
            print(f"  ... и еще {len(found_links) - 15} ссылок.")
            
        print("\n" + "=" * 70)
        print(f"ИТОГ ТЕСТА: Извлечено {len(found_links)} уникальных внутренних URL-адресов.")
        print("=" * 70)
        
    except Exception as e:
        print(f"[КРИТИЧЕСКАЯ ОШИБКА] Ошибка при парсинге ria.ru: {repr(e)}")

if __name__ == "__main__":
    debug_ria_ru()
