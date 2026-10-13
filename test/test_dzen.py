import time
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Отключаем предупреждения об отсутствии SSL-верификации
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def debug_dzen_two_levels(story_url):
    print("=" * 70)
    print(f"1 УРОВЕНЬ (Сюжет): {story_url}")
    print("=" * 70)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.7,en;q=0.3"
    }
    
    # --- Шаг 1: Сканируем 1 уровень (Сюжет Дзена) ---
    try:
        response = requests.get(story_url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        internal_articles = set()
        
        # Находим все внутренние ссылки Дзена на статьи (/a/) или новости (/news/show/)
        for a_tag in soup.find_all('a', href=True):
            href = str(a_tag['href'])
            full_url = urljoin("https://dzen.ru", href)
            
            # Фильтруем ссылки Дзена 2-го уровня (статьи /a/ или карточки новостей)
            if "/a/" in full_url or "/news/show/" in full_url:
                # Отсекаем параметры для чистоты URL
                clean_url = full_url.split('?')[0]
                internal_articles.add(clean_url)
                
        print(f"[ИНФО] На 1 уровне найдено внутренних статей Дзена: {len(internal_articles)}")
        for art in internal_articles:
            print(f"  -> Найдена статья 2-го уровня: {art}")
            
        # --- Шаг 2: Сканируем 2 уровень (Каждую статью /a/) ---
        final_media_links = set()
        print("\n" + "=" * 70)
        print("2 УРОВЕНЬ (Парсинг статей Дзена и поиск внешних СМИ):")
        print("=" * 70)
        
        for art_url in list(internal_articles)[:5]: # Ограничим до 5 штук для быстрой отладки
            print(f"[Парсинг статьи] -> {art_url}")
            try:
                # Делаем паузу между запросами, чтобы Дзен не заблокировал
                time.sleep(1)
                art_res = requests.get(art_url, headers=headers, timeout=8, verify=False)
                art_soup = BeautifulSoup(art_res.text, 'html.parser')
                
                # Ищем финальные ссылки на внешние новостные ресурсы
                for a_tag in art_soup.find_all('a', href=True):
                    href = str(a_tag['href'])
                    
                    # Если ссылка внешняя и это не сервисы Дзена/Яндекса
                    if href.startswith('http') and not any(x in href for x in ['dzen.ru', 'yandex.ru', 'passport.yandex', 'sso.dzen', 'yastatic.net']):
                        if not any(href.lower().endswith(e) for e in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js']):
                            final_media_links.add(href)
                            print(f"    [НАЙДЕНО СМИ] -> {href}")
            except Exception as e:
                print(f"    [Предупреждение] Ошибка парсинга статьи {art_url}: {repr(e)}")
                
        print("\n" + "=" * 70)
        print(f"ИТОГ ДВУХУРОВНЕВОГО ОБХОДА:")
        print(f"Собрано внешних СМИ для отправки в URLScan: {len(final_media_links)}")
        print("=" * 70)
        
    except Exception as e:
        print(f"[КРИТИЧЕСКАЯ ОШИБКА] Ошибка на 1 уровне: {repr(e)}")

if __name__ == "__main__":
    test_url = "https://dzen.ru/news/story/71f5c95f-d2be-5f5c-9f2d-3b95968bb90d"
    debug_dzen_two_levels(test_url)
