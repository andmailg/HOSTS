import json
import requests
import sys
import os
import urllib3

# Отключаем предупреждения о небезопасном HTTPS (корпоративные прокси/сертификаты)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Вставьте сюда ваш API-ключ или настройте .env
API_KEY = os.environ.get("URLSCAN_API_KEY", "").strip()
UUID = "01a11f72-6104-7663-a988-55a46b3027b9"

url = f"https://urlscan.io/api/v1/result/{UUID}/"
headers = {"x-api-key": API_KEY}

try:
    print("Запрос к API...")
    r = requests.get(url, headers=headers, timeout=20)
    r.raise_for_status()
    data = r.json()
    
    # 1. Проверяем корневые ключи
    print("\n[1] Корневые ключи ответа API:", list(data.keys()))
    
    # 2. Ищем, где лежат запросы
    if "data" in data and "requests" in data["data"]:
        reqs = data["data"]["requests"]
        print(f"\n[2] Найдено запросов в data.requests: {len(reqs)}")
        if len(reqs) > 0:
            print("\n[3] Ключи первого элемента запроса:", list(reqs[0].keys()))
            print("\n[4] Содержимое ключа 'request' первого элемента:")
            print(json.dumps(reqs[0].get("request", {}), indent=2, ensure_ascii=False)[:500])
            print("\n[5] Содержимое ключа 'response' первого элемента:")
            print(json.dumps(reqs[0].get("response", {}), indent=2, ensure_ascii=False)[:500])
    else:
        print("\n[Внимание] Ключ data.requests НЕ найден!")
        # Ищем похожие ключи
        for k in data.keys():
            if isinstance(data[k], list):
                print(f"Обнаружен массив в корневом ключе '{k}' (длина: {len(data[k])})")
            elif isinstance(data[k], dict):
                print(f"Вложенные ключи в '{k}':", list(data[k].keys()))

except Exception as e:
    print(f"Ошибка: {e}")
