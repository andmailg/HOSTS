import requests
import json

API_KEY = "01a11b20-0d0f-72bc-a329-dfb6c8d04352"

# 1. Отправляем на сканирование
r = requests.post(
    "https://urlscan.io/api/v1/scan/",
    json={"url": "https://fontanka.ru"},
    headers={"API-Key": API_KEY, "User-Agent": "test"},
    verify=False,
)
print(f"Scan response: {r.status_code}")
scan_data = r.json()
print(json.dumps(scan_data, indent=2))

uuid = scan_data.get("uuid")
if uuid:
    print(f"\nUUID: {uuid}")
    
    # 2. Ждём и проверяем
    import time
    for i in range(10):
        time.sleep(3)
        r2 = requests.get(
            f"https://urlscan.io/api/v1/result/{uuid}/",
            headers={"API-Key": API_KEY},
            verify=False,
        )
        print(f"\nPoll #{i+1}: {r2.status_code}")
        if r2.status_code == 200:
            data = r2.json()
            print(f"Keys: {list(data.keys())}")
            
            # Запросы
            requests_data = data.get("requests", [])
            print(f"Requests: {len(requests_data)}")
            for req in requests_data[:20]:
                req_info = req.get("request", {})
                url = req_info.get("url", "")
                domain = req_info.get("domain", "")
                print(f"  {domain} <- {url[:100]}")
            break
        elif r2.status_code == 404:
            print("  Not ready yet")
        else:
            print(f"  {r2.text[:200]}")
