import requests
import json

# Ищем UUID скана fontanka.ru
r = requests.get(
    "https://urlscan.io/api/v1/search/",
    params={"q": "domain:fontanka.ru", "size": 1},
    timeout=30,
    verify=False,
)
d = r.json()

if d.get("results"):
    res = d["results"][0]
    uuid = res["_id"]
    print(f"UUID: {uuid}")
    print(f"\nResult keys: {list(res.keys())}")
    
    # Есть ли поле с загруженными ресурсами?
    if "requests" in res:
        print(f"\nRequests in result: {len(res['requests'])}")
        for req in res["requests"][:30]:
            print(f"  {json.dumps(req, indent=2, ensure_ascii=False)[:300]}")
    
    # Проверяем field "page"
    page = res.get("page", {})
    print(f"\nPage keys: {list(page.keys())}")
    
    # stats?
    stats = res.get("stats", {})
    print(f"\nStats: {stats}")
