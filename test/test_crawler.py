import asyncio
import os
import sys

# Добавляем python/ в sys.path для импорта модулей из этой директории
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from crawler import run_external_crawler_for_urls  # pyright: ignore[reportMissingImports]

# Имя вашего существующего файла
FILE_NAME = "test/urls_test.txt"

def read_urls_from_file(file_path):
    """
    Читает список URL из существующего файла.
    Удаляет пробелы, переносы строк и пропускает пустые строки.
    """
    if not os.path.exists(file_path):
        print(f"[Ошибка] Файл '{file_path}' не найден! Проверьте путь.")
        return []
    
    with open(file_path, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    
    print(f"[Тест] Успешно прочитано {len(urls)} адресов из файла '{file_path}'.")
    return urls

async def main():
    # 1. Чтение доменов из вашего файла
    url_list = read_urls_from_file(FILE_NAME)
    
    if not url_list:
        return

    # 2. Запуск вашего краулера (max_reqs=1 задает паузу в 1 сек между сайтами)
    result_urls = await run_external_crawler_for_urls(url_list, max_reqs=1)

    # 3. Вывод итоговых результатов в консоль
    print("\n" + "="*60)
    print(f"[Итог теста] Всего уникальных ссылок собрано: {len(result_urls)}")
    print("="*60)
    
    for url in sorted(result_urls):
        print(f" -> {url}")

if __name__ == "__main__":
    # Запуск асинхронного теста
    asyncio.run(main())
