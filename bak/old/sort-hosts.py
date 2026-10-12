#!/usr/bin/env python3
"""Сортирует hosts_auto.txt по уровням домена (TLD -> SLD -> ...)."""

from pathlib import Path

ADBLOCK_FILE = Path(__file__).parent / "hosts_auto.txt"

def sort_key(line: str) -> tuple:
    """Ключ сортировки: обратный список частей домена."""
    parts = line.strip().split()
    if len(parts) >= 2:
        domain = parts[1].lower()
        # ['com', 'google', 'www'] для www.google.com
        return tuple(reversed(domain.split('.')))
    return (line,)  # заголовки и пустые строки — без изменений


lines = ADBLOCK_FILE.read_text(encoding="utf-8").splitlines()

header_lines = []  # строки с #
data_lines = []    # строки с доменами
blank_lines = []   # пустые строки

for line in lines:
    stripped = line.strip()
    if not stripped:
        blank_lines.append(line)
    elif stripped.startswith("#"):
        header_lines.append(line)
    else:
        data_lines.append(line)

data_lines.sort(key=sort_key)

# Перезаписываем файл
with open(ADBLOCK_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(header_lines + data_lines + blank_lines) + "\n")

print(f"Отсортировано {len(data_lines)} доменов")
