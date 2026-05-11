#!/usr/bin/env python3
"""
detector.py

Детектор DDoS-атак для тестового Flask-сервера.
Скрипт анализирует логовые строки сервера в реальном времени и выводит
сообщения об обнаружении локальной или распределённой атаки.

Запуск:
    python app.py | python detector.py
или:
    python detector.py --log-file server.log
"""

import argparse
import collections
import datetime
import json
import os
import queue
import sys
import threading
import time

# Файл по умолчанию с логами сервера
DEFAULT_LOG_FILE = os.path.join(os.path.dirname(__file__), "server.log")

# Пороговые значения для обнаружения атак.
LOCAL_THRESHOLD = 25          # Запросов от одного IP за локальное окно
LOCAL_WINDOW = 10.0           # Окно времени для локального контроля (секунд)
BLOCK_DURATION = 60.0         # Время блокировки IP (секунд)
GLOBAL_THRESHOLD = 250        # Запросов на весь сервер за глобальное окно
GLOBAL_WINDOW = 5.0           # Окно времени для глобального контроля (секунд)
GLOBAL_ALERT_COOLDOWN = 5.0    # Минимальный интервал между глобальными предупреждениями

LINE_QUEUE_MAXSIZE = 1000
line_queue = queue.Queue(maxsize=LINE_QUEUE_MAXSIZE)

# Состояние детектора
ip_requests = {}              # ip -> deque(timestamp)
global_requests = collections.deque()
blocked_ips = {}              # ip -> unblock_timestamp

global_alert_active = False
last_global_alert = 0.0


def block_ip_firewall(ip):
    """Блокирует IP на уровне firewall (Windows)."""
    try:
        os.system(f'netsh advfirewall firewall add rule name="Block DDoS {ip}" dir=in action=block remoteip={ip}')
        print(f"[FIREWALL] IP {ip} заблокирован на уровне firewall.")
    except Exception as e:
        print(f"[ERROR] Не удалось заблокировать IP {ip} в firewall: {e}")


def unblock_ip_firewall(ip):
    """Разблокирует IP на уровне firewall (Windows)."""
    try:
        os.system(f'netsh advfirewall firewall delete rule name="Block DDoS {ip}"')
        print(f"[FIREWALL] IP {ip} разблокирован на уровне firewall.")
    except Exception as e:
        print(f"[ERROR] Не удалось разблокировать IP {ip} в firewall: {e}")


def parse_firewall_block_rule(line):
    """Извлекает IP из строки правила firewall с именем Block DDoS."""
    marker = "Block DDoS"
    if marker not in line:
        return None
    ip = line.split(marker, 1)[1].strip()
    return ip or None


def clear_all_firewall_blocks():
    """Удаляет все правила блокировки DDoS из firewall и очищает файл blocked_ips.json."""
    global blocked_ips
    try:
        # Получить список правил
        result = os.popen('netsh advfirewall firewall show rule name=all').read()
        firewall_blocks = []
        for line in result.splitlines():
            ip = parse_firewall_block_rule(line)
            if ip:
                firewall_blocks.append(ip)
        for ip in firewall_blocks:
            os.system(f'netsh advfirewall firewall delete rule name="Block DDoS {ip}"')
            print(f"[FIREWALL] Удалено правило для IP {ip}")

        blocked_ips.clear()
        save_blocked_ips()
        print("[FIREWALL] Все правила блокировки DDoS удалены.")
    except Exception as e:
        print(f"[ERROR] Не удалось очистить правила firewall: {e}")


def show_current_blocks():
    """Показать текущие заблокированные IP."""
    if blocked_ips:
        print("[ANTI-DDoS] Текущие заблокированные IP:")
        now = time.time()
        for ip, expire in blocked_ips.items():
            remaining = int(expire - now)
            print(f"  {ip} - разблокировка через {remaining} сек")
    else:
        print("[ANTI-DDoS] Нет заблокированных IP.")
    
    # Также показать правила firewall
    try:
        result = os.popen('netsh advfirewall firewall show rule name=all').read()
        firewall_blocks = [line for line in result.split('\n') if 'Block DDoS' in line]
        if firewall_blocks:
            print("[FIREWALL] Правила блокировки в firewall:")
            for line in firewall_blocks:
                print(f"  {line.strip()}")
        else:
            print("[FIREWALL] Нет правил блокировки в firewall.")
    except Exception as e:
        print(f"[ERROR] Не удалось проверить firewall: {e}")


def load_blocked_ips():
    """Загружает список заблокированных IP из файла."""
    import json
    blocked_ips_file = os.path.join(os.path.dirname(__file__), "blocked_ips.json")
    try:
        with open(blocked_ips_file, "r", encoding="utf-8") as ip_file:
            data = json.load(ip_file)
            return {ip: float(expire) for ip, expire in data.items()}
    except Exception:
        return {}


def save_blocked_ips():
    """Сохраняет текущий список заблокированных IP в файл."""
    import json
    blocked_ips_file = os.path.join(os.path.dirname(__file__), "blocked_ips.json")
    try:
        with open(blocked_ips_file, "w", encoding="utf-8") as ip_file:
            json.dump(blocked_ips, ip_file)
    except Exception as e:
        print(f"[ERROR] Не удалось сохранить blocked_ips.json: {e}")


def load_state():
    """Инициализация списка заблокированных IP при старте."""
    global blocked_ips
    blocked_ips = load_blocked_ips()
    now = time.time()
    changed = False
    for addr in list(blocked_ips):
        if blocked_ips[addr] <= now:
            del blocked_ips[addr]
            changed = True
    
    # Синхронизировать с firewall правилами
    try:
        result = os.popen('netsh advfirewall firewall show rule name=all').read()
        for line in result.splitlines():
            ip = parse_firewall_block_rule(line)
            if ip and ip not in blocked_ips:
                blocked_ips[ip] = now + BLOCK_DURATION  # Добавить с полным временем
                changed = True
    except Exception:
        pass
    
    if changed:
        save_blocked_ips()


def parse_log_line(line):
    """Парсинг логовой строки из Flask-сервера.
    Ожидается формат:
        [LOG] 2026-04-12 14:22:15 | POST | 127.0.0.1 → /
    Возвращает tuple(timestamp, ip, method) или None, если строка не подходит.
    """
    if not line.startswith("[LOG]"):
        return None

    try:
        parts = line.split("|")
        if len(parts) < 3:
            return None

        timestamp_str = parts[0].replace("[LOG]", "", 1).strip()
        method = parts[1].strip()
        ip_part = parts[2].strip()

        ip = ip_part.split("→")[0].split("->")[0].strip()
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        return timestamp.timestamp(), ip, method
    except Exception:
        return None


def cleanup_old_requests(deque_obj, oldest_time):
    """Удаляет старые метки времени из очереди запросов."""
    while deque_obj and deque_obj[0] < oldest_time:
        deque_obj.popleft()


def process_request(timestamp, ip):
    """Обработка одного запроса: локальные и глобальные счётчики."""
    global global_alert_active, last_global_alert

    # Пропускаем заблокированные IP (но не удаляем, cleanup сделает)
    if ip in blocked_ips:
        return

    # Локальные запросы от IP
    ip_deque = ip_requests.setdefault(ip, collections.deque())
    ip_deque.append(timestamp)
    cleanup_old_requests(ip_deque, timestamp - LOCAL_WINDOW)

    # Глобальный счётчик запросов
    global_requests.append(timestamp)
    cleanup_old_requests(global_requests, timestamp - GLOBAL_WINDOW)

    # Проверка локального порога
    local_count = len(ip_deque)
    if local_count > LOCAL_THRESHOLD and ip not in blocked_ips:
        blocked_until = timestamp + BLOCK_DURATION
        blocked_ips[ip] = blocked_until
        save_blocked_ips()
        block_ip_firewall(ip)
        print(f"[ANTI-DDoS] IP {ip} заблокирован! ({local_count} запросов за {int(LOCAL_WINDOW)} сек)")
        return

    # Проверка глобального порога
    global_count = len(global_requests)
    if global_count > GLOBAL_THRESHOLD:
        if not global_alert_active or (timestamp - last_global_alert) >= GLOBAL_ALERT_COOLDOWN:
            print(
                f"[ANTI-DDoS] ОБНАРУЖЕНА РАСПРЕДЕЛЁННАЯ DDoS-АТАКА! Общий трафик: {global_count} req/sec"
            )
            global_alert_active = True
            last_global_alert = timestamp
    else:
        global_alert_active = False


def analyze_logs():
    """Поток анализа, который обрабатывает строки из очереди."""
    while True:
        try:
            line = line_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        parsed = parse_log_line(line)
        if parsed is None:
            continue

        timestamp, ip, _ = parsed
        process_request(timestamp, ip)


def enqueue_line(line):
    """Добавление строки в очередь для обработки."""
    try:
        line_queue.put_nowait(line)
    except queue.Full:
        # Если очередь переполнена, пропускаем старые строки.
        pass


def read_stdin():
    """Чтение строк из stdin в реальном времени."""
    for raw_line in sys.stdin:
        enqueue_line(raw_line.rstrip("\n"))


def follow_file(path):
    """Чтение лог-файла по мере появления новых строк (аналог tail -f)."""
    if not os.path.exists(path):
        print(f"[ERROR] Файл {path} не найден.")
        return

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                enqueue_line(line.rstrip("\n"))
            else:
                time.sleep(0.1)


def parse_args():
    parser = argparse.ArgumentParser(description="Детектор DDoS-атак по логам Flask-сервера.")
    parser.add_argument(
        "--log-file",
        dest="log_file",
        help="Путь к лог-файлу для анализа. Если не указан, пытаемся использовать server.log.",
    )
    parser.add_argument(
        "--clear-blocks",
        action="store_true",
        help="Очистить все блокировки firewall перед запуском.",
    )
    parser.add_argument(
        "--unblock-ip",
        dest="unblock_ip",
        help="Разблокировать конкретный IP адрес.",
    )
    parser.add_argument(
        "--show-blocks",
        action="store_true",
        help="Показать текущие заблокированные IP и правила firewall.",
    )
    return parser.parse_args()


def cleanup_expired_blocks():
    """Поток для автоматической разблокировки истёкших блокировок."""
    while True:
        now = time.time()
        to_unblock = []
        for ip, expire in list(blocked_ips.items()):
            if now >= expire:
                to_unblock.append(ip)
        for ip in to_unblock:
            del blocked_ips[ip]
            unblock_ip_firewall(ip)
        save_blocked_ips()
        time.sleep(10)  # Проверяем каждые 10 секунд


def main():
    args = parse_args()

    if args.clear_blocks:
        clear_all_firewall_blocks()
    elif args.unblock_ip:
        unblock_ip_firewall(args.unblock_ip)
        # Также удалить из blocked_ips
        if args.unblock_ip in blocked_ips:
            del blocked_ips[args.unblock_ip]
            save_blocked_ips()
        return  # Выход после разблокировки
    elif args.show_blocks:
        load_state()
        show_current_blocks()
        return  # Выход после показа

    load_state()
    # Запускаем поток для очистки блокировок
    cleanup_thread = threading.Thread(target=cleanup_expired_blocks, daemon=True)
    cleanup_thread.start()
    analyzer_thread = threading.Thread(target=analyze_logs, daemon=True)
    analyzer_thread.start()

    log_path = args.log_file or (DEFAULT_LOG_FILE if os.path.exists(DEFAULT_LOG_FILE) else None)
    if log_path:
        print(f"[ANTI-DDoS] Анализ файла {log_path}...")
        follow_file(log_path)
    else:
        print("[ANTI-DDoS] Анализ stdin в реальном времени...")
        read_stdin()


if __name__ == "__main__":
    main()
