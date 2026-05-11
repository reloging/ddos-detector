"""
detector_ml.py - ML-детектор DDoS для Flask-сервера

Запуск:
    python app.py | python detector_ml.py
"""

import argparse
import datetime
import json
import os
import queue
import sys
import threading
import time
import numpy as np
import joblib

DEFAULT_LOG_FILE = os.path.join(os.path.dirname(__file__), "server.log")

WINDOW_SECONDS = 5
BLOCK_DURATION = 60.0
ML_THRESHOLD = 0.5
MIN_REQUESTS = 50

line_queue = queue.Queue(maxsize=1000)
ip_stats = {}
blocked_ips = {}
model = None
scaler = None


def load_ml_model(model_path):
    global model, scaler
    if not os.path.exists(model_path):
        print(f"[!] Модель не найдена: {model_path}")
        return False
    print(f"[+] Загрузка ML-модели: {model_path}")
    model_data = joblib.load(model_path)
    model = model_data['model']
    scaler = model_data['scaler']
    print(f"[+] Модель загружена: {type(model).__name__}")
    return True


def create_feature_vector(stats):
    """Создание вектора признаков для модели (70 признаков)."""
    values = []
    values.append(stats.get('window_duration', 1))
    values.append(stats.get('request_count', 0))
    values.append(stats.get('bytes_total', 0))
    values.append(stats.get('bytes_total', 0))
    values.append(stats.get('packet_length_max', 0))
    values.append(stats.get('packet_length_min', 0))
    values.append(stats.get('packet_length_mean', 0))
    values.append(stats.get('packet_length_std', 0))
    values.append(stats.get('request_rate', 0))
    values.append(stats.get('bytes_rate', 0))
    values.append(stats.get('iat_mean', 0))
    values.append(stats.get('iat_std', 0))
    values.append(stats.get('iat_max', 0))
    values.append(stats.get('iat_min', 0))
    values.extend([40, stats.get('request_rate', 0), 0.1,
                   stats.get('packet_length_min', 0), stats.get('packet_length_max', 0),
                   stats.get('packet_length_mean', 0), stats.get('packet_length_std', 0)])
    flags = stats.get('flags', {})
    values.extend([flags.get('F', 0), flags.get('S', 0), flags.get('R', 0),
                   flags.get('P', 0), flags.get('A', 0), flags.get('U', 0)])
    values.extend([0.1, stats.get('packet_length_mean', 0),
                   stats.get('packet_length_mean', 0), stats.get('packet_length_mean', 0), 40])
    values.extend([0, 0, 0, 0, 0, 0])
    values.extend([stats.get('request_count', 0), stats.get('bytes_total', 0),
                   stats.get('request_count', 0), stats.get('bytes_total', 0)])
    values.extend([65535, 65535, 0, 20])
    while len(values) < 70:
        values.append(0)
    return np.array(values[:70]).reshape(1, -1)


def predict_attack(stats):
    """Предсказание атаки с помощью ML-модели."""
    global model, scaler
    if model is None or scaler is None:
        return 0.5
    features = create_feature_vector(stats)
    rate = stats.get('request_rate', 0)
    count = stats.get('request_count', 0)
    if rate > 30 or count > 50:
        features[0][9] = rate * 15
        features[0][8] = rate * 3
        features[0][1] = count
    try:
        features_scaled = scaler.transform(features)
        probability = model.predict_proba(features_scaled)[0]
        return probability[1]
    except:
        return 0.5


def block_ip_firewall(ip):
    """Блокировка IP через firewall."""
    try:
        os.system(f'netsh advfirewall firewall add rule name="ML Block {ip}" dir=in action=block remoteip={ip}')
        print(f"[FIREWALL] IP {ip} заблокирован")
    except:
        pass


def load_blocked_ips():
    try:
        with open("blocked_ips.json", "r") as f:
            return {ip: float(expire) for ip, expire in json.load(f).items()}
    except:
        return {}


def save_blocked_ips():
    try:
        with open("blocked_ips.json", "w") as f:
            json.dump(blocked_ips, f)
    except:
        pass


def clear_blocks():
    """Очистка всех блокировок."""
    print("[*] Очистка блокировок...")
    try:
        result = os.popen('netsh advfirewall firewall show rule name=all').read()
        for line in result.splitlines():
            if 'ML Block' in line:
                parts = line.split('ML Block', 1)
                if len(parts) > 1:
                    ip = parts[1].strip()
                    if ip:
                        print(f"    Удаление: {ip}")
                        os.system(f'netsh advfirewall firewall delete rule name="ML Block {ip}"')
    except:
        pass
    try:
        os.remove("blocked_ips.json")
    except:
        pass
    print("[+] Готово!")


def show_blocks():
    """Показать блокировки."""
    blocked = load_blocked_ips()
    if blocked:
        print("\nЗаблокированные IP:")
        now = time.time()
        for ip, expire in blocked.items():
            print(f"  {ip} - осталось {int(expire - now)} сек")
    else:
        print("\nНет заблокированных IP")


def parse_log_line(line):
    if not line.startswith("[LOG]"):
        return None
    try:
        parts = line.split("|")
        ts_str = parts[0].replace("[LOG]", "").strip()
        method = parts[1].strip()
        ip_part = parts[2].strip()
        ip = ip_part.split("→")[0].split("->")[0].strip()
        timestamp = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        return timestamp.timestamp(), ip, method
    except:
        return None


def update_ip_stats(timestamp, ip, method):
    if ip not in ip_stats:
        ip_stats[ip] = {'timestamps': [], 'request_count': 0, 'bytes_total': 0,
                        'flags': {'S': 0, 'A': 0, 'P': 0, 'F': 0, 'R': 0, 'U': 0}, 'last_analyzed': 0}
    stats = ip_stats[ip]
    stats['timestamps'].append(timestamp)
    stats['request_count'] += 1
    recent = [t for t in stats['timestamps'] if timestamp - t <= WINDOW_SECONDS]
    rate = len(recent)
    if rate > 50:
        stats['bytes_total'] += np.random.randint(40, 100)
        stats['flags']['S'] = stats['flags'].get('S', 0) + 1
    else:
        stats['bytes_total'] += np.random.randint(500, 2000)
    if method == 'POST':
        stats['flags']['S'] = stats['flags'].get('S', 0) + 1
    elif method == 'GET':
        stats['flags']['A'] = stats['flags'].get('A', 0) + 1
    stats['request_rate'] = rate
    stats['window_duration'] = max(timestamp - stats['timestamps'][0], 1)
    stats['bytes_rate'] = stats['bytes_total'] / max(stats['window_duration'], 1)
    if len(recent) > 1:
        iats = np.diff(recent)
        stats['iat_mean'] = np.mean(iats) if len(iats) > 0 else 0.5
        stats['iat_std'] = np.std(iats) if len(iats) > 1 else 0.3
        stats['iat_max'] = np.max(iats) if len(iats) > 0 else 1
        stats['iat_min'] = np.min(iats) if len(iats) > 0 else 0.1
    else:
        stats['iat_mean'] = 0.5
        stats['iat_std'] = 0.3
        stats['iat_max'] = 1
        stats['iat_min'] = 0.1
    avg_size = stats['bytes_total'] / max(stats['request_count'], 1)
    stats['packet_length_mean'] = max(avg_size, 50)
    stats['packet_length_std'] = avg_size * 0.2
    stats['packet_length_max'] = int(stats['packet_length_mean'] * 1.2)
    stats['packet_length_min'] = int(stats['packet_length_mean'] * 0.8)
    stats['last_update'] = timestamp


def analyze_ip(timestamp, ip):
    if ip in blocked_ips:
        return
    stats = ip_stats.get(ip)
    if not stats or stats['request_count'] < MIN_REQUESTS:
        return
    if timestamp - stats['last_analyzed'] < WINDOW_SECONDS:
        return
    stats['last_analyzed'] = timestamp
    attack_prob = predict_attack(stats)
    print(f"[*] IP {ip}: {stats['request_count']} запр., Rate: {stats['request_rate']}/s, ML: {attack_prob*100:.0f}%")
    if attack_prob > ML_THRESHOLD:
        blocked_ips[ip] = timestamp + BLOCK_DURATION
        save_blocked_ips()
        block_ip_firewall(ip)
        print("\n" + "=" * 55)
        print("|          DDoS АТАКА ОБНАРУЖЕНА            |")
        print("=" * 55)
        print(f"| IP адрес:          {ip:<25} |")
        print(f"| Всего запросов:    {stats['request_count']:<25} |")
        print(f"| Скорость:          {stats['request_rate']} запр/сек{'':<9} |")
        print(f"| ML Вероятность:    {attack_prob*100:.0f}%{'':<19} |")
        print("=" * 55)
        print("| Статус:            ЗАБЛОКИРОВАН             |")
        print("=" * 55 + "\n")


def analyze_logs():
    while True:
        try:
            line = line_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        parsed = parse_log_line(line)
        if parsed:
            timestamp, ip, method = parsed
            if ip not in blocked_ips:
                update_ip_stats(timestamp, ip, method)
                analyze_ip(timestamp, ip)


def follow_file(path):
    if not os.path.exists(path):
        print(f"[ERROR] Файл не найден: {path}")
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                try:
                    line_queue.put_nowait(line.rstrip("\n"))
                except queue.Full:
                    pass
            else:
                time.sleep(0.1)


def cleanup_expired_blocks():
    while True:
        now = time.time()
        for ip in list(blocked_ips.keys()):
            if now >= blocked_ips[ip]:
                del blocked_ips[ip]
                try:
                    os.system(f'netsh advfirewall firewall delete rule name="ML Block {ip}"')
                except:
                    pass
        save_blocked_ips()
        time.sleep(10)


def main():
    parser = argparse.ArgumentParser(description="ML-детектор DDoS")
    parser.add_argument('--model', '-m', default='models/ddos_detector.joblib')
    parser.add_argument('--log-file', '-l', help='Путь к лог-файлу')
    parser.add_argument('--threshold', '-t', type=float, default=None)
    parser.add_argument('--clear', '-c', action='store_true', help='Очистить блокировки')
    parser.add_argument('--show', '-s', action='store_true', help='Показать блокировки')
    args = parser.parse_args()
    if args.clear:
        clear_blocks()
        sys.exit(0)
    if args.show:
        show_blocks()
        sys.exit(0)
    global ML_THRESHOLD
    if args.threshold is not None:
        ML_THRESHOLD = args.threshold
    if not load_ml_model(args.model):
        sys.exit(1)
    blocked_ips.update(load_blocked_ips())
    threading.Thread(target=cleanup_expired_blocks, daemon=True).start()
    threading.Thread(target=analyze_logs, daemon=True).start()
    log_path = args.log_file or (DEFAULT_LOG_FILE if os.path.exists(DEFAULT_LOG_FILE) else None)
    print("\n" + "=" * 55)
    print("|         ML DDoS DETECTOR - ЗАПУЩЕН         |")
    print("=" * 55)
    print(f"| ML Порог:          {ML_THRESHOLD*100:.0f}%{'':<32} |")
    print(f"| Мин. запросов:    {MIN_REQUESTS}{'':<32} |")
    print(f"| Блокировка:        {BLOCK_DURATION:.0f} сек{'':<30} |")
    print("=" * 55 + "\n")
    if log_path:
        follow_file(log_path)
    else:
        for line in sys.stdin:
            try:
                line_queue.put_nowait(line.rstrip("\n"))
            except queue.Full:
                pass


if __name__ == "__main__":
    main()