# app.py - Тестовый стенд для моделирования DDoS-атак
# Логика изменена: сначала логин → потом главная страница

from flask import Flask, render_template, request, redirect, url_for
import datetime
import json
import logging
import os
import time

app = Flask(__name__)
LOG_FILE = os.path.join(os.path.dirname(__file__), "server.log")
BLOCKED_IPS_FILE = os.path.join(os.path.dirname(__file__), "blocked_ips.json")

# Отключаем логи Werkzeug (HTTP access logs), чтобы не спамить консоль
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.disabled = True
app.logger.disabled = True

# Кэш времени последнего лога блокировки для каждого IP (чтобы не спамить)
last_blocked_log = {}


def write_log(line):
    """Запись логов в файл и вывод в консоль."""
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(line + "\n")
    except Exception:
        pass


def write_log_to_file_only(line):
    """Запись логов только в файл (без вывода в консоль)."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(line + "\n")
    except Exception:
        pass


def load_blocked_ips():
    """Загружает список заблокированных IP из файла."""
    try:
        with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as ip_file:
            content = ip_file.read().strip()
            if not content:
                return {}
            data = json.loads(content)
            return {ip: float(expire) for ip, expire in data.items()}
    except FileNotFoundError:
        return {}  # Файл ещё не создан
    except json.JSONDecodeError:
        return {}
    except Exception as e:
        print(f"[ERROR] Ошибка загрузки blocked_ips.json: {e}")
        return {}


def save_blocked_ips(ips):
    """Сохраняет список заблокированных IP в файл."""
    try:
        temp_name = BLOCKED_IPS_FILE + ".tmp"
        with open(temp_name, "w", encoding="utf-8") as ip_file:
            json.dump(ips, ip_file)
        os.replace(temp_name, BLOCKED_IPS_FILE)
    except Exception:
        pass


def clean_blocked_ips():
    """Удаляет из списка IP, время блокировки которых истекло."""
    ips = load_blocked_ips()
    now = time.time()
    changed = False
    for addr in list(ips):
        if ips[addr] <= now:
            del ips[addr]
            changed = True
    if changed:
        save_blocked_ips(ips)
    return ips


def get_page_name(path):
    """Возвращает понятное название страницы."""
    if path == "/":
        return "Страница авторизации"
    elif path == "/dashboard":
        return "Страница дашборда"
    else:
        return f"Страница {path}"


# Логирование всех входящих запросов
@app.before_request
def log_request():
    ip = request.remote_addr or "Unknown"
    blocked_ips = clean_blocked_ips()
    if ip in blocked_ips:
        now = time.time()
        if now - last_blocked_log.get(ip, 0) > 60:  # Логируем блокировку не чаще раза в минуту
            page_name = get_page_name(request.path)
            log_line = f"[BLOCKED] {ip} заблокирован, доступ к {page_name} запрещён"
            write_log(log_line)
            last_blocked_log[ip] = now
        else:
            # Записываем в файл, но не выводим в консоль
            page_name = get_page_name(request.path)
            log_line = f"[BLOCKED] {ip} заблокирован, доступ к {page_name} запрещён"
            write_log_to_file_only(log_line)
        return "403 Forbidden", 403

    time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    page_name = get_page_name(request.path)
    log_line = f"[LOG] {time_now} | {request.method} | {ip} -> {page_name}"
    write_log(log_line)


# ====================== СТРАНИЦА ЛОГИНА (теперь главная /) ======================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        # Логируем попытку входа
        log_line = f"[LOGIN ATTEMPT] IP: {request.remote_addr} | Login: {username} | Password: {password}"
        write_log(log_line)
        
        # Без реальной проверки — просто редирект после отправки формы
        return redirect(url_for("dashboard"))
    
    # GET-запрос — показываем форму логина
    return render_template("login.html")


# ====================== ЗАЩИЩЁННАЯ ГЛАВНАЯ СТРАНИЦА ======================
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ====================== ЗАПУСК ======================
if __name__ == "__main__":
    print("="*70)
    print("   ТЕСТОВЫЙ СТЕНД ДЛЯ DDoS ЗАПУЩЕН")
    print("   Режим: Многопоточный (threaded)")
    print("="*70)
    print(f"Адрес: http://127.0.0.1:5000")
    print("Запущен в production-like режиме\n")
    
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)