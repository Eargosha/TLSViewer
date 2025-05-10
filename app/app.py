import os
import shlex
import subprocess
from datetime import datetime

from flask import Flask, render_template
from flask_socketio import SocketIO, emit

import threading

from core.handshake_analyzer import analyze_handshake, handshake_states, get_connection_key
from core.log_parser import parse_packet
from core.config import Config
from core.log_monitor import LogMonitor
from core.network_utils import get_interfaces

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY
socketio = SocketIO(app, async_mode="threading")
log_monitor = LogMonitor(socketio)


@app.route("/")
def index():
    return render_template("index.html")

@socketio.on("get_interfaces")
def handle_get_interfaces():
    interfaces = get_interfaces()
    if not interfaces:
        emit("system_message", {
            "type": "error",
            "message": "Нет доступных сетевых интерфейсов!",
            "timestamp": datetime.now().isoformat()
        })
        return

    emit("interface_list", {
        "interfaces": [name for name, _ in interfaces],
        "display": [display for _, display in interfaces]
    })


@socketio.on("connect", namespace="/")
def handle_connect():
    """Обработка нового WebSocket подключения"""
    print(f'[+] Client connected!!')

    try:
        # 1. Отправляем метаданные сессии
        emit('system_message', {
            'type': 'connection',
            'message': 'Соединение установлено!',
            'timestamp': datetime.now().isoformat()
        })

        # 2. Отправляем историю логов (если файл существует)
        if os.path.exists(Config.LOG_FILE):
            with open(Config.LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

                # Проверяем начало новой сессии
                if content.startswith("==== NEW SESSION ===="):
                    emit('system_message', {
                        'type': 'session',
                        'message': 'Мониторинг запущен (найдено начало сессии в логе)',
                        'timestamp': datetime.now().isoformat()
                    })

                # Разбираем пакеты из истории
                packets = content.split("====== [TLS Packet -")[1:]

                user_know_about_history = False

                for packet in packets[:Config.HOW_MANY_LOAD_FORM_HISTORY]:

                    if not user_know_about_history:
                        emit('system_message', {
                            'type': 'connection',
                            'message': f'Загрузка первых {Config.HOW_MANY_LOAD_FORM_HISTORY} кадров(frames) из истории',
                            'timestamp': datetime.now().isoformat()
                        })
                        user_know_about_history = True

                    full_packet = "====== [TLS Packet -" + packet
                    parsed_records = parse_packet(full_packet)

                    for record in parsed_records:
                        # Анализируем TLS Handshake для каждого пакета
                        ip_key = analyze_handshake(record)

                        # Если handshake завершён — отправляем статус клиенту
                        state = handshake_states.get(ip_key)
                        if state and "finished" in state["seen_steps"]:
                            status = {
                                "ip": ip_key,
                                "status": "completed",
                                "current_state": state["current_state"],
                                "seen_steps": list(state["seen_steps"]),
                                "last_update": state["last_update"],
                                "participants": state["participants"],
                                "tls_version": state["tls_version"]
                            }
                            socketio.emit("handshake_status", status, namespace="/")

                        # Отправляем пакет на клиентский интерфейс
                        emit('log_update', {
                            'raw_data': full_packet,
                            'parsed_data': record,
                            'is_handshake': record['is_handshake'],
                            'is_history': True
                        })

        # 3. Отправляем статистику
        emit('server_stats', {
            'clients_connected': len(socketio.server.manager.rooms['/']),
            'log_size': os.path.getsize(Config.LOG_FILE) if os.path.exists(Config.LOG_FILE) else 0,
            'monitoring_active': log_monitor.running
        })

    except Exception as e:
        print(f"Connection error for client: {str(e)}")
        emit('system_message', {
            'type': 'error',
            'message': f'Ошибка инициализации: {str(e)}'
        })

# Храним запущенный процесс
daemon_process = None

@socketio.on("start_daemon")
def handle_start_daemon(data):
    global daemon_process

    if daemon_process and daemon_process.poll() is None:
        emit("system_message", {
            "type": "info",
            "message": f"Daemon уже запущен (PID: {daemon_process.pid})",
            "timestamp": datetime.now().isoformat()
        })
        return

    try:
        selected_iface = data.get("interface")
        print(f"{data.get("mode")} mode")
        mode = data.get("mode", "all")  # all / url
        url = data.get("url", "")

        if not selected_iface:
            emit("system_message", {
                "type": "error",
                "message": "Не указан интерфейс!",
                "timestamp": datetime.now().isoformat()
            })
            return

        args = ["python", "../deamon.py", "--interface", selected_iface]

        if mode == "url" and url:
            args.extend(["--url", url, '--mode', mode])

        print(f"Запускаем с {args}")

        daemon_process = subprocess.Popen(
            args,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            cwd=os.path.dirname(__file__)
        )

        emit("system_message", {
            "type": "info",
            "message": f"Daemon запущен (PID: {daemon_process.pid})",
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        emit("system_message", {
            "type": "error",
            "message": f"Ошибка запуска демона: {str(e)}",
            "timestamp": datetime.now().isoformat()
        })


@socketio.on("stop_daemon")
def handle_stop_daemon():
    global daemon_process

    if daemon_process:
        os.system(f"taskkill /F /PID {daemon_process.pid}")
        emit("system_message", {
            "type": "info",
            "message": "Daemon успешно остановлен",
            "timestamp": datetime.now().isoformat()
        })
    else:
        emit("system_message", {
            "type": "info",
            "message": "Daemon не запущен",
            "timestamp": datetime.now().isoformat()
        })

@socketio.on("clear_log")
def handle_stop_daemon():
    open(Config.TLS_PACKETS_LOG, 'w')



@socketio.on("request_handshake_status")
def handle_handshake_status(data):
    ip = data.get("ip")

    print(handshake_states)

    # Парсим IP как A:B или B:A
    try:
        src, dst = ip.split(":")
    except ValueError:
        emit("handshake_status", {"error": "Invalid format. Use 'IP1:IP2'."})
        return

    ip_key = get_connection_key(src, dst)
    state = handshake_states.get(ip_key)

    if not state:
        emit("handshake_status", {"error": f"No handshake found for {ip_key}"})
        return

    status = "completed" if "finished" in state["seen_steps"] else "in progress"

    response = {
        "ip": ip_key,
        "status": status,
        "current_state": state["current_state"],
        "seen_steps": list(state["seen_steps"]),
        "last_update": state["last_update"],
        "participants": state["participants"],
        "tls_version": state["tls_version"],
        "sni": state["sni"]
    }

    emit("handshake_status", response)

@socketio.on("request_all_handshakes")
def handle_get_all_handshakes():
    all_states = []
    for ip_key, state in handshake_states.items():
        status = "completed" if "finished" in state["seen_steps"] else "in progress"
        all_states.append({
            "ip": ip_key,
            "status": status,
            "current_state": state["current_state"],
            "seen_steps": list(state["seen_steps"]),
            "last_update": state["last_update"],
            "participants": state["participants"],
            "tls_version": state.get("tls_version", "TLS 1.2"),
            "sni":state.get("sni")
        })
    emit("all_handshakes", all_states)

if __name__ == "__main__":
    monitor_thread = threading.Thread(target=log_monitor.monitor_log_file)
    monitor_thread.daemon = True
    monitor_thread.start()

    try:
        socketio.run(app, debug=True, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        log_monitor.stop()
        monitor_thread.join()