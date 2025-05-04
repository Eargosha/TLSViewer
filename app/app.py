import os
from datetime import datetime

from flask import Flask, render_template
from flask_socketio import SocketIO, emit

import threading

from core.log_parser import parse_packet
from core.config import Config
from core.log_monitor import LogMonitor

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY
socketio = SocketIO(app, async_mode="threading")
log_monitor = LogMonitor(socketio)


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("connect", namespace="/")
def handle_connect():
    """Обработка нового WebSocket подключения"""
    print(f'[+] Client connected!!')

    try:
        # 1. Отправляем метаданные сессии
        emit('system_message', {
            'type': 'connection',
            'message': 'Connection established',
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
                        'message': 'New monitoring session started',
                        'timestamp': datetime.now().isoformat()
                    })

                # Отправляем историю по частям (чтобы не перегружать канал)
                packets = content.split("====== [TLS Packet -")[1:]
                for packet in packets[:100]:
                    full_packet = "====== [TLS Packet -" + packet
                    parsed_records = parse_packet(full_packet)

                    for record in parsed_records:
                        emit('log_update', {
                            'raw_data': full_packet,  # или record.get('raw_snippet')
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
            'message': f'Initialization failed: {str(e)}'
        })


if __name__ == "__main__":
    monitor_thread = threading.Thread(target=log_monitor.monitor_log_file)
    monitor_thread.daemon = True
    monitor_thread.start()

    try:
        socketio.run(app, debug=True, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        log_monitor.stop()
        monitor_thread.join()