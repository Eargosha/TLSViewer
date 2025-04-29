import os
import time
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import threading

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key"
socketio = SocketIO(app, async_mode="threading")

LOG_FILE = "..\\tls_packets.log"
last_position = 0


def parse_packet(packet_content):
    """Парсинг содержимого пакета в структурированный формат"""
    packet_data = {
        "timestamp": None,
        "is_handshake": 0,
        "attributes": {},
        "errors": [],
        "source": None,
        "destination": None,
    }

    lines = packet_content.split("\n")
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Извлечение временной метки
        if line.startswith("====== [TLS Packet -"):
            timestamp = line.split("[TLS Packet - ")[1].split("]")[0].strip()
            packet_data["timestamp"] = timestamp
            continue

        # Проверка на handshake
        if line == "TLS Handshake Detected:":
            packet_data["is_handshake"] = 1
            continue

        # Извлечение source/destination
        if line.startswith("Source:"):
            src_dst = line.split(" --> ")
            packet_data["source"] = src_dst[0].replace("Source: ", "").strip()
            packet_data["destination"] = src_dst[1].replace("Destination: ", "").strip()
            continue

        # Обработка ошибок
        if line.startswith("[-] Ошибка"):
            packet_data["errors"].append(line)
            continue

        # Парсинг атрибутов (key: value)
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            # Обработка специальных случаев
            if key == "handshake_ciphersuite":
                value = f"0x{value[2:].upper()}" if value.startswith("0x") else value

            packet_data["attributes"][key] = value

    return packet_data


# def monitor_log_file():
#     """Monitor the log file for changes and emit new content"""
#     global last_position

#     while True:
#         if not os.path.exists(LOG_FILE):
#             # Даем время на создание log
#             time.sleep(1)
#             continue

#         try:
#             with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
#                 # Go to the end if it's a new file
#                 if last_position == 0:
#                     f.seek(0, 2)
#                     last_position = f.tell()
#                     time.sleep(1)
#                     continue

#                 # Check if file was rotated
#                 current_size = os.path.getsize(LOG_FILE)
#                 if current_size < last_position:
#                     last_position = 0
#                     continue

#                 # Read new content
#                 f.seek(last_position)
#                 new_content = f.read()
#                 if new_content:
#                     socketio.emit('log_update', {'data': new_content}, namespace='/')
#                     last_position = f.tell()

#         except Exception as e:
#             print(f"Error monitoring log file: {e}")

#         # Меньше проца кушаем
#         time.sleep(0.1)


def monitor_log_file():
    """Monitor the log file for changes and emit new content"""
    global last_position

    while True:
        if not os.path.exists(LOG_FILE):
            time.sleep(1)
            continue

        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                if last_position == 0:
                    f.seek(0, 2)
                    last_position = f.tell()
                    time.sleep(1)
                    continue

                current_size = os.path.getsize(LOG_FILE)
                if current_size < last_position:
                    last_position = 0
                    continue

                f.seek(last_position)
                new_content = f.read()
                if new_content:
                    # Разделяем на отдельные пакеты
                    packets = new_content.split("====== [TLS Packet -")
                    for packet in packets[1:]:  # Первый элемент пустой
                        full_packet = "====== [TLS Packet -" + packet
                        parsed = parse_packet(full_packet)

                        # Отправка структурированных данных
                        socketio.emit(
                            "log_update",
                            {
                                "raw_data": full_packet,
                                "parsed_data": parsed,
                                "is_handshake": parsed["is_handshake"],
                            },
                            namespace="/",
                        )

                    last_position = f.tell()

        except Exception as e:
            print(f"Error monitoring log file: {e}")

        time.sleep(0.1)


# @socketio.on('connect', namespace='/')
# def handle_connect():
#     """Handle new WebSocket connection"""
#     print('Client connected')
#     # Send existing log content when client first connects
#     if os.path.exists(LOG_FILE):
#         try:
#             with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
#                 content = f.read()
# if content == "==== NEW SESSION ====":
#     emit('log_update', {'data': content, 'new_session':1})
#                 emit('log_update', {'data': content})
#         except Exception as e:
#             print(f"Error reading log file: {e}")


@socketio.on("connect", namespace="/")
def handle_connect():
    """Handle new WebSocket connection"""
    print("Client connected")
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
                if content == "==== NEW SESSION ====":
                    emit("log_update", {"data": content, "new_session": 1})
                packets = content.split("====== [TLS Packet -")[
                    1:
                ]  # Игнорируем первый пустой элемент

                for packet in packets:
                    full_packet = "====== [TLS Packet -" + packet
                    parsed = parse_packet(full_packet)
                    emit(
                        "log_update",
                        {
                            "raw_data": full_packet,
                            "parsed_data": parsed,
                            "is_handshake": parsed["is_handshake"],
                        },
                    )

                # Отправляем маркер завершения начальной загрузки
                emit("initial_load_complete")

        except Exception as e:
            print(f"Error reading log file: {e}")


@app.route("/")
def index():
    """Render the main page"""
    return render_template("index.html")


if __name__ == "__main__":
    # Start background thread before running the app
    thread = threading.Thread(target=monitor_log_file)
    thread.daemon = True
    thread.start()

    # Run the app
    socketio.run(app, debug=True, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
