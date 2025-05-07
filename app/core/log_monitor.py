import os
import time
from flask_socketio import SocketIO, emit

# Ошибка в имортах это норма
from core.config import Config
from core.log_parser import parse_packet

class LogMonitor:
    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        self.last_position = 0
        self.running = False

    def monitor_log_file(self):
        """Monitor the log file for changes and emit new content"""
        print("[+] Мониторинрг начали")
        self.running = True
        while self.running:
            if not os.path.exists(Config.LOG_FILE):
                time.sleep(1)
                continue

            try:
                with open(Config.LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                    if self.last_position == 0:
                        f.seek(0, 2)
                        self.last_position = f.tell()
                        time.sleep(1)
                        continue

                    current_size = os.path.getsize(Config.LOG_FILE)
                    if current_size < self.last_position:
                        self.last_position = 0
                        continue

                    f.seek(self.last_position)
                    new_content = f.read()

                    if new_content:
                        packets = new_content.split("====== [TLS Packet -")
                        for packet in packets[1:]:
                            full_packet = "====== [TLS Packet -" + packet
                            parsed_records = parse_packet(full_packet)

                            if parsed_records is not None:
                                for record in parsed_records:
                                    if record is not None:
                                        self.socketio.emit(
                                            "log_update",
                                            {
                                                "raw_data": full_packet,
                                                "parsed_data": record,
                                                "is_handshake": record.get("is_handshake", False),
                                            },
                                            namespace="/",
                                        )
                            else:
                                print(f"[!] Failed to parse packet:\n{full_packet}")
                        self.last_position = f.tell()

            except Exception as e:
                print(f"Error monitoring log file: {e}")

            time.sleep(Config.MONITOR_INTERVAL)

    def stop(self):
        self.running = False