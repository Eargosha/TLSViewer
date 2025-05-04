# Захват трафика
import json
import queue
import subprocess
import time

import pyshark
import asyncio
import threading

from scapy.layers.inet import IP
from scapy.layers.tls.record import TLS

from tls_monitor.config import Config
from datetime import datetime
from tls_parser.parser import TlsRecordParser
from tls_parser.exceptions import NotEnoughData, UnknownTypeByte
from OpenSSL import SSL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii


# class TrafficSniffer:
#     def __init__(self, interface):
#         self.interface = interface
#         self.log_file = open(Config.TLS_PACKETS_LOG, "w", encoding='utf-8')
#         self._stop_event = threading.Event()
#         self._capture = None
#         self._thread = None
#         self._tshark_decrypt_process = None  # Процесс tshark для расшифровки
#         self._decrypted_data_cache = {}  # Кэш для хранения расшифрованных данных
#         self._decrypted_queue = queue.Queue()  # Потокобезопасная очередь для расшифрованных данных
#         self._session_started = False
#
#     def _write_session_header(self):
#         """Записывает заголовок новой сессии в начало файла (с очисткой файла)"""
#         session_header = f"==== NEW SESSION ====\n\n"
#
#         # Просто открываем файл в режиме записи (перезаписываем)
#         self.log_file.write(session_header)
#         self.log_file.flush()
#         self._session_started = True
#
#
    # # Основная функция распределения видов TLS пакетов, тут же производятся попытки расшифровки
    # def _process_packet(self, packet):
    #     """Обработка отдельного пакета"""
    #     if 'tls' in packet and (packet.ip.src == Config.TARGET_IP or packet.ip.dst == Config.TARGET_IP):
    #         current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    #         log_entry = f"====== [TLS Packet - {current_time}] ======\n"
    #         parsed_record = None
    #
    #         content_type = '0'
    #         opaque_type = '0'
    #
    #         try:
    #             content_type = str(packet.tls.record_content_type)
    #         except AttributeError:
    #             print("[DEBUG -] record_content_type отсутствует")
    #
    #         try:
    #             opaque_type = str(packet.tls.record_opaque_type)
    #         except AttributeError:
    #             print("[DEBUG -] record_opaque_type отсутствует")
    #
    #         if content_type == '0' and opaque_type == '0':
    #             log_entry += 'TLS Recognition Error:\n'
    #
    #         # Определяем версию TLS
    #         tls_version = 'TLS1.2'
    #         if hasattr(packet.tls, 'record_version'):
    #             if packet.tls.record_version == '0x0304':
    #                 tls_version = 'TLS1.3'
    #
    #         # [===] Обработка Alert
    #         if hasattr(packet.tls, 'record'):
    #             if content_type == "21":
    #                 log_entry += "TLS Alert Detected:\n"
    #
    #         # [===] Обработка Application
    #         if hasattr(packet.tls, 'record'):
    #             if content_type == "23" or (opaque_type == "23" and content_type == "0"):
    #                 log_entry += "TLS Application Detected:\n"
    #
    #
    #         # [===] Обработка ChangeCipherSpec
    #         if hasattr(packet.tls, 'record'):
    #             if content_type == "20":
    #                 log_entry += "TLS ChangeCipherSpec Detected:\n"
    #
    #
    #         # [===] Обработка Handshake
    #         if hasattr(packet.tls, 'record'):
    #             if content_type == "22":
    #                 log_entry += "TLS Handshake Detected:\n"
    #
    #
    #         # [===] Основное логирование полей TLS, доступных для чтения
    #         tls_layer = packet.tls
    #         for field in tls_layer.field_names:
    #             try:
    #                 log_entry += f"{field}: {getattr(tls_layer, field)}\n"
    #             except AttributeError:
    #                 continue
    #
    #         # [===] IP адреса пакета
    #         log_entry += f"Source: {packet.ip.src} --> Destination: {packet.ip.dst}\n\n"
    #
    #         # [===] Потокобезопасная запись в лог (Возможно тут иногда и происходит стопор)
    #         self.log_file.write(log_entry)
    #         self.log_file.flush()
    #         print(log_entry)

#
#     def _capture_loop(self):
#         """Основной цикл захвата пакетов"""
#         loop = asyncio.new_event_loop()
#         asyncio.set_event_loop(loop)
#
#         try:
#             self._capture = pyshark.LiveCapture(
#                 interface=self.interface,
#                 override_prefs={
#                     'tls.keylog_file': Config.SSL_KEY_LOG_FILE,
#                 },
#                 tshark_path=Config.TSHARK_PATH,
#                 # debug=True,
#                 # custom_parameters=[
#                 #     # '-o', f'tls.keylog_file:{Config.SSL_KEY_LOG_FILE}',
#                 #     # '-o', f'tls.debug_file:{Config.TLS_DEBUG_LIVE_CAPTURE_FILE}'  # Для диагностики
#                 # ]
#                 # custom_parameters=['-o', 'tls.keylog_file:' + Config.SSL_KEY_LOG_FILE]
#             )
#
#             self._write_session_header()
#
#             for packet in self._capture.sniff_continuously():
#                 if self._stop_event.is_set():
#                     break
#                 self._process_packet(packet)
#         except Exception as e:
#             print(f"Capture error: {str(e)}")
#         finally:
#             if hasattr(self, '_capture'):
#                 self._capture.close()
#             loop.close()
#             self.log_file.close()
#
#     def start_capture(self):
#         """Запуск захвата в отдельном потоке"""
#         if not self._thread or not self._thread.is_alive():
#             self._stop_event.clear()
#             self._thread = threading.Thread(target=self._capture_loop, daemon=True)
#             self._thread.start()
#
#     def stop_capture(self):
#         """Корректная остановка захвата"""
#         self._stop_event.set()
#         if self._thread and self._thread.is_alive():
#             self._thread.join(timeout=5)
#         if hasattr(self, '_capture') and self._capture:
#             self._capture.close()


# # С ИСПОЛЬЗОВАНИЕ САБПРОЦЕССА TSHARK.EXE. РАСШИФРОВКА РАБОТАЕТ, ВИДНО ДАЖЕ HTML, но выводит лишнюю инфу по TCP и IP traffic_sniffer.py
import subprocess
import threading
import re
from tls_monitor.config import Config

import subprocess
import threading
import re
from datetime import datetime
from tls_monitor.config import Config

class TrafficSniffer:
    def __init__(self, interface):
        self.interface = interface
        self._stop_event = threading.Event()
        self._process = None

    def _capture_loop(self):
        # Начало новой сессии
        with open(Config.TLS_PACKETS_LOG, 'a', encoding='utf-8') as log_file:
            log_file.write("==== NEW SESSION ====\n")
            print("==== NEW SESSION ====")

        # 1 var
        # command = [
        #     Config.TSHARK_PATH,
        #     '-i', self.interface,
        #     '-f', f'ip host {Config.TARGET_IP}',
        #     '-o', f'tls.keylog_file:{Config.SSL_KEY_LOG_FILE}',
        #     '-Y', 'tls',
        #     '-O', 'tls',
        #     '-l'
        # ]

        # 2 var
        command = [
            Config.TSHARK_PATH,
            '-i', self.interface,
            '-f', f'ip host {Config.TARGET_IP}',
            '-o', f'tls.keylog_file:{Config.SSL_KEY_LOG_FILE}',
            '-Y', 'tls',  # Фильтруем только TLS-пакеты
            '-V',  # Показываем структуру пакета
            '-l'  # Буферизация по строкам
        ]

        self._process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=False
        )

        with open(Config.TLS_PACKETS_LOG, 'a', encoding='utf-8') as log_file:
            current_frame = []
            frame_time = None
            frame_type = "UNKNOWN"

            while not self._stop_event.is_set():
                line_bytes = self._process.stdout.readline()
                if not line_bytes:
                    break

                try:
                    line = line_bytes.decode('utf-8', errors='replace')
                except UnicodeDecodeError:
                    line = "[BINARY DATA]"

                if line.startswith("Frame "):
                    if current_frame:
                        self._process_frame(current_frame, frame_type, frame_time, log_file)

                    frame_time = self._extract_frame_time(line)
                    current_frame = [line]
                    frame_type = "UNKNOWN"
                else:
                    current_frame.append(line)
                    detected = self._detect_tls_type([line])  # Проверяем только эту строку
                    if detected != "UNKNOWN":
                        frame_type = detected

            if current_frame:
                self._process_frame(current_frame, frame_type, frame_time, log_file)

    def _extract_frame_time(self, line):
        match = re.search(r'on (\w+ \d+ \d+:\d+:\d+\.\d+)', line)
        if match:
            time_str = match.group(1)
            try:
                dt = datetime.strptime(time_str, "%b %d %H:%M:%S.%f")
                return dt.strftime("2025-%m-%d %H:%M:%S.%f")[:-3]
            except Exception:
                pass
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _detect_tls_type(self, frame_lines):
        for line in frame_lines:
            if re.search(r'TLSv[0-9.]+ Record Layer: Change Cipher Spec Protocol: Change Cipher Spec', line):
                return "Cipher"
        for line in frame_lines:
            if re.search(r'Handshake Protocol: (?!Encrypted Extensions)', line):
                return "Handshake"
        for line in frame_lines:
            if re.search(r'Content Type: Application Data', line):
                return "Application"
        for line in frame_lines:
            if re.search(r'Alert Protocol', line):
                return "Alert"
        return "UNKNOWN"

    def _process_frame(self, frame_lines, frame_type, frame_time, log_file):
        time_header = f"\n====== [TLS Packet - {frame_time}] ======\n"
        log_file.write(time_header)
        print(time_header.strip())

        type_header = f"[TYPE: {frame_type}]\n"
        log_file.write(type_header)
        print(type_header.strip())

        content = ''.join(frame_lines)
        log_file.write(content)
        print(content, end='')

        # Извлечение текстовых данных
        in_text_data = False
        for line in frame_lines:
            if "Line-based text data:" in line:
                in_text_data = True
                print("\n[HTTP/2 CONTENT START]")
                continue
            if in_text_data and line.strip() == "":
                break
            if in_text_data:
                print(line, end='')
        if in_text_data:
            print("[HTTP/2 CONTENT END]")

    # def _process_frame(self, frame_lines, frame_type, frame_time, log_file):
    #     time_header = f"\n====== [TLS Packet - {frame_time}] ======\n"
    #     log_file.write(time_header)
    #     print(time_header.strip())
    #
    #     type_header = f"[TYPE: {frame_type}]\n"
    #     log_file.write(type_header)
    #     print(type_header.strip())
    #
    #     content = ''.join(frame_lines)
    #     log_file.write(content)
    #     print(content, end='')

    def start_capture(self):
        self._thread = threading.Thread(target=self._capture_loop)
        self._thread.start()

    def stop_capture(self):
        self._stop_event.set()
        if self._process:
            self._process.terminate()
        if self._thread:
            self._thread.join()