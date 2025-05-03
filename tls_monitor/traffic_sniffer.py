# Захват трафика
import pyshark
import asyncio
import threading
from tls_monitor.config import Config
from datetime import datetime
from tls_parser.parser import TlsRecordParser
from tls_parser.exceptions import NotEnoughData, UnknownTypeByte
from OpenSSL import SSL


class TrafficSniffer:
    def __init__(self, interface):
        self.interface = interface
        self.log_file = open(Config.TLS_PACKETS_LOG, "w", encoding='utf-8')
        self._stop_event = threading.Event()
        self._capture = None
        self._thread = None

    def _write_session_header(self):
        """Записывает заголовок новой сессии в начало файла (с очисткой файла)"""
        session_header = f"==== NEW SESSION ====\n\n"

        # Просто открываем файл в режиме записи (перезаписываем)
        self.log_file.write(session_header)
        self.log_file.flush()
        self._session_started = True

    def _parse_tls_record(self, raw_bytes):
        """Парсинг TLS записи с помощью tls-parser"""
        try:
            record, len_consumed = TlsRecordParser.parse_bytes(raw_bytes)
            return str(record)
        except (NotEnoughData, UnknownTypeByte) as e:
            return f"[-] TLS parsing error: {str(e)}"

    # Основная функция распределения видов TLS пакетов, тут же производятся попытки расшифровки
    def _process_packet(self, packet):
        """Обработка отдельного пакета"""
        if 'tls' in packet and (packet.ip.src == Config.TARGET_IP or packet.ip.dst == Config.TARGET_IP):
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            log_entry = f"====== [TLS Packet - {current_time}] ======\n"
            parsed_record = None

            content_type = '0'
            opaque_type = '0'

            try:
                content_type = str(packet.tls.record_content_type)
            except AttributeError:
                print("[DEBUG -] record_content_type отсутствует")

            try:
                opaque_type = str(packet.tls.record_opaque_type)
            except AttributeError:
                print("[DEBUG -] record_opaque_type отсутствует")

            if content_type == '0' and opaque_type == '0':
                log_entry += 'TLS Recognition Error:\n'



            # [===] Обработка Alert
            if hasattr(packet.tls, 'record'):
                if content_type == "21":
                    log_entry += "TLS Alert Detected:\n"


            # [===] Обработка Application
            if hasattr(packet.tls, 'record'):
                if content_type == "23" or (opaque_type == "23" and content_type == "0"):
                    log_entry += "TLS Application Detected:\n"


            # [===] Обработка ChangeCipherSpec
            if hasattr(packet.tls, 'record'):
                if content_type == "20":
                    log_entry += "TLS ChangeCipherSpec Detected:\n"


            # [===] Обработка Handshake
            if hasattr(packet.tls, 'record'):
                if content_type == "22":
                    log_entry += "TLS Handshake Detected:\n"


            # Обработка Application Data
            if parsed_record and "APPLICATION" in parsed_record:
                try:
                    log_entry += "TLS Application Data Detected (OLD):\n"
                    log_entry += f"Parsed Data: {parsed_record}\n"
                except Exception as e:
                    log_entry += f"[-] Ошибка обработки AppData: {str(e)}\n"

            # [===] Основное логирование полей TLS, доступных для чтения
            tls_layer = packet.tls
            for field in tls_layer.field_names:
                try:
                    log_entry += f"{field}: {getattr(tls_layer, field)}\n"
                except AttributeError:
                    continue

            # [===] IP адреса пакета
            log_entry += f"Source: {packet.ip.src} --> Destination: {packet.ip.dst}\n\n"

            # [===] Потокобезопасная запись в лог (Возможно тут иногда и происходит стопор)
            self.log_file.write(log_entry)
            self.log_file.flush()
            print(log_entry)


    def _capture_loop(self):
        """Основной цикл захвата пакетов"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            self._capture = pyshark.LiveCapture(
                interface=self.interface,
                override_prefs={
                    'tls.keylog_file': Config.SSL_KEY_LOG_FILE,
                },
                tshark_path=Config.TSHARK_PATH,
                debug=False,
                custom_parameters=['-o', 'tls.keylog_file:' + Config.SSL_KEY_LOG_FILE]
            )

            self._write_session_header()

            for packet in self._capture.sniff_continuously():
                if self._stop_event.is_set():
                    break
                self._process_packet(packet)
        except Exception as e:
            print(f"Capture error: {str(e)}")
        finally:
            if hasattr(self, '_capture'):
                self._capture.close()
            loop.close()
            self.log_file.close()

    def start_capture(self):
        """Запуск захвата в отдельном потоке"""
        if not self._thread or not self._thread.is_alive():
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._capture_loop, daemon=True)
            self._thread.start()

    def stop_capture(self):
        """Корректная остановка захвата"""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if hasattr(self, '_capture') and self._capture:
            self._capture.close()