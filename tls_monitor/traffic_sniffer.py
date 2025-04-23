# Захват трафика

import pyshark
from tls_monitor.config import Config


class TrafficSniffer:
    def __init__(self, interface):
        self.interface = interface
        self.log_file = open("tls_packets.log", "a")  # Открытие файла для записи

    def start_capture(self):
        capture = pyshark.LiveCapture(
            interface=self.interface,
            override_prefs={'tls.keylog_file': Config.SSL_KEY_LOG_FILE},
            tshark_path=Config.TSHARK_PATH,
            debug=True,
        )

        for packet in capture.sniff_continuously():
            if 'tls' in packet and (packet.ip.src == Config.TARGET_IP or packet.ip.dst == Config.TARGET_IP):
                # Проверяем, есть ли данные в слое TLS
                tls_layer = packet.tls
                if hasattr(tls_layer, 'pretty_print') and tls_layer.pretty_print():
                    log_entry = f"====== [TLS Packet] ====== {tls_layer.pretty_print()}\n"
                else:
                    # Если pretty_print недоступен, логируем доступные поля вручную
                    log_entry = f"====== [TLS Packet] ======\n"
                    for field in tls_layer.field_names:
                        try:
                            log_entry += f"{field}: {getattr(tls_layer, field)}\n"
                        except AttributeError:
                            log_entry += f"{field}: <not available>\n"

                log_entry += f"Source: {packet.ip.src} --> Destination: {packet.ip.dst}\n\n"
                self.log_file.write(log_entry)
                self.log_file.flush()  # Обеспечиваем немедленную запись

