# Захват трафика

import pyshark
from tls_monitor.config import Config

class TrafficSniffer:
    def __init__(self, interface):
        self.interface = interface

    def start_capture(self):
        capture = pyshark.LiveCapture(
            interface=self.interface,
            override_prefs={'tls.keylog_file': Config.SSL_KEY_LOG_FILE},
            tshark_path=Config.TSHARK_PATH,
            debug=True,
        )

        for packet in capture.sniff_continuously():
            if 'tls' in packet and (packet.ip.src == Config.TARGET_IP or packet.ip.dst == Config.TARGET_IP):
                print(f"====== [TLS Packet] ====== {packet.tls.pretty_print()}")
                print(f"Source: {packet.ip.src} --> Destination: {packet.ip.dst}")