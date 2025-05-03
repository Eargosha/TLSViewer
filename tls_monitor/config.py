# Конфигурационый файл - константы, пути, названия и так далее

import os


class Config:
    SSL_KEY_LOG_FILE = "sslkeylogfile.txt"
    MITMPROXY_PORT = 8080
    WEBSITE_URL = "https://habr.com/ru/articles/"
    TARGET_IP = "178.248.237.68"
    TSHARK_PATH = "C:\\Program Files\\Wireshark\\tshark.exe"
    CHROMEDRIVER_PATH = "chromedriver.exe"
    TLS_PACKETS_LOG = "tls_packets.log"
    MITMPROXY_LOG = "mitmproxy.log"
