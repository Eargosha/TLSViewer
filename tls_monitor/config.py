# # Конфигурационый файл - константы, пути, названия и так далее
#
# import os
#
#
# class Config:
#     # SSL_KEY_LOG_FILE = "sslkeylogfile.txt"
#
#     # Получаем путь к системной папке Temp
#     temp_dir = os.environ.get('TEMP') or os.environ.get('TMP')
#     # Путь к вашему временному файлу
#     SSL_KEY_LOG_FILE = os.path.join(temp_dir, 'sslkeylogfile.txt')
#
#     MITMPROXY_PORT = 8080
#     WEBSITE_URL = "https://habr.com/ru/articles/"
#     TARGET_IP = "178.248.237.68"
#     TSHARK_PATH = "C:\\Program Files\\Wireshark\\tshark.exe"
#     CHROMEDRIVER_PATH = "chromedriver.exe"
#     TLS_PACKETS_LOG = "tls_packets.log"
#     MITMPROXY_LOG = "mitmproxy.log"
import os


class Config:
    MITMPROXY_PORT = 8080
    WEBSITE_URL = "https://habr.com/ru/articles/"
    TARGET_IP = "178.248.237.68"
    TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
    CHROMEDRIVER_PATH = r"..\chromedriver.exe" #"chromedriver.exe"
    TLS_PACKETS_LOG = r"..\tls_packets.log" #"tls_packets.log"
    MITMPROXY_LOG = r"..\mitmproxy.log" #"mitmproxy.log"

    # --- Настройка пути для SSLKEYLOGFILE ---
    temp_dir = os.environ.get('TEMP') or os.environ.get('TMP')

    if not temp_dir:
        raise EnvironmentError("Системная переменная TEMP или TMP не установлена.")

    tlsviewer_dir = os.path.join(temp_dir, 'TLSViewer')

    try:
        os.makedirs(tlsviewer_dir, exist_ok=True)
    except Exception as e:
        raise PermissionError(f"Не удалось создать папку {tlsviewer_dir}: {e}")

    SSL_KEY_LOG_FILE = os.path.join(tlsviewer_dir, 'sslkeylogfile.txt')

    # Очистить файл при старте (если существует), чтобы начать с чистого лога
    try:
        with open(SSL_KEY_LOG_FILE, 'w'):
            pass
    except Exception as e:
        raise IOError(f"Не удалось очистить файл {SSL_KEY_LOG_FILE}: {e}")