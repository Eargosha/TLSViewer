import os
import time
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import pyshark

# Настройки
SSL_KEY_LOG_FILE = os.path.abspath("sslkeylogfile.txt")
MITMPROXY_PORT = 8080
WEBSITE_URL = "https://habr.com/ru/articles/"  # Целевой сайт
TARGET_IP = "178.248.237.68"  # IP-адрес для фильтрации

# !!! Перед запуском mitmproxy нужно установить сертификат mitmproxy-ca-cert.pem
# !!! Сделать проверку PING перед использованием кода
# !!! Использовать tshark.exe
def start_mitmproxy():
    """Запуск mitmproxy в фоновом режиме с SSLKEYLOGFILE"""
    os.environ["SSLKEYLOGFILE"] = SSL_KEY_LOG_FILE
    command = [
        "mitmdump",
        "--ssl-insecure",  # Для тестирования, игнорирует ошибки сертификатов
        "--set", f"sslkeylogfile={SSL_KEY_LOG_FILE}",
        "--listen-port", str(MITMPROXY_PORT)
    ]
    # Подавление вывода mitmproxy
    with open("mitmproxy.log", "w") as log_file:
        return subprocess.Popen(
            command,
            stdout=log_file,  # Логи записываются в файл
            stderr=log_file
        )


def configure_browser():
    """Настройка Chrome для работы через mitmproxy и записи ключей TLS"""
    chrome_options = Options()
    chrome_options.add_argument(f"--proxy-server=http://localhost:{MITMPROXY_PORT}")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--ssl-key-log-file=" + SSL_KEY_LOG_FILE)

    # Путь к chromedriver (замените на свой)
    service = Service('chromedriver.exe')
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver


def capture_traffic(interface="Ethernet"):
    """Захват и анализ TLS-трафика с использованием PyShark"""
    capture = pyshark.LiveCapture(
        interface=interface,
        override_prefs={'tls.keylog_file': os.path.abspath(SSL_KEY_LOG_FILE)},
        debug=True,
        tshark_path="C:\\Program Files\\Wireshark\\tshark.exe"
    )

    for packet in capture.sniff_continuously():

        if 'tls' in packet and (packet.ip.src == TARGET_IP or packet.ip.dst == TARGET_IP):
            print(packet.tls.pretty_print())
            print("IPISHNIKI:==========")
            print(packet.ip.src)
            print(packet.ip.dst)


def main():
    # Запуск mitmproxy
    mitm_process = start_mitmproxy()
    time.sleep(2)  # Ожидание запуска mitmproxy

    try:
        # Запуск браузера
        driver = configure_browser()
        driver.get(WEBSITE_URL)
        time.sleep(5)  # Время для работы с сайтом

        # Захват трафика (запускается в отдельном потоке)
        capture_traffic()

    finally:
        # Завершение процессов
        if 'driver' in locals() and driver:
            driver.quit()
        mitm_process.terminate()


if __name__ == "__main__":
    main()