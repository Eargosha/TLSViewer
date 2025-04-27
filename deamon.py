import time
import threading

from tls_monitor.config import Config
from tls_monitor.mitm_manager import MitmProxyManager
from tls_monitor.browser_controller import BrowserController
from tls_monitor.traffic_sniffer import TrafficSniffer
from tls_monitor.network_utils import NetworkUtils


def main():
    # Выбор интерфейса
    interfaces = NetworkUtils.get_interfaces()
    if not interfaces:
        print("Нет доступных интерфейсов!")
        return

    print("Доступные интерфейсы:")
    for idx, (_, display) in enumerate(interfaces, 1):
        print(f"{idx}. {display}")

    while True:
        try:
            choice = int(input("Введите номер интерфейса: "))
            if 1 <= choice <= len(interfaces):
                selected_iface = interfaces[choice - 1][0]
                break
        except ValueError:
            print("Некорректный ввод!")

    print("[+] Интерфейс выбран")

    # Инициализация компонентов
    print("[+] Инициализация MitmProxy")
    mitm = MitmProxyManager()
    print("[+] Завершена")
    print("[+] Инициализация DebugBrowser")
    browser = BrowserController()
    print("[+] Завершена")
    print("[+] Инициализация TrafficSniffer")
    sniffer = TrafficSniffer(selected_iface)

    try:
        print("[+] Старт MitmProxy")
        mitm.start()
        time.sleep(2)

        print("[+] Start of sniffing")
        sniffer.start_capture()  # Запуск в отдельном потоке с event loop

        print("[+] Старт DebugBrowser")
        driver = browser.start()
        driver.get(Config.WEBSITE_URL)

        # Бесконечный цикл для ожидания
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("Прервано пользователем")
    finally:
        sniffer.stop_capture()  # Добавить остановку сниффера
        browser.stop()
        mitm.stop()


if __name__ == "__main__":
    main()