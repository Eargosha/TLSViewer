import sys
import time
import argparse

from tls_monitor.config import Config
from tls_monitor.mitm_manager import MitmProxyManager
from tls_monitor.browser_controller import BrowserController
from tls_monitor.traffic_sniffer import TrafficSniffer
from tls_monitor.network_utils import NetworkUtils


def main():
    parser = argparse.ArgumentParser(description="Запуск TLS Monitor демона")
    parser.add_argument("--interface", type=str, help="Выбранный сетевой интерфейс")
    parser.add_argument("--url", type=str, help="Целевой URL для фильтрации")
    parser.add_argument("--mode", choices=["all", "url"], default="all",
                        help="Режим работы: 'all' - весь трафик, 'url' - только указанный сайт")


    args = parser.parse_args()

    # Динамическое обновление конфига
    update_dict = {}
    if args.url:
        print(f"[+] Обновили URL {args.url}")
        update_dict['WEBSITE_URL'] = args.url
        update_dict['TARGET_IP'] = NetworkUtils.get_ip_from_url(args.url)
        print(f"[+] Обновили IP {NetworkUtils.get_ip_from_url(args.url)}")
    if args.mode:
        print(f"[+] Мод TSHARK: {args.mode}")
        update_dict['TSHARK_MODE'] = args.mode


    Config.update_config(**update_dict)

    # print(args)

    # Выводим полученные значения
    if args.mode == "url" and args.url:
        print(f"[+] Режим: фильтрация по URL: {args.url}")
    else:
        print("[+] Режим: весь трафик по интерфейсу")

    # Выбор интерфейса
    interfaces = NetworkUtils.get_interfaces()
    if not interfaces:
        print("Нет доступных интерфейсов!")
        return

    if args.interface:
        selected_iface = args.interface
    else:
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

    print(f"[+] Интерфейс выбран: {selected_iface}")

    open(Config.SSL_KEY_LOG_FILE, 'w')
    open(Config.TLS_PACKETS_LOG, 'w')
    open(Config.MITMPROXY_LOG, 'w')
    print("[+] LOG файлы очищены")

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