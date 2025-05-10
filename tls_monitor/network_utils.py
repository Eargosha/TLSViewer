# Работа с интерфейсами системы, пока только WINDOWS
import socket

import wmi

class NetworkUtils:
    @staticmethod
    def get_interfaces():
        try:
            c = wmi.WMI()
            interfaces = []
            for adapter in c.Win32_NetworkAdapter():
                if adapter.NetConnectionID:
                    status = {
                        0: "Нет данных",
                        2: "Подключено",
                        7: "Отключено"
                    }.get(adapter.NetConnectionStatus, "Неизвестно")
                    display_name = f"{adapter.NetConnectionID} ({adapter.Description}) [{status}]"
                    interfaces.append((adapter.NetConnectionID, display_name))
            return interfaces
        except Exception as e:
            print(f"Ошибка: {str(e)}")
            return []

    def get_ip_from_url(url: str) -> str:
        # Убираем http:// или https:// и всё, что после /
        domain = url.split("://")[-1].split("/")[0].split(":")[0]
        # print(f"Вот че вышло {domain}")
        try:
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror as e:
            raise RuntimeError(f"Не удалось разрешить домен {domain}: {e}")
