# Работа с интерфейсами системы, пока только WINDOWS

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