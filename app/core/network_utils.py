import wmi
import pythoncom  # ← добавь этот импорт


def get_interfaces():
    try:
        pythoncom.CoInitialize()  # ← ОБЯЗАТЕЛЬНО для работы WMI в потоках!
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
        print(f"[!] Ошибка при получении интерфейсов: {e}")
        return []
    finally:
        pythoncom.CoUninitialize()  # ← освобождаем ресурсы COM