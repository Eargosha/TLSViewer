import re

def split_tls_records(lines):
    """
    Разделение строк на отдельные TLS-записи,
    включая вложенные TLS-записи из Encrypted Application Data.
    """
    tls_records = []
    current_record = []
    record_start_markers = [
        "TLSv1.2 Record Layer:",
        "TLSv1.3 Record Layer:",
        "Transport Layer Security"
    ]
    inside_encrypted_data = False

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Проверяем, не начались ли вложенные TLS-записи в Encrypted Application Data
        if "Encrypted Application Data:" in line:
            inside_encrypted_data = True
        elif inside_encrypted_data and any(marker in line for marker in record_start_markers):
            # Началась новая TLS запись внутри зашифрованных данных
            if current_record:
                tls_records.append(current_record)
                current_record = []
            inside_encrypted_data = False  # Сброс для следующих записей

        # Если нашли начало TLS-записи, сохраняем предыдущую
        if any(marker in line for marker in record_start_markers):
            if current_record:
                tls_records.append(current_record)
                current_record = []
        current_record.append(line)

    if current_record:
        tls_records.append(current_record)

    return tls_records


def filter_tls_lines(lines):
    """
    Фильтрует входные строки, оставляя только те,
    которые принадлежат TLS-записям.
    """
    tls_lines = []
    in_tls_block = False

    for line in lines:
        line = line.rstrip('\n')
        stripped_line = line.strip()

        # Начинается TLS-запись
        if stripped_line.startswith("TLSv1"):
            in_tls_block = True

        # Если внутри TLS-блока и строка не пустая — сохраняем
        if in_tls_block and stripped_line != "":
            tls_lines.append(line)

    return tls_lines

# === Дополнительная функция: удаляет слишком короткие записи ===
def filter_the_lines_2(tls_records):
    """
    Удаляет из списка TLS-записей те, которые содержат менее 2 строк.
    """
    filtered_records = []
    for record in tls_records:
        if len(record) >= 2:
            filtered_records.append(record)
    return filtered_records


def parse_packet(packet_content):
    """Парсинг содержимого пакета с разделением вложенных TLS записей"""
    base_packet = {
        "timestamp": None,
        "packet_type": "Unknown",
        "layers": {},
        "errors": [],
        "source": {},
        "destination": {},
        "frame_number": 987,
        "tls_details": {
            "signature_algorithms": [],
            "handshake_type": "Unknown",
        },
        "certificates": []
    }

    # Сначала извлекаем базовую информацию о пакете
    try:
        lines = packet_content.split("\n")
        current_section = None
        cert_data = None

        # Обработка заголовка пакета
        if packet_content.startswith("====== [TLS Packet -"):
            parts = packet_content.split("======")
            if len(parts) >= 2:
                base_packet["timestamp"] = parts[1].split("[TLS Packet - ")[1].strip().rstrip(" =")

        # Разделяем пакет на TLS-записи
        tls_records = []
        current_record = []
        record_start_markers = [
            "TLSv1.2 Record Layer:",
            "TLSv1.3 Record Layer:",
            "Transport Layer Security"
        ]

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Общая информация о пакете (применяется ко всем записям) !!!!!!!!УСТАРЕЛО ВРОДЕ
            if "[TYPE:" in line:
                base_packet["packet_type"] = line.split("[TYPE: ")[1].split("]")[0].strip()
                base_packet["is_handshake"] = 1 if "Handshake" in base_packet["packet_type"] else 0
                base_packet["is_cipher"] = 1 if "Cipher" in base_packet["packet_type"] else 0
                base_packet["is_application"] = 1 if "Application" in base_packet["packet_type"] else 0
                base_packet["is_alert"] = 1 if "Alert" in base_packet["packet_type"] else 0
                base_packet["is_unknown"] = 1 if "UNKNOWN" in base_packet["packet_type"] else 0

            if "Frame Number:" in line:
                number = line.split("Frame Number:")[1].strip()
                base_packet["frame_number"] = number

            # Ethernet информация
            if "Ethernet II" in line:
                current_section = "ethernet"
            elif current_section == "ethernet":
                if "Source:" in line:
                    src = line.split("Source:")[1].split("(")[0].strip()
                    base_packet["source"]["mac"] = src
                if "Destination:" in line:
                    dst = line.split("Destination:")[1].split("(")[0].strip()
                    base_packet["destination"]["mac"] = dst

            # IP информация
            if "Internet Protocol Version 4" in line:
                current_section = "ip"
            elif current_section == "ip":
                if "Source Address:" in line:
                    base_packet["source"]["ip"] = line.split("Source Address:")[1].strip()
                if "Destination Address:" in line:
                    base_packet["destination"]["ip"] = line.split("Destination Address:")[1].strip()

            # TCP информация
            if "Transmission Control Protocol" in line:
                current_section = "tcp"
                if "Src Port:" in line:
                    base_packet["source"]["port"] = line.split("Src Port:")[1].split(",")[0].strip()
                if "Dst Port:" in line:
                    base_packet["destination"]["port"] = line.split("Dst Port:")[1].split(",")[0].strip()

            # #  Разделение TLS записей
            # if any(marker in line for marker in record_start_markers):
            #     if current_record:  # Сохраняем предыдущую запись
            #         tls_records.append("\n".join(current_record))
            #         current_record = []
            # current_record.append(line)


        # if current_record:  # Добавляем последнюю запись
        #     tls_records.append("\n".join(current_record))

        # # Если не найдено TLS записей, возвращаем базовый пакет
        # if not tls_records or len(tls_records) == 1:
        #     return [parse_single_record("\n".join(lines), base_packet)]

        lines = filter_tls_lines(lines)
        tls_records = split_tls_records(lines)
        tls_records = filter_the_lines_2(tls_records)

        # --- Вставь сюда ---
        with open("parsed_tls_records_output.txt", "a", encoding="utf-8") as f:
            for idx, record in enumerate(tls_records):
                f.write("================\n")
                f.write(f"=== TLS Record {idx + 1} ===\n\n")
                for line in record:
                    f.write(line + "\n")
                f.write("\n")
        # --------------------

        # Парсим каждую TLS запись отдельно
        parsed_records = []
        for record in tls_records:
            parsed_record = parse_single_record(record, base_packet)
            if parsed_record:
                parsed_records.append(parsed_record)

        return parsed_records if parsed_records else [base_packet]

    except Exception as e:
        base_packet["errors"].append(f"Error during parsing: {str(e)}")
        return [base_packet]


def parse_single_record(record_content, base_packet):
    """Парсинг отдельной TLS записи"""
    record_data = {
        **base_packet,
        "tls_details": base_packet["tls_details"].copy(),
        "certificates": [],
        "is_handshake": 0,
        "is_cipher": 0,
        "is_application": 0,
        "is_alert": 0,
        "is_heartbeat": 0,
        "is_unknown": 0,
        "errors": base_packet["errors"].copy()
    }

    try:
        # lines = record_content.split("\n")
        lines = record_content
        current_section = None
        cert_data = None
        is_tls_record = False
        length_found = False  # Флаг для отслеживания первого "Length:"
        tls_version = False

        # Новые поля для анализа согласования версии
        client_supported_versions = []
        negotiated_version = None

        count = 0;
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Определение TLS записи
            if "Transport Layer Security" in line or "TLSv" in line:
                # Извлечение реальной версии из заголовка типа "TLSv1.3 Record Layer"
                if "TLSv" in line:
                    if "TLSv1.3" in line:
                        record_data["tls_details"]["version"] = "TLS 1.3"
                    elif "TLSv1.2" in line:
                        record_data["tls_details"]["version"] = "TLS 1.2"
                    elif "TLSv1" in line:
                        record_data["tls_details"]["version"] = "TLS 1.0"
                    tls_version = True
                current_section = "tls"
                is_tls_record = True
                continue

            if current_section == "tls":
                if "Content Type:" in line:
                    content_type = line.split("Content Type:")[1].split("(")[0].strip()
                    record_data["tls_details"]["content_type"] = content_type
                    print(lines)

                    if "Handshake" in content_type:
                        record_data["is_handshake"] = 1
                    elif "Application" in content_type:
                        record_data["is_application"] = 1
                    elif "Alert" in content_type:
                        record_data["is_alert"] = 1
                    elif "Change Cipher Spec" in content_type:
                        record_data["is_cipher"] = 1
                    elif "Heartbeat" in content_type:
                        record_data["is_heartbeat"] = 1
                    else:
                        record_data["is_unknown"] = 1

                if "Cipher Suite:" in line:
                    record_data["tls_details"]["cipher"] = line.split("Cipher Suite:")[1].split("(")[0].strip()

                if "Handshake Protocol:" in line:
                    handshake_type = line.split("Handshake Protocol:")[1].strip()
                    record_data["tls_details"]["handshake_type"] = handshake_type

                    # === ДОБАВЛЕНО: Поддерживаемые клиентом версии (supported_versions) ===
                if "Extension: supported_versions" in line:
                    client_supported_versions.append("TLS 1.3")

                    # === ДОБАВЛЕНО: Версия, выбранная сервером ===
                if "Supported Version:" in line:
                    if "TLS 1.3" in line:
                        negotiated_version = "TLS 1.3"
                    elif "TLS 1.2" in line:
                        negotiated_version = "TLS 1.2"
                    elif "TLS 1.0" in line:
                        negotiated_version = "TLS 1.0"

                    # Резервный вариант — Version: в Server Hello
                if "Version:" in line and not tls_version:
                    version_str = line.split("Version:")[1].split("(")[0].strip()
                    if "TLS 1.3" in version_str:
                        record_data["tls_details"]["legacy_version"] = "TLS 1.3"
                    elif "TLS 1.2" in version_str:
                        record_data["tls_details"]["legacy_version"] = "TLS 1.2"
                    elif "TLS 1.0" in version_str:
                        record_data["tls_details"]["legacy_version"] = "TLS 1.0"
                    tls_version = True


                if "Server Name:" in line:
                    record_data["tls_details"]["sni"] = line.split("Server Name:")[1].strip()

                # Обработка "Length:" с учетом флага
                if "Length:" in line and not length_found:
                    record_data["tls_details"]["length"] = line.split("Length:")[1].strip()
                    length_found = True  # Устанавливаем флаг после первого нахождения

                if "Signature Algorithm:" in line:
                    algo = line.split(":")[1].split("(")[0].strip()
                    record_data["tls_details"]["signature_algorithms"].append(algo)

                if "Certificate Length:" in line:
                    cert_data = {"raw": []}

                if cert_data is not None:
                    cert_data["raw"].append(line)
                    if "Encrypted Application Data" in line or "Certificate:" in line:
                        record_data["certificates"].append(cert_data)
                        cert_data = None

                if "Expert Info" in line or "MISSING>" in line:
                    record_data["errors"].append(line)

        # Записываем negotiated_version и client_supported_versions в record_data для анализа хендшека===
        record_data["tls_details"]["client_supported_versions"] = client_supported_versions
        record_data["tls_details"]["negotiated_version"] = negotiated_version

        # Форматирование адресов
        record_data["source"]["formatted"] = f"{record_data['source'].get('ip', '')}:{record_data['source'].get('port', '')}"
        record_data["destination"]["formatted"] = f"{record_data['destination'].get('ip', '')}:{record_data['destination'].get('port', '')}"

        # Если это не TLS запись, возвращаем None (она будет отфильтрована)
        return record_data if is_tls_record else None

    except Exception as e:
        record_data["errors"].append(f"Error during record parsing: {str(e)}")
        return record_data