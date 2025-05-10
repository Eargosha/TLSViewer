import json
import re

from lxml import etree


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
            "handshake_type": '',
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

            if line.startswith("TLS segment data "):
                temp_line = line.replace("TLS segment data ", "").strip()
                value = temp_line.strip("()").split()[0]
                base_packet["tls_details"]["segment_data"] = value

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
        "tls_details":  {
            **base_packet["tls_details"],
            "application_data_protocol": None,
            # "http2": {
            #     "stream_id": None,
            #     "frame_type": None,
            #     "flags": None
            # },
        },
        "certificates": [],
        "is_handshake": 0,
        "is_cipher": 0,
        "is_application": 0,
        "is_alert": 0,
        "is_heartbeat": 0,
        "is_unknown": 0,
        "errors": base_packet["errors"].copy(),
        "application_data": {
            "content_type": None,
            "data": None,
            "encoding": None,
            "svg_data": {}
        },
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

        capture_data = False
        current_app_data = []
        current_content_type = None
        current_encoding = None

        capture_http2_data = False
        http2_data_lines = []
        http2_stream_id = None
        http2_frame_type = None
        http2_flags = None

        capture_data = False
        current_app_data = []
        current_content_type = None
        current_encoding = None

        capture_svg = False
        current_svg_data = []

        negotiated_version_found = False

        if "http2_frames" not in record_data["tls_details"]:
            record_data["tls_details"]["http2_frames"] = []

        count = 0
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

                stripped_line = line.lstrip()
                # if record_data["is_unknown"] == 1:
                #     # print(line)

                if "[Application Data Protocol:" in stripped_line:
                    start_idx = stripped_line.find(":") + 1
                    end_idx = stripped_line.find("]")
                    if end_idx != -1:
                        protocol = stripped_line[start_idx:end_idx].strip()
                        record_data["tls_details"]["application_data_protocol"] = protocol
                        # print("Extracted protocol:", protocol)

                # === Парсинг HyperText Transfer Protocol 2 ===
                if "HyperText Transfer Protocol 2" in line:
                    capture_http2_data = True
                    http2_data_lines = []

                if capture_http2_data and line.startswith("Stream:"):
                    # Проверяем, не начинается ли строка с "Settings -", чтобы исключить внутренние поля
                    if "Settings -" in line:
                        continue

                    stream_match = re.search(r"Stream:\s*(.+?),\s*Stream ID:\s*(\d+)", line)
                    if stream_match:
                        http2_frame_type = stream_match.group(1).strip()
                        http2_stream_id = stream_match.group(2)

                        # Добавляем новый фрейм как словарь
                        record_data["tls_details"]["http2_frames"].append({
                            "stream_id": http2_stream_id,
                            "frame_type": http2_frame_type,
                            "flags": None,
                            "length": None,
                            "settings": [],
                            "connection_window_before": None,
                            "connection_window_after": None,
                        })

                # === Парсинг Connection Window Size до и после ===
                if "[Connection window size (before):" in line:
                    # Берём всё после '[Connection window size (before):'
                    value = line.split("[Connection window size (before):")[1]
                    # Убираем лишние пробелы и закрывающую скобку
                    value = value.strip().rstrip("]")
                    last_frame = record_data["tls_details"]["http2_frames"][-1]
                    last_frame["connection_window_before"] = value

                if "[Connection window size (after):" in line:
                    # Берём всё после '[Connection window size (after):'
                    value = line.split("[Connection window size (after):")[1]
                    # Убираем лишние пробелы и закрывающую скобку
                    value = value.strip().rstrip("]")
                    last_frame = record_data["tls_details"]["http2_frames"][-1]
                    last_frame["connection_window_after"] = value

                if "Length:" in line and current_section == "tls":
                    match = re.search(r"Length:\s*(\d+)", line)
                    if match:
                        length_value = match.group(1)
                        if record_data["tls_details"]["http2_frames"]:
                            last_frame = record_data["tls_details"]["http2_frames"][-1]
                            last_frame["length"] = length_value

                if line.startswith("TLS segment data "):
                    temp_line = line.replace("TLS segment data ", "").strip()
                    value = temp_line.strip("()").split()[0]
                    record_data["tls_details"]["segment_data"] = value

                if line.startswith("Settings - "):
                    # Извлекаем имя и значение настройки
                    setting_line = line.replace("Settings - ", "").strip()
                    setting_name_value = setting_line.split(":")
                    if len(setting_name_value) >= 2:
                        name = setting_name_value[0].strip()
                        value = ":".join(setting_name_value[1:]).strip()
                        # Проверяем, что есть хотя бы один фрейм
                        if record_data.get("tls_details", {}).get("http2_frames"):
                            last_frame = record_data["tls_details"]["http2_frames"][-1]
                            #  Добавляем новую настройку
                            last_frame["settings"].append({
                                "name": name,
                                "value": value
                            })

                if capture_http2_data and "Flags:" in line:
                    flags_match = re.search(r"Flags:\s*(0x[0-9a-fA-F]+)", line)
                    if flags_match:
                        flags_value = flags_match.group(1).strip()
                        if record_data["tls_details"]["http2_frames"]:
                            last_frame = record_data["tls_details"]["http2_frames"][-1]
                            last_frame["flags"] = flags_value

                if "Encrypted Application Data" in line:
                    hex_data = line.split(":")[1].strip()
                    record_data["application_data"]["data"] = hex_data
                    record_data["application_data"]["content_type"] = "application/octet-stream"

                # === Парсинг Headers в HyperText Transfer Protocol 2 ===
                if line.startswith("Header: "):
                    header_line = line.replace("Header: ", "").strip()
                    if "://" not in header_line:  # исключаем URL
                        key_val = header_line.split(":")
                        if len(key_val) >= 2:
                            key = key_val[0].strip()
                            val = ":".join(key_val[1:]).strip()

                            # Сохраняем как текстовое представление
                            if "headers_str" not in record_data["application_data"]:
                                record_data["application_data"]["headers_str"] = []

                            record_data["application_data"]["headers_str"].append(f"{key}: {val}")

                if line.startswith("Header: "):
                    header_line = line.replace("Header: ", "").strip()

                    if "://" not in header_line and ":" in header_line:
                        key_val = header_line.split(":", 1)
                        name = key_val[0].strip()
                        value = key_val[1].strip()

                        # Инициализируем объект заголовка
                        parsed_header = {
                            "name": name,
                            "value": value,
                            "name_length": None,
                            "value_length": None,
                            "unescaped_value": None,
                            "representation": None,
                            "index": None
                        }

                        # Проверяем, есть ли следующие строки с метаданными
                        next_line_index = lines.index(line) + 1
                        while next_line_index < len(lines):
                            next_line = lines[next_line_index].strip()

                            # Выход, если это уже другой заголовок или не относится к текущему
                            if next_line.startswith("Header: "):
                                break

                            # print(next_line)
                            if next_line.startswith("Name Length:"):
                                parsed_header["name_length"] = int(next_line.split(":", 1)[1].strip())

                            elif next_line.startswith("Value Length:"):
                                # print("МЫ НАШЛИ Value Length")
                                parsed_header["value_length"] = int(next_line.split(":", 1)[1].strip())

                            elif next_line.startswith("[Unescaped:"):
                                parsed_header["unescaped_value"] = next_line.split(":", 1)[1].strip().rstrip(
                                    "]").strip()

                            elif next_line.startswith("Representation:"):
                                parsed_header["representation"] = next_line.split(":", 1)[1].strip()

                            elif next_line.startswith("Index:"):
                                parsed_header["index"] = int(next_line.split(":", 1)[1].strip())

                            next_line_index += 1

                        # Добавляем заголовок в фрейм
                        if record_data.get("tls_details", {}).get("http2_frames"):
                            last_frame = record_data["tls_details"]["http2_frames"][-1]

                            if "headers" not in last_frame:
                                last_frame["headers"] = []

                            last_frame["headers"].append(parsed_header)

                # Внутри цикла for line in lines:
                if "Content-encoded entity body" in line:
                    # Извлекаем тип кодирования (например, gzip, br)
                    match = re.search(r"Content-encoded entity body $br$:.*?->.*?$", line)
                    if match:
                        encoding_match = re.search(r"$br$:\s*(\d+)\sbytes\s->\s(\d+)\sbytes", line)
                        if encoding_match:
                            current_encoding = "br"

                # === Поиск начала HTML ===
                if line.startswith("<!DOCTYPE html") or line.startswith("<html"):
                    capture_data = True
                    current_app_data = []  # Сбрасываем предыдущие данные, если были

                # === Сборка данных приложения ===
                if capture_data:
                    current_app_data.append(line)

                # === Начало сборки SVG ===
                if not capture_data and ("<svg" in line.lower()):
                    capture_svg = True
                    current_svg_data = [line]

                # === Сборка SVG ===
                if capture_svg:
                    current_svg_data.append(line)

                    # Собираем временный буфер
                    svg_buffer = "\n".join(current_svg_data)

                    # Проверяем, достаточно ли тегов
                    if svg_buffer.count("</svg>") > svg_buffer.count("<svg"):
                        capture_svg = False
                        record_data["application_data"]["svg_data"] = {
                            "content_type": "image/svg+xml",
                            "data": svg_buffer,
                            "encoding": current_encoding
                        }
                        current_svg_data = []

                # === Конец блока с данными приложения ===
                if capture_data and "</html>" in line.lower():
                    current_app_data.append(line)
                    capture_data = False

                    cleaned_data = "\n".join(current_app_data)

                    # Сохраняем данные в record_data
                    record_data["application_data"] = {
                        "content_type": detect_content_type(cleaned_data),
                        "data": cleaned_data,
                        "encoding": current_encoding
                    }


                # # === Конец блока с данными приложения ===
                # if capture_data and line.startswith("</html"):
                #     current_app_data.append(line)
                #     capture_data = False
                #
                #     cleaned_data = "\n".join(current_app_data)
                #
                #     # Сохраняем данные в record_data
                #     record_data["application_data"] = {
                #         "content_type": detect_content_type(cleaned_data),
                #         "data": cleaned_data,
                #         "encoding": current_encoding
                #     }
                #     continue
                #
                # # === Сборка данных приложения ===
                # if capture_data:
                #     current_app_data.append(line)

                if "Cipher Suite:" in line:
                    record_data["tls_details"]["cipher"] = line.split("Cipher Suite:")[1].split("(")[0].strip()

                if "Handshake Protocol:" in line:
                    handshake_type = line.split("Handshake Protocol:")[1].strip()
                    record_data["tls_details"]["handshake_type"] = handshake_type

                    # === ДОБАВЛЕНО: Поддерживаемые клиентом версии (supported_versions) ===
                if "Extension: supported_versions" in line:
                    client_supported_versions.append("TLS 1.3")

                    # === ДОБАВЛЕНО: Версия, выбранная сервером ===
                if "Supported Version:" in line and not negotiated_version_found:
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

def detect_content_type(data):
    try:
        json.loads(data)
        return "application/json"
    except Exception:
        pass
    try:
        etree.fromstring(data)
        # Если содержит <svg>, это SVG
        if "<svg" in data.lower():
            return "image/svg+xml"
        return "application/xml"
    except Exception:
        pass
    if "<html" in data.lower():
        return "text/html"
    return "text/plain"