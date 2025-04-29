def parse_packet(packet_content):
    """Парсинг содержимого пакета в структурированный формат"""
    packet_data = {
        "timestamp": None,
        "is_handshake": 0,
        "attributes": {},
        "errors": [],
        "source": None,
        "destination": None,
    }

    lines = packet_content.split("\n")
    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith("====== [TLS Packet -"):
            timestamp = line.split("[TLS Packet - ")[1].split("]")[0].strip()
            packet_data["timestamp"] = timestamp
            continue

        if line == "TLS Handshake Detected:":
            packet_data["is_handshake"] = 1
            continue

        if line.startswith("Source:"):
            src_dst = line.split(" --> ")
            packet_data["source"] = src_dst[0].replace("Source: ", "").strip()
            packet_data["destination"] = src_dst[1].replace("Destination: ", "").strip()
            continue

        if line.startswith("[-] Ошибка"):
            packet_data["errors"].append(line)
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key == "handshake_ciphersuite":
                value = f"0x{value[2:].upper()}" if value.startswith("0x") else value

            packet_data["attributes"][key] = value

    return packet_data