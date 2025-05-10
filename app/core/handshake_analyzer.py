import time

from Scripts.unicodedata import normalize

handshake_states = {}


def get_connection_key(ip1, ip2):
    return f"{min(ip1, ip2)}:{max(ip1, ip2)}"


def analyze_handshake(record):
    src_ip = record["source"]["ip"]
    dst_ip = record["destination"]["ip"]
    ip_key = get_connection_key(src_ip, dst_ip)

    handshake_type = record["tls_details"].get("handshake_type", "").lower()
    packet_type = record["packet_type"].lower()
    tls_version = record["tls_details"].get("version", "").lower()

    if ip_key not in handshake_states:
        handshake_states[ip_key] = {
            "seen_steps": set(),
            "current_state": None,
            "last_update": time.time(),
            "participants": {
                "client": None,
                "server": None
            },
            "tls_version": None,
            "sni": None
        }

    state = handshake_states[ip_key]
    state["last_update"] = time.time()

    # Попробуем получить negotiated_version из ServerHello или Extension
    negotiated_version = record["tls_details"].get("negotiated_version")
    client_versions = record["tls_details"].get("client_supported_versions", [])
    if state["sni"]:
        state["sni"] = record["tls_details"].get("sni")


    # print(f" SNI: {record["tls_details"].get("sni")}")
    #
    # print(f"TLS_VERSION: {tls_version}")
    # print(f"NEGOTIATED_VERSION: {negotiated_version}")
    # print(f"CLIENTS_VERSION: {client_versions}")


    candidates = []

    if negotiated_version:
        candidates.append(negotiated_version)

    if client_versions:
        candidates.extend(client_versions)

    if tls_version:
        candidates.append(tls_version)

    # Выбираем самую высокую версию из доступных кандидатов
    if candidates:
        def version_key(v):
            if not v:
                return -1
            normalized = v.replace(" ", "").lower()
            return {
                "tls1.3": 3,
                "tls1.2": 2,
                "tls1.1": 1,
                "tls1.0": 1,
                "ssl3.0": 0
            }.get(normalized, -1)

        # Фильтруем пустые значения и получаем уникальные версии
        filtered_candidates = [v for v in candidates if v]
        if filtered_candidates:
            sorted_candidates = sorted(
                list(set(filtered_candidates)),
                key=lambda v: version_key(v)
            )

            highest_candidate = sorted_candidates[-1]
            current_version_value = version_key(state["tls_version"]) if state["tls_version"] else -1
            highest_candidate_value = version_key(highest_candidate)

            # Обновляем версию только если она выше текущей или еще не установлена
            if highest_candidate_value > current_version_value:
                state["tls_version"] = highest_candidate

    # print(f"В итоге: {state["tls_version"]}")

    # Определяем участников
    if "client hello" in handshake_type:
        state["participants"]["client"] = src_ip
        state["participants"]["server"] = dst_ip
    elif "server hello" in handshake_type and state["participants"]["client"] is None:
        state["participants"]["server"] = src_ip
        state["participants"]["client"] = dst_ip

    # TLS 1.3 анализ
    if state["tls_version"] and "1.3" in state["tls_version"]:
        if "client hello" in handshake_type:
            state["seen_steps"].add("client_hello")
            state["current_state"] = "client_hello"
        elif "server hello" in handshake_type:
            state["seen_steps"].add("server_hello")
            state["current_state"] = "server_hello"
        elif "encrypted extensions" in handshake_type:
            state["seen_steps"].add("encrypted_extensions")
            state["current_state"] = "encrypted_extensions"
        elif "certificate" in handshake_type:
            state["seen_steps"].add("certificate")
            state["current_state"] = "certificate"
        elif "finished" in handshake_type:
            state["seen_steps"].add("finished")
            state["current_state"] = "finished"

    # TLS 1.2 и ниже анализ
    else:
        if "client hello" in handshake_type:
            state["seen_steps"].add("client_hello")
            state["current_state"] = "client_hello"
        elif "server hello" in handshake_type:
            state["seen_steps"].add("server_hello")
            state["current_state"] = "server_hello"
        elif "certificate" in handshake_type:
            state["seen_steps"].add("certificate")
            state["current_state"] = "certificate"
        elif "server key exchange" in handshake_type:
            state["seen_steps"].add("server_key_exchange")
            state["current_state"] = "server_key_exchange"
        elif "server hello done" in handshake_type:
            state["seen_steps"].add("server_hello_done")
            state["current_state"] = "server_hello_done"
        elif "client key exchange" in handshake_type:
            state["seen_steps"].add("client_key_exchange")
            state["current_state"] = "client_key_exchange"
        elif "change cipher spec" in handshake_type or "cipher" in packet_type:
            state["seen_steps"].add("change_cipher_spec")
            state["current_state"] = "change_cipher_spec"
        elif "finished" in handshake_type:
            state["seen_steps"].add("finished")
            state["current_state"] = "finished"

    return ip_key