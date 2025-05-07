import time

handshake_states = {}

def get_connection_key(ip1, ip2):
    return ":".join(sorted([ip1, ip2]))

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
            "tls_version": None
        }

    state = handshake_states[ip_key]
    state["last_update"] = time.time()

    # Определяем версию TLS
    if not state["tls_version"] and tls_version:
        state["tls_version"] = tls_version.strip()

    # Определяем участников
    if "client hello" in handshake_type:
        state["participants"]["client"] = src_ip
        state["participants"]["server"] = dst_ip
    elif "server hello" in handshake_type and state["participants"]["client"] is None:
        state["participants"]["server"] = src_ip
        state["participants"]["client"] = dst_ip

    # TLS 1.3 анализ
    if state["tls_version"] and "tls 1.3" in state["tls_version"]:
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

    # TLS 1.2 анализ
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