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
    print (packet_type)

    if ip_key not in handshake_states:
        handshake_states[ip_key] = {
            "seen_steps": set(),
            "current_state": None,
            "last_update": time.time(),
            "participants": {
                "client": None,
                "server": None
            }
        }

    state = handshake_states[ip_key]
    state["last_update"] = time.time()

    if "client hello" in handshake_type:
        state["participants"]["client"] = src_ip
        state["participants"]["server"] = dst_ip
    elif "server hello" in handshake_type and state["participants"]["client"] is None:
        state["participants"]["server"] = src_ip
        state["participants"]["client"] = dst_ip

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
        print("CIPHER")
        state["seen_steps"].add("change_cipher_spec")
        state["current_state"] = "change_cipher_spec"
    elif "finished" in handshake_type:
        state["seen_steps"].add("finished")
        state["current_state"] = "finished"

    return ip_key