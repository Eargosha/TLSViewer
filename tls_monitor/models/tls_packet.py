class TLSPacket:
    def __init__(self, packet):
        self.packet = packet
        self.tls_layer = packet.tls if 'tls' in packet else None

        # Основные поля
        self.tls_version = self._get_tls_version()
        self.cipher_suite = self._get_cipher_suite()
        self.handshake_type = self._get_handshake_type()
        self.sni = self._get_sni()
        self.session_resumption = self._check_session_resumption()
        self.alpn = self._get_alpn()
        self.packet_size = self._get_packet_size()
        self.timestamp = packet.sniff_time
        self.ja3_hash = self._get_ja3_hash()
        self.server_cert_info = self._get_server_cert_info()
        self.client_random = self._get_client_random()
        self.handshake_protocol = self._get_handshake_protocol()
        self.content_type = self._get_content_type()

    def _get_tls_version(self):
        """Версия TLS в человекочитаемом формате"""
        try:
            if self.tls_layer:
                # Для TLSv1.3 проверяем supported_versions
                if hasattr(self.tls_layer, 'supported_versions'):
                    versions = self.tls_layer.supported_versions.split(",")
                    for version in versions:
                        if "TLS 1.3" in version:
                            return "TLS 1.3"
                # Для TLSv1.2 и ниже используем record_version
                if hasattr(self.tls_layer, 'record_version'):
                    version_hex = self.tls_layer.record_version
                    if version_hex == "0x0301":
                        return "TLS 1.0"
                    elif version_hex == "0x0302":
                        return "TLS 1.1"
                    elif version_hex == "0x0303":
                        return "TLS 1.2"
                return None
        except AttributeError:
            return None

    def _get_cipher_suite(self):
        """Набор шифров (например, TLS_AES_128_GCM_SHA256)"""
        try:
            if self.tls_layer:
                # Для Server Hello (выбранный шифр)
                if hasattr(self.tls_layer, 'cipher_suite'):
                    return self.tls_layer.cipher_suite
                # Для Client Hello (список поддерживаемых шифров)
                elif hasattr(self.tls_layer, 'handshake_cipher_suites'):
                    return self.tls_layer.handshake_cipher_suites.split(",")
            return None
        except AttributeError:
            return None

    def _get_handshake_type(self):
        """Тип handshake (Client Hello, Server Hello и т.д.)"""
        try:
            if self.tls_layer and hasattr(self.tls_layer, 'handshake_type'):
                handshake_types = {
                    '1': 'Client Hello',
                    '2': 'Server Hello',
                    '11': 'Certificate',
                    '14': 'Server Hello Done',
                    '16': 'Client Key Exchange',
                    '20': 'Finished',
                    '4': 'New Session Ticket'
                }
                return handshake_types.get(self.tls_layer.handshake_type, "Unknown")
            return None
        except AttributeError:
            return None

    def _get_sni(self):
        """SNI (Server Name Indication)"""
        try:
            if self.tls_layer and hasattr(self.tls_layer, 'handshake_extensions_server_name'):
                return self.tls_layer.handshake_extensions_server_name
            return None
        except AttributeError:
            return None

    def _check_session_resumption(self):
        """Проверка возобновления сессии"""
        try:
            if self.tls_layer:
                if hasattr(self.tls_layer, 'session_id') and self.tls_layer.session_id:
                    return "Session ID Resumption"
                elif hasattr(self.tls_layer, 'handshake_session_ticket'):
                    return "Session Ticket Resumption"
            return "No Resumption"
        except AttributeError:
            return "No Resumption"

    def _get_alpn(self):
        """ALPN (например, h2, http/1.1)"""
        try:
            if self.tls_layer and hasattr(self.tls_layer, 'handshake_alpn_protocol'):
                return self.tls_layer.handshake_alpn_protocol.split(",")
            return None
        except AttributeError:
            return None

    def _get_packet_size(self):
        """Размер пакета в байтах"""
        try:
            return int(self.packet.length)
        except (AttributeError, ValueError):
            return 0

    def _get_ja3_hash(self):
        """JA3-хэш (для фингерпринтинга клиентов)"""
        try:
            if self.tls_layer and hasattr(self.tls_layer, 'ja3_hash'):
                return self.tls_layer.ja3_hash
            return None
        except AttributeError:
            return None

    def _get_server_cert_info(self):
        """Информация о серверном сертификате"""
        try:
            if self.tls_layer and hasattr(self.tls_layer, 'handshake_certificate'):
                cert = self.tls_layer.handshake_certificate
                return {
                    "issuer": cert.issuer,
                    "subject": cert.subject,
                    "valid_from": cert.valid_from,
                    "valid_to": cert.valid_to,
                    "fingerprint": cert.fingerprint
                }
            return None
        except AttributeError:
            return None

    def _get_client_random(self):
        """Client Random (для анализа сессий)"""
        try:
            if self.tls_layer and hasattr(self.tls_layer, 'handshake_random'):
                return self.tls_layer.handshake_random
            return None
        except AttributeError:
            return None

    def _get_handshake_protocol(self):
        """Протокол handshake (например, TLSv1.3)"""
        try:
            if self.tls_layer and hasattr(self.tls_layer, 'handshake_protocol'):
                return self.tls_layer.handshake_protocol
            return None
        except AttributeError:
            return None

    def _get_content_type(self):
        """Тип контента (Application Data, Handshake, Alert и т.д.)"""
        try:
            if self.tls_layer and hasattr(self.tls_layer, 'content_type'):
                content_types = {
                    '20': 'Change Cipher Spec',
                    '21': 'Alert',
                    '22': 'Handshake',
                    '23': 'Application Data'
                }
                return content_types.get(self.tls_layer.content_type, "Unknown")
            return None
        except AttributeError:
            return None

    def __repr__(self):
        return (
            f"TLSPacket(\n"
            f"  TLS Version: {self.tls_version}\n"
            f"  Content Type: {self.content_type}\n"
            f"  Handshake Type: {self.handshake_type}\n"
            f"  Cipher Suite: {self.cipher_suite}\n"
            f"  SNI: {self.sni}\n"
            f"  ALPN: {self.alpn}\n"
            f"  Session Resumption: {self.session_resumption}\n"
            f"  Packet Size: {self.packet_size} bytes\n"
            f"  Client Random: {self.client_random}\n"
            f"  JA3 Hash: {self.ja3_hash}\n"
            f"  Server Certificate: {self.server_cert_info}\n"
            f"  Timestamp: {self.timestamp}\n"
            f")"
        )