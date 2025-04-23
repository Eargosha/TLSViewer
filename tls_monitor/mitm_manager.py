# Управление mitproxy

import os
import subprocess
from tls_monitor.config import Config

class MitmProxyManager:
    def __init__(self):
        self.process = None

    def start(self):
        os.environ["SSLKEYLOGFILE"] = Config.SSL_KEY_LOG_FILE
        command = [
            "mitmdump",
            "--ssl-insecure",
            "--set", f"sslkeylogfile={Config.SSL_KEY_LOG_FILE}",
            "--listen-port", str(Config.MITMPROXY_PORT)
        ]
        with open("mitmproxy.log", "w") as log_file:
            self.process = subprocess.Popen(
                command,
                stdout=log_file,
                stderr=log_file
            )

    def stop(self):
        if self.process:
            self.process.terminate()