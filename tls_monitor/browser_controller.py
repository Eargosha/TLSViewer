# Управление открытым браузером (debug)

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from tls_monitor.config import Config

class BrowserController:
    def __init__(self):
        self.driver = None

    def start(self):
        chrome_options = Options()
        chrome_options.add_argument(f"--proxy-server=http://localhost:{Config.MITMPROXY_PORT}")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument(f"--ssl-key-log-file={Config.SSL_KEY_LOG_FILE}")

        service = Service(Config.CHROMEDRIVER_PATH)
        self.driver = webdriver.Chrome(service=service, options=chrome_options)
        return self.driver

    def stop(self):
        if self.driver:
            self.driver.quit()