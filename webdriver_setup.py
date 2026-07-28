import os
import time
import base64
import logging
import threading
import subprocess
import sys
from selenium import webdriver
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
from webdriver_manager.microsoft import EdgeChromiumDriverManager

from config import SCREENSHOT_DIR

logger = logging.getLogger('webdriver')

_driver = None
_driver_lock = threading.Lock()


def get_driver():
    global _driver
    if _driver is None:
        try:
            options = Options()
            options.add_argument('--headless=new')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--ignore-ssl-errors')
            options.add_argument('--allow-insecure-localhost')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_experimental_option('excludeSwitches', ['enable-automation'])
            options.add_experimental_option('useAutomationExtension', False)

            service = Service(EdgeChromiumDriverManager().install())
            _driver = webdriver.Edge(service=service, options=options)
            _driver.set_page_load_timeout(30)
            logger.info('WebDriver initialized successfully')
        except Exception as e:
            logger.error(f'WebDriver initialization failed: {e}')
            raise
    return _driver


def take_screenshot(url, page_id, timestamp, wait_seconds=2):
    try:
        driver = get_driver()
        with _driver_lock:
            driver.set_window_size(1920, 1080)
            driver.get(url)
            time.sleep(wait_seconds)

            ss_dir = os.path.join(SCREENSHOT_DIR, str(page_id))
            os.makedirs(ss_dir, exist_ok=True)
            filepath = os.path.join(ss_dir, f'{timestamp}_screen.png')

            resp = driver.execute_cdp_cmd('Page.captureScreenshot', {
                'format': 'png',
                'captureBeyondViewport': True,
                'fromSurface': True,
            })
            with open(filepath, 'wb') as f:
                f.write(base64.b64decode(resp['data']))
            return filepath
    except Exception as e:
        logger.error(f'Screenshot failed for {url}: {e}')
        return None


def fetch_rendered(url, wait_seconds=5):
    try:
        driver = get_driver()
        with _driver_lock:
            driver.get(url)
            time.sleep(wait_seconds)

            page_width = driver.execute_script(
                "return Math.max(document.body.scrollWidth, document.body.offsetWidth, "
                "document.documentElement.clientWidth, document.documentElement.scrollWidth, document.documentElement.offsetWidth);"
            )
            page_height = driver.execute_script(
                "return Math.max(document.body.scrollHeight, document.body.offsetHeight, "
                "document.documentElement.clientHeight, document.documentElement.scrollHeight, document.documentElement.offsetHeight);"
            )
            driver.set_window_size(page_width, page_height)

            html = driver.page_source
            return html
    except Exception as e:
        logger.error(f'Render failed for {url}: {e}')
        return None


def quit_driver():
    global _driver
    if _driver:
        try:
            _driver.quit()
        except:
            pass
        _driver = None
    if sys.platform == 'win32':
        try:
            subprocess.run(['taskkill', '/f', '/im', 'msedgedriver.exe'], capture_output=True)
            subprocess.run(['taskkill', '/f', '/im', 'msedge.exe'], capture_output=True)
        except:
            pass
