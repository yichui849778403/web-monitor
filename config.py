import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
BASELINE_DIR = os.path.join(DATA_DIR, 'baselines')
SCREENSHOT_DIR = os.path.join(DATA_DIR, 'screenshots')
REPORT_DIR = os.path.join(DATA_DIR, 'reports')
DB_PATH = os.path.join(DATA_DIR, 'monitor.db')

CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')

DEFAULT_CONFIG = {
    "global_request_interval": 8,
    "same_domain_interval": 20,
    "request_timeout": 15,
    "screenshot_interval_cycles": 1,
    "retry_count": 3,
    "retry_interval_minutes": 2,
    "screenshot_diff_threshold": 5.0,
    "report_retention_days": 90,
    "max_queue_wait": 300,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    ]
}


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
            return cfg
    return dict(DEFAULT_CONFIG)


def save_config(cfg):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
