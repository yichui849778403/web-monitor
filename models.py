import sqlite3
import os
import json
import time
from datetime import datetime, timedelta
from config import DB_PATH, BASELINE_DIR, SCREENSHOT_DIR, REPORT_DIR

os.makedirs(BASELINE_DIR, exist_ok=True)
os.makedirs(SCREENSHOT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT (datetime('now','localtime')),
            updated_at TIMESTAMP DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            priority INTEGER DEFAULT 5,
            request_interval INTEGER DEFAULT 8,
            waf_blocked INTEGER DEFAULT 0,
            waf_blocked_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT (datetime('now','localtime')),
            updated_at TIMESTAMP DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            render_wait INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT (datetime('now','localtime')),
            updated_at TIMESTAMP DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
            screenshot_path TEXT,
            html_path TEXT,
            dom_fingerprint TEXT,
            created_at TIMESTAMP DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS detection_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
            baseline_id INTEGER REFERENCES baselines(id),
            status TEXT NOT NULL DEFAULT 'pending',
            dom_changes TEXT,
            screenshot_diff_percent REAL,
            screenshot_path TEXT,
            html_path TEXT,
            diff_image_path TEXT,
            response_status INTEGER,
            response_time REAL,
            error_message TEXT,
            retry_count INTEGER DEFAULT 0,
            is_retry INTEGER DEFAULT 0,
            detected_at TIMESTAMP DEFAULT (datetime('now','localtime')),
            reviewed INTEGER DEFAULT 0,
            review_result TEXT,
            review_comment TEXT,
            reviewed_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
            result_id INTEGER REFERENCES detection_results(id),
            status TEXT,
            response_status INTEGER,
            response_time REAL,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS baseline_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            old_baseline_id INTEGER,
            new_baseline_id INTEGER,
            reason TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS custom_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT (datetime('now','localtime'))
        );

        CREATE INDEX IF NOT EXISTS idx_pages_site ON pages(site_id);
        CREATE INDEX IF NOT EXISTS idx_baselines_page ON baselines(page_id);
        CREATE INDEX IF NOT EXISTS idx_results_page ON detection_results(page_id);
        CREATE INDEX IF NOT EXISTS idx_results_status ON detection_results(status);
        CREATE INDEX IF NOT EXISTS idx_results_detected ON detection_results(detected_at);
        CREATE INDEX IF NOT EXISTS idx_logs_page ON detection_logs(page_id);
        CREATE INDEX IF NOT EXISTS idx_logs_created ON detection_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_history_page ON baseline_history(page_id);
    ''')
    try:
        c.execute("ALTER TABLE pages ADD COLUMN render_wait INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


class Customer:
    @staticmethod
    def list_all():
        db = get_db()
        rows = db.execute(
            'SELECT c.*, (SELECT COUNT(*) FROM sites WHERE customer_id=c.id) as site_count '
            'FROM customers c ORDER BY c.created_at DESC'
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_id(cid):
        db = get_db()
        row = db.execute('SELECT * FROM customers WHERE id=?', (cid,)).fetchone()
        db.close()
        return dict(row) if row else None

    @staticmethod
    def create(name, description=''):
        db = get_db()
        db.execute('INSERT INTO customers (name, description) VALUES (?, ?)', (name, description))
        db.commit()
        cid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        db.close()
        return cid

    @staticmethod
    def update(cid, name, description):
        db = get_db()
        db.execute(
            "UPDATE customers SET name=?, description=?, updated_at=datetime('now','localtime') WHERE id=?",
            (name, description, cid)
        )
        db.commit()
        db.close()

    @staticmethod
    def delete(cid):
        db = get_db()
        db.execute('DELETE FROM customers WHERE id=?', (cid,))
        db.commit()
        db.close()


class Site:
    @staticmethod
    def list_by_customer(cid):
        db = get_db()
        rows = db.execute(
            'SELECT s.*, '
            '(SELECT COUNT(*) FROM pages WHERE site_id=s.id) as page_count, '
            '(SELECT COUNT(*) FROM detection_results WHERE page_id IN (SELECT id FROM pages WHERE site_id=s.id) AND status != \'normal\' AND reviewed=0) as alert_count '
            'FROM sites s WHERE s.customer_id=? ORDER BY s.created_at DESC',
            (cid,)
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def list_all_enabled():
        db = get_db()
        rows = db.execute(
            'SELECT s.*, (SELECT COUNT(*) FROM pages WHERE site_id=s.id AND enabled=1) as page_count '
            'FROM sites s WHERE s.enabled=1 AND s.waf_blocked=0 ORDER BY s.priority DESC'
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_id(sid):
        db = get_db()
        row = db.execute('SELECT * FROM sites WHERE id=?', (sid,)).fetchone()
        db.close()
        return dict(row) if row else None

    @staticmethod
    def create(customer_id, name, domain, priority=5):
        db = get_db()
        db.execute(
            'INSERT INTO sites (customer_id, name, domain, priority) VALUES (?, ?, ?, ?)',
            (customer_id, name, domain.rstrip('/'), priority)
        )
        db.commit()
        sid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        db.close()
        return sid

    @staticmethod
    def update(sid, name, domain, enabled, priority):
        db = get_db()
        db.execute(
            "UPDATE sites SET name=?, domain=?, enabled=?, priority=?, updated_at=datetime('now','localtime') WHERE id=?",
            (name, domain.rstrip('/'), enabled, priority, sid)
        )
        db.commit()
        db.close()

    @staticmethod
    def delete(sid):
        db = get_db()
        db.execute('DELETE FROM sites WHERE id=?', (sid,))
        db.commit()
        db.close()

    @staticmethod
    def mark_waf_blocked(sid):
        db = get_db()
        db.execute("UPDATE sites SET waf_blocked=1, waf_blocked_at=datetime('now','localtime') WHERE id=?", (sid,))
        db.commit()
        db.close()

    @staticmethod
    def mark_waf_unblocked(sid):
        db = get_db()
        db.execute('UPDATE sites SET waf_blocked=0, waf_blocked_at=NULL WHERE id=?', (sid,))
        db.commit()
        db.close()

    @staticmethod
    def get_waf_blocked_sites():
        db = get_db()
        rows = db.execute('SELECT s.*, c.name as customer_name FROM sites s JOIN customers c ON s.customer_id=c.id WHERE s.waf_blocked=1').fetchall()
        db.close()
        return [dict(r) for r in rows]


class Page:
    @staticmethod
    def list_by_site(sid):
        db = get_db()
        rows = db.execute(
            'SELECT p.*, '
            '(SELECT status FROM detection_results WHERE page_id=p.id ORDER BY detected_at DESC LIMIT 1) as last_status, '
            '(SELECT detected_at FROM detection_results WHERE page_id=p.id ORDER BY detected_at DESC LIMIT 1) as last_detected, '
            'EXISTS(SELECT 1 FROM baselines WHERE page_id=p.id) as has_baseline '
            'FROM pages p WHERE p.site_id=? ORDER BY p.created_at DESC',
            (sid,)
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def list_all_enabled():
        db = get_db()
        rows = db.execute(
            'SELECT p.*, s.id as site_id_for_ref, s.domain, s.priority, s.waf_blocked '
            'FROM pages p '
            'JOIN sites s ON p.site_id=s.id '
            'WHERE p.enabled=1 AND s.enabled=1 AND s.waf_blocked=0 '
            'AND EXISTS (SELECT 1 FROM baselines WHERE page_id=p.id) '
            'ORDER BY s.priority DESC, p.id ASC'
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_id(pid):
        db = get_db()
        row = db.execute(
            'SELECT p.*, s.domain, s.customer_id, s.name as site_name, c.name as customer_name '
            'FROM pages p JOIN sites s ON p.site_id=s.id JOIN customers c ON s.customer_id=c.id '
            'WHERE p.id=?', (pid,)
        ).fetchone()
        db.close()
        return dict(row) if row else None

    @staticmethod
    def create(site_id, name, url, render_wait=0):
        db = get_db()
        db.execute('INSERT INTO pages (site_id, name, url, render_wait) VALUES (?, ?, ?, ?)', (site_id, name, url, render_wait))
        db.commit()
        pid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        db.close()
        return pid

    @staticmethod
    def update(pid, name, url, enabled, render_wait=0):
        db = get_db()
        db.execute(
            "UPDATE pages SET name=?, url=?, enabled=?, render_wait=?, updated_at=datetime('now','localtime') WHERE id=?",
            (name, url, enabled, render_wait, pid)
        )
        db.commit()
        db.close()

    @staticmethod
    def delete(pid):
        db = get_db()
        db.execute('DELETE FROM pages WHERE id=?', (pid,))
        db.commit()
        db.close()


class Baseline:
    @staticmethod
    def get_latest(pid):
        db = get_db()
        row = db.execute(
            'SELECT * FROM baselines WHERE page_id=? ORDER BY created_at DESC LIMIT 1', (pid,)
        ).fetchone()
        db.close()
        return dict(row) if row else None

    @staticmethod
    def get_history(pid):
        db = get_db()
        rows = db.execute(
            'SELECT * FROM baselines WHERE page_id=? ORDER BY created_at DESC', (pid,)
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def create(pid, screenshot_path, html_path, dom_fingerprint, reason=''):
        db = get_db()
        old = db.execute(
            'SELECT id FROM baselines WHERE page_id=? ORDER BY created_at DESC LIMIT 1', (pid,)
        ).fetchone()
        old_id = old['id'] if old else None

        db.execute(
            'INSERT INTO baselines (page_id, screenshot_path, html_path, dom_fingerprint) VALUES (?, ?, ?, ?)',
            (pid, screenshot_path, html_path, json.dumps(dom_fingerprint, ensure_ascii=False))
        )
        db.commit()
        new_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

        db.execute(
            'INSERT INTO baseline_history (page_id, action, old_baseline_id, new_baseline_id, reason) '
            'VALUES (?, ?, ?, ?, ?)',
            (pid, 'update' if old_id else 'create', old_id, new_id, reason)
        )
        db.commit()
        db.close()
        return new_id

    @staticmethod
    def get_history_entries(page_id=None, start_date=None, end_date=None, limit=50, offset=0):
        db = get_db()
        query = '''
            SELECT bh.*, p.url, p.name as page_name, s.name as site_name, c.name as customer_name
            FROM baseline_history bh
            JOIN pages p ON bh.page_id=p.id
            JOIN sites s ON p.site_id=s.id
            JOIN customers c ON s.customer_id=c.id
            WHERE 1=1
        '''
        params = []
        if page_id:
            query += ' AND bh.page_id=?'
            params.append(page_id)
        if start_date:
            query += ' AND date(bh.created_at) >= ?'
            params.append(start_date)
        if end_date:
            query += ' AND date(bh.created_at) <= ?'
            params.append(end_date)
        query += ' ORDER BY bh.created_at DESC LIMIT ? OFFSET ?'
        params.append(limit)
        params.append(offset)
        rows = db.execute(query, params).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def count_history_entries(page_id=None, start_date=None, end_date=None):
        db = get_db()
        query = 'SELECT COUNT(*) as cnt FROM baseline_history bh WHERE 1=1'
        params = []
        if page_id:
            query += ' AND bh.page_id=?'
            params.append(page_id)
        if start_date:
            query += ' AND date(bh.created_at) >= ?'
            params.append(start_date)
        if end_date:
            query += ' AND date(bh.created_at) <= ?'
            params.append(end_date)
        row = db.execute(query, params).fetchone()
        db.close()
        return row['cnt'] if row else 0


class DetectionResult:
    @staticmethod
    def create(pid, baseline_id, status, dom_changes=None, screenshot_diff_pct=None,
               screenshot_path=None, html_path=None, diff_image_path=None,
               response_status=None, response_time=None, error_message=None,
               retry_count=0, is_retry=0):
        db = get_db()
        db.execute(
            'INSERT INTO detection_results '
            '(page_id, baseline_id, status, dom_changes, screenshot_diff_percent, '
            'screenshot_path, html_path, diff_image_path, response_status, '
            'response_time, error_message, retry_count, is_retry) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (pid, baseline_id, status,
             json.dumps(dom_changes, ensure_ascii=False) if dom_changes else None,
             screenshot_diff_pct, screenshot_path, html_path, diff_image_path,
             response_status, response_time, error_message, retry_count, is_retry)
        )
        db.commit()
        rid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        db.close()
        return rid

    @staticmethod
    def log_detection(pid, rid, status, response_status=None, response_time=None, error_message=None):
        db = get_db()
        db.execute(
            'INSERT INTO detection_logs (page_id, result_id, status, response_status, response_time, error_message) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (pid, rid, status, response_status, response_time, error_message)
        )
        db.commit()
        db.close()

    @staticmethod
    def get_alerts(limit=100, offset=0):
        db = get_db()
        rows = db.execute(
            'SELECT dr.*, p.url, p.name as page_name, s.name as site_name, c.name as customer_name '
            'FROM detection_results dr '
            'JOIN pages p ON dr.page_id=p.id '
            'JOIN sites s ON p.site_id=s.id '
            'JOIN customers c ON s.customer_id=c.id '
            'WHERE dr.status != \'normal\' AND dr.is_retry=0 '
            'ORDER BY dr.detected_at DESC LIMIT ? OFFSET ?',
            (limit, offset)
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def count_alerts_all():
        db = get_db()
        row = db.execute(
            'SELECT COUNT(*) as cnt FROM detection_results '
            'WHERE status != \'normal\' AND is_retry=0'
        ).fetchone()
        db.close()
        return row['cnt'] if row else 0

    @staticmethod
    def has_unreviewed_alert(page_id, status):
        db = get_db()
        row = db.execute(
            'SELECT COUNT(*) as cnt FROM detection_results '
            'WHERE page_id=? AND status=? AND is_retry=0 AND reviewed=0',
            (page_id, status)
        ).fetchone()
        db.close()
        return (row['cnt'] if row else 0) > 0

    @staticmethod
    def get_page_results(pid, limit=50):
        db = get_db()
        rows = db.execute(
            'SELECT * FROM detection_results WHERE page_id=? ORDER BY detected_at DESC LIMIT ?',
            (pid, limit)
        ).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_id(rid):
        db = get_db()
        row = db.execute(
            'SELECT dr.*, p.url, p.name as page_name, s.name as site_name, s.domain, '
            'c.name as customer_name, c.id as customer_id '
            'FROM detection_results dr '
            'JOIN pages p ON dr.page_id=p.id '
            'JOIN sites s ON p.site_id=s.id '
            'JOIN customers c ON s.customer_id=c.id '
            'WHERE dr.id=?', (rid,)
        ).fetchone()
        db.close()
        return dict(row) if row else None

    @staticmethod
    def review(rid, result, comment=''):
        db = get_db()
        db.execute(
            "UPDATE detection_results SET reviewed=1, review_result=?, review_comment=?, reviewed_at=datetime('now','localtime') WHERE id=?",
            (result, comment, rid)
        )
        db.commit()
        db.close()

    @staticmethod
    def count_alerts():
        db = get_db()
        row = db.execute(
            'SELECT COUNT(*) as cnt FROM detection_results '
            'WHERE status != \'normal\' AND is_retry=0 AND reviewed=0'
        ).fetchone()
        db.close()
        return row['cnt']

    @staticmethod
    def get_logs(start_date=None, end_date=None, page_id=None, limit=200, offset=0):
        db = get_db()
        query = '''
            SELECT dl.*, p.url, p.name as page_name,
                   s.name as site_name, c.name as customer_name
            FROM detection_logs dl
            JOIN pages p ON dl.page_id=p.id
            JOIN sites s ON p.site_id=s.id
            JOIN customers c ON s.customer_id=c.id
            WHERE 1=1
        '''
        params = []
        if start_date:
            query += ' AND date(dl.created_at) >= ?'
            params.append(start_date)
        if end_date:
            query += ' AND date(dl.created_at) <= ?'
            params.append(end_date)
        if page_id:
            query += ' AND dl.page_id=?'
            params.append(page_id)
        query += ' ORDER BY dl.created_at DESC LIMIT ? OFFSET ?'
        params.append(limit)
        params.append(offset)
        rows = db.execute(query, params).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def count_logs(start_date=None, end_date=None, page_id=None):
        db = get_db()
        query = '''
            SELECT COUNT(*) as cnt FROM detection_logs dl
            JOIN pages p ON dl.page_id=p.id
            WHERE 1=1
        '''
        params = []
        if start_date:
            query += ' AND date(dl.created_at) >= ?'
            params.append(start_date)
        if end_date:
            query += ' AND date(dl.created_at) <= ?'
            params.append(end_date)
        if page_id:
            query += ' AND dl.page_id=?'
            params.append(page_id)
        row = db.execute(query, params).fetchone()
        db.close()
        return row['cnt'] if row else 0

    @staticmethod
    def get_dashboard_stats():
        db = get_db()
        stats = {}

        total_pages = db.execute(
            'SELECT COUNT(*) as cnt FROM pages WHERE enabled=1'
        ).fetchone()['cnt']
        stats['total_pages'] = total_pages

        total_sites = db.execute(
            'SELECT COUNT(*) as cnt FROM sites WHERE enabled=1'
        ).fetchone()['cnt']
        stats['total_sites'] = total_sites

        alerts = db.execute(
            'SELECT COUNT(*) as cnt FROM detection_results '
            'WHERE status != \'normal\' AND is_retry=0 AND reviewed=0'
        ).fetchone()['cnt']
        stats['active_alerts'] = alerts

        waf_blocked = db.execute(
            'SELECT COUNT(*) as cnt FROM sites WHERE waf_blocked=1'
        ).fetchone()['cnt']
        stats['waf_blocked'] = waf_blocked

        last_detection = db.execute(
            'SELECT detected_at FROM detection_results ORDER BY detected_at DESC LIMIT 1'
        ).fetchone()
        stats['last_detection'] = last_detection['detected_at'] if last_detection else None

        today = datetime.now().strftime('%Y-%m-%d')
        today_detections = db.execute(
            'SELECT COUNT(*) as cnt FROM detection_logs WHERE date(created_at)=?', (today,)
        ).fetchone()['cnt']
        stats['today_detections'] = today_detections

        status_breakdown = db.execute(
            'SELECT status, COUNT(*) as cnt FROM detection_results '
            'WHERE is_retry=0 GROUP BY status'
        ).fetchall()
        stats['status_breakdown'] = {r['status']: r['cnt'] for r in status_breakdown}

        hourly = db.execute('''
            SELECT 
                CAST(strftime('%H', created_at) AS INTEGER) as hour,
                COUNT(*) as cnt
            FROM detection_logs 
            WHERE date(created_at)=?
            GROUP BY strftime('%H', created_at)
            ORDER BY hour
        ''', (today,)).fetchall()
        stats['hourly_detections'] = {r['hour']: r['cnt'] for r in hourly}

        db.close()
        return stats

    @staticmethod
    def get_recent_retries(pid):
        db = get_db()
        rows = db.execute(
            'SELECT retry_count FROM detection_results WHERE page_id=? AND is_retry=1 '
            'ORDER BY detected_at DESC LIMIT 10',
            (pid,)
        ).fetchall()
        db.close()
        return [r['retry_count'] for r in rows]


class CustomKeyword:
    @staticmethod
    def list_all():
        db = get_db()
        rows = db.execute('SELECT * FROM custom_keywords ORDER BY created_at DESC').fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def add(keyword):
        db = get_db()
        kw = keyword.strip()
        if not kw:
            db.close()
            return None
        db.execute('INSERT OR IGNORE INTO custom_keywords (keyword) VALUES (?)', (kw,))
        db.commit()
        kid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        db.close()
        return kid

    @staticmethod
    def delete(kid):
        db = get_db()
        db.execute('DELETE FROM custom_keywords WHERE id=?', (kid,))
        db.commit()
        db.close()

    @staticmethod
    def get_all_keywords():
        builtin = [
            'hacked', 'hacker', 'defaced', 'pwned',
            '赌博', '博彩', '赌场', '六合彩', '时时彩',
            '色情', '成人', '裸聊', '约炮',
            '黑页', '黑客', '被黑',
            'backdoor', 'webshell', 'shell',
        ]
        db = get_db()
        rows = db.execute('SELECT keyword FROM custom_keywords').fetchall()
        db.close()
        custom = [r['keyword'] for r in rows]
        return builtin + custom
