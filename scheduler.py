import time
import threading
import logging
from datetime import datetime, timedelta
from collections import deque

from config import load_config
from models import get_db, Page, Site, DetectionResult, Baseline
from detector import run_detection

logger = logging.getLogger('scheduler')

_scheduler_running = False
_scheduler_thread = None
_queue = deque()
_current_task = None
_task_history = []
_lock = threading.Lock()
_paused = False


def get_status():
    return {
        'running': _scheduler_running,
        'paused': _paused,
        'queue_size': len(_queue),
        'current_task': _current_task,
        'history_size': len(_task_history),
    }


def pause():
    global _paused
    _paused = True


def resume():
    global _paused
    _paused = False


def build_queue():
    global _queue
    with _lock:
        pages = Page.list_all_enabled()
        domain_groups = {}
        for p in pages:
            d = p['domain']
            if d not in domain_groups:
                domain_groups[d] = []
            domain_groups[d].append(p)

        _queue = deque()
        for domain, domain_pages in sorted(domain_groups.items()):
            priority = max(dp['priority'] for dp in domain_pages)
            for dp in domain_pages:
                _queue.append(dp)


def scheduler_loop():
    global _scheduler_running, _paused, _current_task, _task_history
    config = load_config()

    time.sleep(3)

    while _scheduler_running:
        if _paused:
            time.sleep(2)
            continue

        if not _queue:
            build_queue()

        if not _queue:
            time.sleep(10)
            continue

        page = None
        with _lock:
            if _queue:
                page = _queue.popleft()

        if not page:
            continue

        pid = page['id']
        url = page['url']
        domain = page['domain']
        site_id = page.get('site_id_for_ref')

        _current_task = {'page_id': pid, 'url': url, 'started_at': datetime.now().isoformat()}
        logger.info(f'Detecting: {url}')

        try:
            result = run_detection(pid, url, domain)

            if result['status'] in ('timeout', 'connection_error', 'http_error', 'error'):
                _handle_failure(pid, url, domain, result, site_id)
            elif result['status'] == 'no_baseline':
                logger.info(f'No baseline for {url}, skipping')
            else:
                baseline = Baseline.get_latest(pid)
                baseline_id = baseline['id'] if baseline else None

                if result['status'] in ('tampered', 'malware', 'unreachable'):
                    if DetectionResult.has_unreviewed_alert(pid, result['status']):
                        logger.info(f'Skip duplicate alert for {url} [{result["status"]}]')
                        DetectionResult.log_detection(pid, None, result['status'],
                                                      result['response_status'],
                                                      result['response_time'],
                                                      result['error_message'])
                    else:
                        rid = DetectionResult.create(
                            pid, baseline_id, result['status'],
                            dom_changes=result['dom_changes'],
                            screenshot_diff_pct=result['screenshot_diff_percent'],
                            screenshot_path=result['screenshot_path'],
                            html_path=result['html_path'],
                            diff_image_path=result['diff_image_path'],
                            response_status=result['response_status'],
                            response_time=result['response_time'],
                            error_message=result['error_message'],
                        )
                        DetectionResult.log_detection(pid, rid, result['status'],
                                                      result['response_status'],
                                                      result['response_time'],
                                                      result['error_message'])
                        logger.warning(f'ALERT [{result["status"]}] {url}: {_summarize_changes(result.get("dom_changes", []))}')
                elif result['status'] == 'info':
                    msg = result.get('error_message', '')
                    if not msg:
                        pct = result.get('screenshot_diff_percent')
                        msg = f'截图像素差异 {pct:.1f}%，无 DOM 结构变更' if pct else '仅截图有变化'
                    rid = DetectionResult.create(
                        pid, baseline_id, result['status'],
                        dom_changes=result['dom_changes'],
                        screenshot_diff_pct=result['screenshot_diff_percent'],
                        screenshot_path=result['screenshot_path'],
                        html_path=result['html_path'],
                        diff_image_path=result['diff_image_path'],
                        response_status=result['response_status'],
                        response_time=result['response_time'],
                        error_message=msg,
                    )
                    DetectionResult.log_detection(pid, rid, result['status'],
                                                  result['response_status'],
                                                  result['response_time'],
                                                  msg)
                else:
                    msg = result.get('error_message', '')
                    DetectionResult.log_detection(pid, None, result['status'],
                                                  result['response_status'],
                                                  result['response_time'],
                                                  msg)

            _task_history.append({
                'page_id': pid, 'url': url, 'status': result['status'],
                'time': datetime.now().isoformat()
            })
            if len(_task_history) > 500:
                _task_history = _task_history[-200:]

        except Exception as e:
            logger.error(f'Detection error for {url}: {e}')

        _current_task = None

        same_domain_wait = config['same_domain_interval']
        if _queue:
            next_page = _queue[0]
            if next_page.get('domain') == domain:
                wait = same_domain_wait
            else:
                wait = config['global_request_interval']
        else:
            wait = config['global_request_interval']

        for _ in range(wait):
            if not _scheduler_running:
                break
            time.sleep(1)


def _handle_failure(pid, url, domain, result, site_id):
    baseline = Baseline.get_latest(pid)
    baseline_id = baseline['id'] if baseline else None

    rid = DetectionResult.create(
        pid, baseline_id, result['status'],
        error_message=result['error_message'],
        response_status=result['response_status'],
        response_time=result['response_time'],
        retry_count=1, is_retry=1,
    )
    DetectionResult.log_detection(pid, rid, result['status'],
                                  result['response_status'],
                                  result['response_time'],
                                  result['error_message'])

    retry_limit = load_config()['retry_count']
    retry_interval = load_config()['retry_interval_minutes']

    for attempt in range(2, retry_limit + 1):
        time.sleep(retry_interval * 60)
        logger.info(f'Retry {attempt}/{retry_limit} for {url}')
        try:
            r = run_detection(pid, url, domain)
            r_rid = DetectionResult.create(
                pid, baseline_id, r['status'],
                dom_changes=r['dom_changes'],
                screenshot_diff_pct=r['screenshot_diff_percent'],
                screenshot_path=r['screenshot_path'],
                html_path=r['html_path'],
                diff_image_path=r['diff_image_path'],
                response_status=r['response_status'],
                response_time=r['response_time'],
                error_message=r['error_message'],
                retry_count=attempt, is_retry=1,
            )
            DetectionResult.log_detection(pid, r_rid, r['status'],
                                          r['response_status'],
                                          r['response_time'],
                                          r['error_message'])

            if r['status'] not in ('timeout', 'connection_error', 'http_error', 'error'):
                return
        except Exception as e:
            logger.error(f'Retry error: {e}')

    final_rid = DetectionResult.create(
        pid, baseline_id, result['status'],
        error_message=result['error_message'] + f' (已重试{retry_limit}次)',
        response_status=result['response_status'],
        response_time=result['response_time'],
        retry_count=retry_limit, is_retry=0,
    )
    DetectionResult.log_detection(pid, final_rid, result['status'],
                                  result['response_status'],
                                  result['response_time'],
                                  result['error_message'])

    if result['response_status'] == 403 and site_id:
        _check_waf_block(site_id)


def _check_waf_block(site_id):
    from models import get_db
    db = get_db()
    pages = db.execute('SELECT id FROM pages WHERE site_id=? AND enabled=1', (site_id,)).fetchall()
    all_403 = True
    for p in pages:
        last = db.execute(
            'SELECT response_status FROM detection_results WHERE page_id=? ORDER BY detected_at DESC LIMIT 1',
            (p['id'],)
        ).fetchone()
        if not last or last['response_status'] != 403:
            all_403 = False
            break
    if all_403 and len(pages) > 0:
        Site.mark_waf_blocked(site_id)
        logger.warning(f'Site {site_id} 疑似被 WAF 封禁，已自动暂停检测')
    db.close()


def _summarize_changes(changes):
    if not changes:
        return '无具体变更'
    summaries = []
    for c in changes[:3]:
        summaries.append(c.get('detail', c.get('type', '')))
    return '; '.join(summaries)


def start():
    global _scheduler_running, _scheduler_thread
    if _scheduler_running:
        return
    _scheduler_running = True
    _scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
    _scheduler_thread.start()
    logger.info('Scheduler started')


def stop():
    global _scheduler_running
    _scheduler_running = False
    logger.info('Scheduler stopping')
