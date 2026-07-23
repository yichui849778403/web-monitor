import os
import json
import difflib
import logging
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, send_from_directory, Response, flash

from config import load_config, save_config, BASELINE_DIR, SCREENSHOT_DIR, DATA_DIR, BASE_DIR
from models import init_db, Customer, Site, Page, Baseline, DetectionResult, CustomKeyword, get_db
from detector import create_baseline_for_page
from report_generator import generate_daily_report, generate_report_for_customer
import scheduler

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
logger = logging.getLogger('app')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()

init_db()


@app.route('/data/<path:filename>')
def serve_data(filename):
    return send_from_directory(DATA_DIR, filename)


def _now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _today_str():
    return datetime.now().strftime('%Y-%m-%d')


app.jinja_env.globals['now_str'] = _now_str
app.jinja_env.globals['today_str'] = _today_str


@app.context_processor
def inject_globals():
    return {
        'alert_count': DetectionResult.count_alerts(),
        'waf_blocked_count': _waf_blocked_count(),
        'scheduler_status': scheduler.get_status(),
    }


def _waf_blocked_count():
    sites = Site.get_waf_blocked_sites()
    return len(sites)


def _status_label(status):
    labels = {
        'normal': '正常',
        'tampered': '疑似篡改',
        'malware': '疑似挂马',
        'unreachable': '无法访问',
        'timeout': '超时',
        'connection_error': '连接失败',
        'http_error': 'HTTP错误',
        'error': '检测异常',
        'no_baseline': '无基线',
        'info': '仅记录',
    }
    return labels.get(status, status)


def _status_class(status):
    classes = {
        'normal': 'success',
        'tampered': 'warning',
        'malware': 'danger',
        'unreachable': 'danger',
        'timeout': 'warning',
        'connection_error': 'danger',
        'http_error': 'danger',
        'error': 'danger',
        'no_baseline': 'secondary',
        'info': 'info',
    }
    return classes.get(status, 'secondary')


app.jinja_env.globals['status_label'] = _status_label
app.jinja_env.globals['status_class'] = _status_class


def _format_dt(dt_str):
    if not dt_str:
        return '-'
    try:
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return dt.strftime('%m-%d %H:%M')
    except:
        return str(dt_str)[:16]


def _data_path(abspath):
    if not abspath:
        return ''
    try:
        rel = os.path.relpath(abspath, DATA_DIR)
        return rel.replace('\\', '/')
    except:
        return ''


app.jinja_env.globals['data_path'] = _data_path
app.jinja_env.globals['format_dt'] = _format_dt


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route('/')
def dashboard():
    stats = DetectionResult.get_dashboard_stats()
    alerts = DetectionResult.get_alerts(limit=20)
    logs = DetectionResult.get_logs(start_date=_today_str(), limit=50)
    return render_template('dashboard.html', stats=stats, alerts=alerts, logs=logs)


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------
def _is_modal():
    return request.headers.get('X-Modal') == '1' or request.args.get('modal') == '1'


@app.route('/customers')
def customers():
    cid = request.args.get('cid', type=int)
    clist = Customer.list_all()
    waf_sites = Site.get_waf_blocked_sites()
    waf_ids = {s['id'] for s in waf_sites}

    for c in clist:
        sites = Site.list_by_customer(c['id'])
        for s in sites:
            s['waf_blocked'] = s['id'] in waf_ids
            s['pages'] = Page.list_by_site(s['id'])
        c['sites'] = sites

    selected_cid = cid
    if not selected_cid and clist:
        selected_cid = clist[0]['id']

    selected_customer = None
    if selected_cid:
        for c in clist:
            if c['id'] == selected_cid:
                selected_customer = c
                break

    return render_template('customers.html', customers=clist,
                           selected_cid=selected_cid, selected_customer=selected_customer)


@app.route('/customers/add', methods=['GET', 'POST'])
def customer_add():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        desc = request.form.get('description', '').strip()
        if name:
            Customer.create(name, desc)
            return redirect(url_for('customers'))
    return render_template('customer_form.html', customer=None, modal=_is_modal())


@app.route('/customers/<int:cid>/edit', methods=['GET', 'POST'])
def customer_edit(cid):
    c = Customer.get_by_id(cid)
    if not c:
        return redirect(url_for('customers'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        desc = request.form.get('description', '').strip()
        if name:
            Customer.update(cid, name, desc)
            return redirect(url_for('customers', cid=cid))
    return render_template('customer_form.html', customer=c, modal=_is_modal())


@app.route('/customers/<int:cid>/delete', methods=['POST'])
def customer_delete(cid):
    Customer.delete(cid)
    return redirect(url_for('customers'))


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------
@app.route('/customers/<int:cid>/sites')
def sites(cid):
    return redirect(url_for('customers', cid=cid))


@app.route('/customers/<int:cid>/sites/add', methods=['GET', 'POST'])
def site_add(cid):
    cust = Customer.get_by_id(cid)
    if not cust:
        return redirect(url_for('customers'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        domain = request.form.get('domain', '').strip()
        priority = int(request.form.get('priority', 5))
        if name and domain:
            Site.create(cid, name, domain, priority)
            return redirect(url_for('customers', cid=cid))
    return render_template('site_form.html', customer=cust, site=None, modal=_is_modal())


@app.route('/sites/<int:sid>/edit', methods=['GET', 'POST'])
def site_edit(sid):
    s = Site.get_by_id(sid)
    if not s:
        return redirect(url_for('dashboard'))
    cust = Customer.get_by_id(s['customer_id'])
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        domain = request.form.get('domain', '').strip()
        enabled = int(request.form.get('enabled', '1'))
        priority = int(request.form.get('priority', 5))
        if name and domain:
            Site.update(sid, name, domain, enabled, priority)
            return redirect(url_for('customers', cid=s['customer_id']))
    return render_template('site_form.html', customer=cust, site=s, modal=_is_modal())


@app.route('/sites/<int:sid>/delete', methods=['POST'])
def site_delete(sid):
    s = Site.get_by_id(sid)
    if not s:
        return redirect(url_for('dashboard'))
    cid = s['customer_id']
    Site.delete(sid)
    return redirect(url_for('customers', cid=cid))


@app.route('/sites/<int:sid>/waf-unblock', methods=['POST'])
def site_waf_unblock(sid):
    s = Site.get_by_id(sid)
    if s:
        Site.mark_waf_unblocked(sid)
        return redirect(url_for('customers', cid=s['customer_id']))
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route('/sites/<int:sid>/pages')
def pages(sid):
    s = Site.get_by_id(sid)
    if not s:
        return redirect(url_for('dashboard'))
    return redirect(url_for('customers', cid=s['customer_id']))


@app.route('/sites/<int:sid>/pages/add', methods=['GET', 'POST'])
def page_add(sid):
    s = Site.get_by_id(sid)
    if not s:
        return redirect(url_for('dashboard'))
    cust = Customer.get_by_id(s['customer_id'])
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        url = request.form.get('url', '').strip()
        render_wait = int(request.form.get('render_wait', 0))
        if name and url:
            Page.create(sid, name, url, render_wait)
            return redirect(url_for('customers', cid=s['customer_id']))
    return render_template('page_form.html', site=s, customer=cust, page=None, modal=_is_modal())


@app.route('/pages/<int:pid>/edit', methods=['GET', 'POST'])
def page_edit(pid):
    p = Page.get_by_id(pid)
    if not p:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        url = request.form.get('url', '').strip()
        enabled = int(request.form.get('enabled', '1'))
        render_wait = int(request.form.get('render_wait', 0))
        if name and url:
            Page.update(pid, name, url, enabled, render_wait)
            return redirect(url_for('customers', cid=p['customer_id']))
    return render_template('page_form.html', site={'id': p['site_id'], 'name': p['site_name']},
                           customer={'id': p['customer_id'], 'name': p['customer_name']}, page=p, modal=_is_modal())


@app.route('/pages/<int:pid>/delete', methods=['POST'])
def page_delete(pid):
    p = Page.get_by_id(pid)
    if p:
        Page.delete(pid)
        return redirect(url_for('customers', cid=p['customer_id']))
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Baseline operations
# ---------------------------------------------------------------------------
@app.route('/pages/<int:pid>/baseline', methods=['POST'])
def page_baseline_create(pid):
    p = Page.get_by_id(pid)
    if not p:
        return redirect(url_for('dashboard'))
    reason = request.form.get('reason', '手动建立基线')
    bid, error = create_baseline_for_page(pid, p['url'], reason)
    if error:
        flash(f'基线建立失败: {error}', 'danger')
    else:
        flash('基线建立成功', 'success')
    return redirect(url_for('customers', cid=p['customer_id']))


@app.route('/pages/<int:pid>/baseline/update', methods=['POST'])
def page_baseline_update(pid):
    p = Page.get_by_id(pid)
    if not p:
        return redirect(url_for('dashboard'))
    reason = request.form.get('reason', '人工确认后更新基线')
    bid, error = create_baseline_for_page(pid, p['url'], reason)
    if error:
        logger.error(f'Baseline update failed: {error}')
    return redirect(url_for('customers', cid=p['customer_id']))


@app.route('/baseline/history')
def baseline_history():
    page_id = request.args.get('page_id', type=int)
    start = request.args.get('start')
    end = request.args.get('end')
    p = request.args.get('p', 1, type=int)
    per_page = request.args.get('per_page', 30, type=int)
    offset = (p - 1) * per_page
    entries = Baseline.get_history_entries(page_id=page_id, start_date=start, end_date=end, limit=per_page, offset=offset)
    total = Baseline.count_history_entries(page_id=page_id, start_date=start, end_date=end)
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template('baseline_history.html', entries=entries, page=p, total_pages=total_pages, total=total, per_page=per_page)


# ---------------------------------------------------------------------------
# Alerts & Diff View
# ---------------------------------------------------------------------------
@app.route('/alerts')
def alerts():
    p = request.args.get('p', 1, type=int)
    per_page = request.args.get('per_page', 30, type=int)
    offset = (p - 1) * per_page
    alist = DetectionResult.get_alerts(limit=per_page, offset=offset)
    total = DetectionResult.count_alerts_all()
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template('alerts.html', alerts=alist, page=p, total_pages=total_pages, total=total, per_page=per_page)


@app.route('/alerts/<int:rid>/review', methods=['POST'])
def alert_review(rid):
    result = request.form.get('result', 'confirmed_threat')
    comment = request.form.get('comment', '')
    DetectionResult.review(rid, result, comment)

    if result == 'baseline_updated':
        r = DetectionResult.get_by_id(rid)
        if r:
            reason = '人工审核确认安全，更新基线'
            create_baseline_for_page(r['page_id'], r['url'], reason)

    return redirect(url_for('alerts'))


@app.route('/diff/<int:rid>')
def diff_view(rid):
    r = DetectionResult.get_by_id(rid)
    if not r:
        return redirect(url_for('alerts'))

    baseline = Baseline.get_latest(r['page_id'])
    baseline_html = ''
    if baseline and baseline['html_path'] and os.path.exists(baseline['html_path']):
        with open(baseline['html_path'], 'r', encoding='utf-8') as f:
            baseline_html = f.read()

    current_html = ''
    if r['html_path'] and os.path.exists(r['html_path']):
        with open(r['html_path'], 'r', encoding='utf-8') as f:
            current_html = f.read()

    dom_changes = json.loads(r['dom_changes']) if r['dom_changes'] else []

    source_diff = None
    if baseline_html or current_html:
        bl_lines = baseline_html.splitlines(keepends=True)
        cr_lines = current_html.splitlines(keepends=True)
        diff = difflib.HtmlDiff(tabsize=2, wrapcolumn=120)
        from_time = _format_dt(baseline['created_at']) if baseline else ''
        to_time = _format_dt(r['detected_at'])
        source_diff = diff.make_table(
            bl_lines, cr_lines,
            fromdesc=f'基线 HTML  ({from_time})' if from_time else '基线 HTML',
            todesc=f'当前 HTML  ({to_time})',
            context=False
        )

    return render_template('diff_view.html', result=r, baseline_html=baseline_html,
                           current_html=current_html, dom_changes=dom_changes,
                           baseline=baseline, source_diff=source_diff)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
@app.route('/reports')
def reports():
    from config import REPORT_DIR
    os.makedirs(REPORT_DIR, exist_ok=True)
    files = []
    for f in sorted(os.listdir(REPORT_DIR), reverse=True):
        if f.endswith('.html'):
            fp = os.path.join(REPORT_DIR, f)
            files.append({
                'filename': f,
                'size': os.path.getsize(fp),
                'mtime': datetime.fromtimestamp(os.path.getmtime(fp)).strftime('%Y-%m-%d %H:%M:%S'),
            })
    customers_report = Customer.list_all()
    return render_template('reports.html', files=files, customers=customers_report)


@app.route('/reports/generate', methods=['POST'])
def report_generate():
    cid = request.form.get('customer_id', type=int)
    date = request.form.get('date', _today_str())
    if cid:
        path = generate_report_for_customer(cid, date)
    else:
        path = generate_daily_report(date)
    if path:
        logger.info(f'Report generated: {path}')
    return redirect(url_for('reports'))


@app.route('/reports/view/<filename>')
def report_view(filename):
    from config import REPORT_DIR
    path = os.path.join(REPORT_DIR, filename)
    if os.path.exists(path):
        return send_file(path, mimetype='text/html')
    return '报告不存在', 404


@app.route('/reports/delete/<filename>', methods=['POST'])
def report_delete(filename):
    from config import REPORT_DIR
    path = os.path.join(REPORT_DIR, filename)
    if os.path.exists(path):
        os.remove(path)
    return redirect(url_for('reports'))


# ---------------------------------------------------------------------------
# Detection logs
# ---------------------------------------------------------------------------
@app.route('/logs')
def detection_logs():
    page_id = request.args.get('page_id', type=int)
    start = request.args.get('start', _today_str())
    end = request.args.get('end', _today_str())
    p = request.args.get('p', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (p - 1) * per_page
    logs = DetectionResult.get_logs(start_date=start, end_date=end, page_id=page_id, limit=per_page, offset=offset)
    total = DetectionResult.count_logs(start_date=start, end_date=end, page_id=page_id)
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template('detection_logs.html', logs=logs, page=p, total_pages=total_pages, total=total, per_page=per_page)


# ---------------------------------------------------------------------------
# Scheduler control
# ---------------------------------------------------------------------------
@app.route('/scheduler/status')
def scheduler_status():
    return jsonify(scheduler.get_status())


@app.route('/scheduler/start', methods=['POST'])
def scheduler_start():
    scheduler.start()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/scheduler/stop', methods=['POST'])
def scheduler_stop():
    scheduler.stop()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/scheduler/pause', methods=['POST'])
def scheduler_pause():
    scheduler.pause()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/scheduler/resume', methods=['POST'])
def scheduler_resume():
    scheduler.resume()
    return redirect(request.referrer or url_for('dashboard'))


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    config = load_config()
    keywords = CustomKeyword.list_all()
    if request.method == 'POST':
        config['global_request_interval'] = int(request.form.get('global_request_interval', 8))
        config['same_domain_interval'] = int(request.form.get('same_domain_interval', 20))
        config['request_timeout'] = int(request.form.get('request_timeout', 15))
        config['retry_count'] = int(request.form.get('retry_count', 3))
        config['retry_interval_minutes'] = int(request.form.get('retry_interval_minutes', 2))
        config['screenshot_diff_threshold'] = float(request.form.get('screenshot_diff_threshold', 5.0))
        config['report_retention_days'] = int(request.form.get('report_retention_days', 90))
        save_config(config)
        return redirect(url_for('settings'))
    return render_template('settings.html', config=config, keywords=keywords)


@app.route('/keywords/add', methods=['POST'])
def keyword_add():
    kw = request.form.get('keyword', '').strip()
    if kw:
        CustomKeyword.add(kw)
    return redirect(url_for('settings'))


@app.route('/keywords/<int:kid>/delete', methods=['POST'])
def keyword_delete(kid):
    CustomKeyword.delete(kid)
    return redirect(url_for('settings'))


@app.route('/keywords/export')
def keyword_export():
    keywords = CustomKeyword.list_all()
    content = '\n'.join(kw['keyword'] for kw in keywords)
    from io import BytesIO
    buf = BytesIO(content.encode('utf-8'))
    buf.seek(0)
    filename = f'keywords_{_today_str()}.txt'
    return send_file(buf, mimetype='text/plain; charset=utf-8', as_attachment=True, download_name=filename)


@app.route('/keywords/import', methods=['POST'])
def keyword_import():
    file = request.files.get('file')
    if file and file.filename:
        text = file.read().decode('utf-8', errors='ignore')
        added = 0
        for line in text.splitlines():
            kw = line.strip()
            if kw:
                kid = CustomKeyword.add(kw)
                if kid:
                    added += 1
    return redirect(url_for('settings'))


@app.route('/reset-monitoring', methods=['POST'])
def reset_monitoring():
    was_running = scheduler._scheduler_running
    if was_running:
        scheduler.stop()
    
    db = get_db()
    db.execute('DELETE FROM detection_logs')
    db.execute('DELETE FROM detection_results')
    db.execute('DELETE FROM baseline_history')
    db.execute('DELETE FROM baselines')
    db.commit()
    db.close()
    import shutil
    for d in [BASELINE_DIR, SCREENSHOT_DIR, os.path.join(BASE_DIR, 'data', 'reports')]:
        if os.path.exists(d):
            shutil.rmtree(d, ignore_errors=True)
    os.makedirs(BASELINE_DIR, exist_ok=True)
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    
    if was_running:
        scheduler.start()
    
    flash('监测数据已重置，客户/站点/页面资产已保留', 'success')
    return redirect(url_for('settings'))


@app.route('/rules')
def rules():
    return render_template('rules.html')


@app.route('/pages/<int:pid>/baseline/view')
def baseline_view(pid):
    p = Page.get_by_id(pid)
    if not p:
        return redirect(url_for('dashboard'))
    baseline = Baseline.get_latest(pid)
    if not baseline:
        return redirect(url_for('customers', cid=p['customer_id']))

    baseline_html = ''
    if baseline['html_path'] and os.path.exists(baseline['html_path']):
        with open(baseline['html_path'], 'r', encoding='utf-8') as f:
            baseline_html = f.read()
    return render_template('baseline_view.html', page=p, baseline=baseline,
                           baseline_html=baseline_html)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
import atexit
def cleanup():
    scheduler.stop()
    from webdriver_setup import quit_driver
    quit_driver()

atexit.register(cleanup)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
