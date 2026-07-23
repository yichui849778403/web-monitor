import os
import json
from datetime import datetime
from config import REPORT_DIR, load_config
from models import get_db, DetectionResult, Baseline


def _get_data_for_report(customer_id=None, date=None):
    config = load_config()
    db = get_db()

    if not date:
        date = datetime.now().strftime('%Y-%m-%d')

    where_c = ''
    params = [date]
    if customer_id:
        where_c = ' AND c.id=?'
        params.append(customer_id)

    customers = db.execute(
        'SELECT * FROM customers WHERE 1=1' + (f' AND id={customer_id}' if customer_id else ''),
    ).fetchall()

    result = []
    for cust in customers:
        sites = db.execute(
            'SELECT * FROM sites WHERE customer_id=?', (cust['id'],)
        ).fetchall()

        site_data = []
        for site in sites:
            pages = db.execute(
                'SELECT * FROM pages WHERE site_id=?', (site['id'],)
            ).fetchall()

            page_data = []
            for page in pages:
                detections = db.execute(
                    'SELECT * FROM detection_logs WHERE page_id=? AND date(created_at)=? ORDER BY created_at ASC',
                    (page['id'], date)
                ).fetchall()

                alerts = db.execute(
                    'SELECT * FROM detection_results WHERE page_id=? AND date(detected_at)=? AND status != \'normal\' AND is_retry=0',
                    (page['id'], date)
                ).fetchall()

                baseline_history = db.execute('''
                    SELECT bh.* FROM baseline_history bh
                    WHERE bh.page_id=? AND date(bh.created_at)=?
                    ORDER BY bh.created_at
                ''', (page['id'], date)).fetchall()

                last_result = db.execute(
                    'SELECT * FROM detection_results WHERE page_id=? ORDER BY detected_at DESC LIMIT 1',
                    (page['id'],)
                ).fetchone()

                page_data.append({
                    'page': dict(page),
                    'detection_count': len(detections),
                    'alerts': [dict(a) for a in alerts],
                    'last_status': dict(last_result) if last_result else None,
                    'baseline_updates': [dict(h) for h in baseline_history],
                })

            site_data.append({
                'site': dict(site),
                'pages': page_data,
                'page_count': len(pages),
                'alert_count': sum(len(p['alerts']) for p in page_data),
            })

        result.append({
            'customer': dict(cust),
            'sites': site_data,
            'page_count': sum(s['page_count'] for s in site_data),
            'alert_count': sum(s['alert_count'] for s in site_data),
        })

    db.close()
    return result


def generate_daily_report(date=None):
    if not date:
        date = datetime.now().strftime('%Y-%m-%d')

    data = _get_data_for_report(date=date)
    html = _render_report_html(data, date)

    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f'report_{date}.html'
    path = os.path.join(REPORT_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)

    _cleanup_old_reports()
    return path


def generate_report_for_customer(customer_id, date=None):
    if not date:
        date = datetime.now().strftime('%Y-%m-%d')

    data = _get_data_for_report(customer_id=customer_id, date=date)

    customer_name = data[0]['customer']['name'] if data else 'unknown'
    html = _render_report_html(data, date, customer_name)

    os.makedirs(REPORT_DIR, exist_ok=True)
    safe_name = customer_name.replace('/', '_').replace('\\', '_')[:30]
    filename = f'report_{safe_name}_{date}.html'
    path = os.path.join(REPORT_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)

    _cleanup_old_reports()
    return path


def _render_report_html(data, date, title_extra=None):
    title = f'网站监测日报 - {date}'
    if title_extra:
        title = f'网站监测日报 - {title_extra} - {date}'

    total_pages = sum(c['page_count'] for c in data)
    total_alerts = sum(c['alert_count'] for c in data)

    STATUS_LABELS = {
        'normal': '正常',
        'tampered': '疑似篡改',
        'malware': '疑似挂马',
        'unreachable': '无法访问',
        'timeout': '超时',
        'connection_error': '连接失败',
        'http_error': 'HTTP错误',
        'error': '检测异常',
    }

    rows_html = ''
    for cust_data in data:
        for site_data in cust_data['sites']:
            for page_data in site_data['pages']:
                p = page_data['page']
                ls = page_data.get('last_status')
                status_label = STATUS_LABELS.get(ls['status'], ls['status']) if ls else '未检测'
                status_style = ''
                if ls and ls['status'] in ('malware', 'tampered'):
                    status_style = 'color:red;font-weight:bold;'
                elif ls and ls['status'] in ('unreachable', 'connection_error', 'http_error'):
                    status_style = 'color:red;'

                rows_html += f'''
                <tr>
                    <td>{cust_data['customer']['name']}</td>
                    <td>{site_data['site']['name']}</td>
                    <td><a href="{p['url']}" target="_blank">{p['name']}</a></td>
                    <td style="{status_style}">{status_label}</td>
                    <td>{page_data['detection_count']}</td>
                </tr>'''

    alerts_html = ''
    for cust_data in data:
        for site_data in cust_data['sites']:
            for page_data in site_data['pages']:
                for alert in page_data['alerts']:
                    status_label = STATUS_LABELS.get(alert['status'], alert['status'])
                    alerts_html += f'''
                    <tr>
                        <td>{cust_data['customer']['name']}</td>
                        <td>{site_data['site']['name']}</td>
                        <td>{page_data['page']['name']}</td>
                        <td style="color:red;">{status_label}</td>
                        <td>{alert.get('detected_at', '-')[:16]}</td>
                    </tr>'''

    baseline_html = ''
    for cust_data in data:
        for site_data in cust_data['sites']:
            for page_data in site_data['pages']:
                for bu in page_data['baseline_updates']:
                    action = '新建基线' if bu['action'] == 'create' else '更新基线'
                    baseline_html += f'''
                    <tr>
                        <td>{cust_data['customer']['name']}</td>
                        <td>{site_data['site']['name']}</td>
                        <td>{page_data['page']['name']}</td>
                        <td>{action}</td>
                        <td>{bu.get('reason', '-')}</td>
                        <td>{bu.get('created_at', '-')[:16]}</td>
                    </tr>'''

    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
    body {{ font-family: "Microsoft YaHei", sans-serif; margin: 30px; color: #333; font-size: 13px; }}
    h1 {{ text-align: center; color: #1a73e8; font-size: 20px; margin-bottom: 5px; }}
    .subtitle {{ text-align: center; color: #666; margin-bottom: 20px; font-size: 12px; }}
    .summary {{ display: flex; gap: 20px; justify-content: center; margin-bottom: 25px; }}
    .summary-item {{ text-align: center; padding: 10px 20px; background: #f5f5f5; border-radius: 6px; }}
    .summary-item .num {{ font-size: 22px; font-weight: bold; }}
    .summary-item .num.red {{ color: #d93025; }}
    h2 {{ color: #1a73e8; font-size: 16px; border-bottom: 1px solid #e0e0e0; padding-bottom: 5px; margin-top: 25px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 10px 0 20px; font-size: 12px; }}
    th {{ background: #f0f0f0; padding: 8px 10px; text-align: left; border: 1px solid #ddd; }}
    td {{ padding: 6px 10px; border: 1px solid #ddd; }}
    tr:nth-child(even) {{ background: #fafafa; }}
    .footer {{ text-align: center; color: #999; font-size: 11px; margin-top: 30px; border-top: 1px solid #eee; padding-top: 10px; }}
    a {{ color: #1a73e8; }}
    .no-data {{ color: #999; font-style: italic; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="subtitle">自动生成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="summary">
    <div class="summary-item">
        <div>监控页面</div>
        <div class="num">{total_pages}</div>
    </div>
    <div class="summary-item">
        <div>异常数量</div>
        <div class="num {"red" if total_alerts > 0 else ""}">{total_alerts}</div>
    </div>
    <div class="summary-item">
        <div>监测客户</div>
        <div class="num">{len(data)}</div>
    </div>
</div>

<h2>一、检测明细</h2>
{"<p class='no-data'>无数据</p>" if not rows_html else f'''
<table>
    <tr><th>客户</th><th>站点</th><th>页面</th><th>最后状态</th><th>今日检测次数</th></tr>
    {rows_html}
</table>
'''}

<h2>二、异常详情</h2>
{"<p class='no-data'>今日未发现异常</p>" if not alerts_html else f'''
<table>
    <tr><th>客户</th><th>站点</th><th>页面</th><th>异常类型</th><th>发现时间</th></tr>
    {alerts_html}
</table>
'''}

<h2>三、基线变更记录</h2>
{"<p class='no-data'>今日无基线变更</p>" if not baseline_html else f'''
<table>
    <tr><th>客户</th><th>站点</th><th>页面</th><th>操作</th><th>原因</th><th>时间</th></tr>
    {baseline_html}
</table>
'''}

<p class="footer">网站安全监测系统 - 自动生成报告</p>
</body>
</html>'''


def _cleanup_old_reports():
    config = load_config()
    retention = config.get('report_retention_days', 90)
    cutoff = datetime.now().timestamp() - retention * 86400
    for f in os.listdir(REPORT_DIR):
        if f.endswith('.html'):
            fp = os.path.join(REPORT_DIR, f)
            if os.path.getmtime(fp) < cutoff:
                try:
                    os.remove(fp)
                except:
                    pass
