import os
import json
import base64
import html
from datetime import datetime
from config import REPORT_DIR, load_config
from models import get_db

# 证据图片嵌入上限（字节），超过则不嵌入，避免报告文件过大
_EMBED_IMG_MAX = 1024 * 1024

STATUS_LABELS = {
    'normal': '正常',
    'tampered': '疑似篡改',
    'malware': '疑似挂马',
    'unreachable': '无法访问',
    'timeout': '超时',
    'connection_error': '连接失败',
    'http_error': 'HTTP错误',
    'error': '检测异常',
    'info': '仅记录',
}

STATUS_BADGE = {
    'normal': 'ok',
    'info': 'muted',
    'tampered': 'bad',
    'malware': 'bad',
    'unreachable': 'warn',
    'timeout': 'warn',
    'connection_error': 'warn',
    'http_error': 'warn',
    'error': 'warn',
}

REVIEW_LABELS = {
    'confirmed_threat': '确认威胁',
    'false_positive': '误报',
    'baseline_updated': '确认安全 · 已更新基线',
}

REVIEW_BADGE = {
    'confirmed_threat': 'bad',
    'false_positive': 'muted',
    'baseline_updated': 'info',
}

CHANGE_CATEGORY = {
    'script': '脚本',
    'iframe': 'iframe',
    'title': '标题',
    'content': '内容',
    'structure': '结构',
    'link': '外部资源',
    'keyword': '关键词',
}


def _esc(s):
    return html.escape(str(s)) if s is not None else ''


def _badge(text, kind='muted'):
    return f'<span class="badge badge-{kind}">{_esc(text)}</span>'


def _status_badge(status):
    return _badge(STATUS_LABELS.get(status, status or '未知'), STATUS_BADGE.get(status, 'muted'))


def _embed_image(path):
    """把证据图片以 base64 嵌入报告，保证报告单文件可转发、可打印。"""
    if not path or not os.path.exists(path):
        return None
    try:
        if os.path.getsize(path) > _EMBED_IMG_MAX:
            return None
        with open(path, 'rb') as f:
            return 'data:image/png;base64,' + base64.b64encode(f.read()).decode('ascii')
    except OSError:
        return None


def _get_data_for_report(customer_id=None, date=None):
    db = get_db()

    if not date:
        date = datetime.now().strftime('%Y-%m-%d')

    if customer_id:
        customers = db.execute('SELECT * FROM customers WHERE id=?', (customer_id,)).fetchall()
    else:
        customers = db.execute('SELECT * FROM customers').fetchall()

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
                    "SELECT * FROM detection_results WHERE page_id=? AND date(detected_at)=? "
                    "AND status NOT IN ('normal', 'info') AND is_retry=0 ORDER BY detected_at ASC",
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

                alert_list = []
                for a in alerts:
                    ad = dict(a)
                    try:
                        ad['dom_changes_list'] = json.loads(ad['dom_changes']) if ad.get('dom_changes') else []
                    except (json.JSONDecodeError, TypeError):
                        ad['dom_changes_list'] = []
                    alert_list.append(ad)

                page_data.append({
                    'page': dict(page),
                    'detection_count': len(detections),
                    'alerts': alert_list,
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
    html_text = _render_report_html(data, date)

    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f'report_{date}.html'
    path = os.path.join(REPORT_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html_text)

    _cleanup_old_reports()
    return path


def generate_report_for_customer(customer_id, date=None):
    if not date:
        date = datetime.now().strftime('%Y-%m-%d')

    data = _get_data_for_report(customer_id=customer_id, date=date)

    customer_name = data[0]['customer']['name'] if data else 'unknown'
    html_text = _render_report_html(data, date, customer_name)

    os.makedirs(REPORT_DIR, exist_ok=True)
    safe_name = customer_name.replace('/', '_').replace('\\', '_')[:30]
    filename = f'report_{safe_name}_{date}.html'
    path = os.path.join(REPORT_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html_text)

    _cleanup_old_reports()
    return path


def _iter_pages(data):
    for cust_data in data:
        for site_data in cust_data['sites']:
            for page_data in site_data['pages']:
                yield cust_data, site_data, page_data


def _render_overview_table(data):
    rows = []
    for cust_data, site_data, page_data in _iter_pages(data):
        p = page_data['page']
        ls = page_data.get('last_status')
        status = _status_badge(ls['status']) if ls else _badge('未检测', 'muted')
        rows.append(f'''
                <tr>
                    <td>{_esc(cust_data['customer']['name'])}</td>
                    <td>{_esc(site_data['site']['name'])}</td>
                    <td><a href="{_esc(p['url'])}" target="_blank">{_esc(p['name'])}</a>
                        <div class="cell-sub">{_esc(p['url'])}</div></td>
                    <td>{status}</td>
                    <td class="num-cell">{page_data['detection_count']}</td>
                </tr>''')
    if not rows:
        return '<div class="empty-box">当日无检测数据</div>'
    return f'''
<table>
    <thead><tr><th>客户</th><th>站点</th><th>页面</th><th>最新状态</th><th style="width:90px;">检测次数</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
</table>'''


def _render_review_stats(alerts):
    n_threat = sum(1 for a in alerts if a.get('review_result') == 'confirmed_threat')
    n_false = sum(1 for a in alerts if a.get('review_result') == 'false_positive')
    n_baseline = sum(1 for a in alerts if a.get('review_result') == 'baseline_updated')
    n_pending = sum(1 for a in alerts if not a.get('reviewed'))
    return f'''
    <div class="mini-stats">
        <div class="mini-stat">
            <div class="mini-num">{len(alerts)}</div>
            <div class="mini-label">告警总数</div>
        </div>
        <div class="mini-stat">
            <div class="mini-num text-bad">{n_threat}</div>
            <div class="mini-label">确认威胁</div>
        </div>
        <div class="mini-stat">
            <div class="mini-num">{n_false}</div>
            <div class="mini-label">确认误报</div>
        </div>
        <div class="mini-stat">
            <div class="mini-num text-info">{n_baseline}</div>
            <div class="mini-label">已更新基线</div>
        </div>
        <div class="mini-stat">
            <div class="mini-num {"text-warn" if n_pending else ""}">{n_pending}</div>
            <div class="mini-label">待审核</div>
        </div>
    </div>'''


def _render_dom_changes(changes):
    items = []
    for c in changes:
        cat = CHANGE_CATEGORY.get(c.get('category'), c.get('category', '-'))
        sev = c.get('severity', '')
        sev_kind = 'bad' if sev == 'malware' else ('warn' if sev == 'tamper' else 'info')
        items.append(f'''
                    <li>
                        <span class="change-cat">{_esc(cat)}</span>
                        {_badge(c.get('type', '-'), sev_kind)}
                        <span class="change-detail">{_esc(c.get('detail', ''))}</span>
                    </li>''')
    if not items:
        return ''
    return f'''
                <div class="block-label">页面变更明细</div>
                <ul class="change-list">{''.join(items)}</ul>'''


def _render_review_block(alert):
    if not alert.get('reviewed'):
        return '''
                <div class="review-block pending">
                    <div class="review-head">
                        <span class="badge badge-warn">待审核</span>
                        <span class="review-tip">该告警尚未进行人工审核，请登录系统「告警管理 → 差异对比」完成判定。</span>
                    </div>
                </div>'''

    result = alert.get('review_result', '')
    label = REVIEW_LABELS.get(result, result or '已审核')
    kind = REVIEW_BADGE.get(result, 'muted')
    comment = (alert.get('review_comment') or '').strip()
    reviewed_at = (alert.get('reviewed_at') or '-')[:19]

    comment_html = (
        f'<div class="review-comment">{_esc(comment)}</div>'
        if comment else '<div class="review-comment empty">（未填写审核批注）</div>'
    )
    return f'''
                <div class="review-block">
                    <div class="review-head">
                        <span class="review-title">审核记录</span>
                        {_badge(label, kind)}
                        <span class="review-time">审核时间：{_esc(reviewed_at)}</span>
                    </div>
                    <div class="block-label">审核批注</div>
                    {comment_html}
                </div>'''


def _render_alert_card(cust_data, site_data, page_data, alert, idx):
    p = page_data['page']
    info_items = [
        ('客户单位', _esc(cust_data['customer']['name'])),
        ('所属站点', _esc(site_data['site']['name'])),
        ('页面地址', f'<a href="{_esc(p["url"])}" target="_blank">{_esc(p["url"])}</a>'),
        ('HTTP 状态', _esc(alert.get('response_status')) if alert.get('response_status') else '-'),
        ('响应时间', f"{alert['response_time']:.1f} s" if alert.get('response_time') is not None else '-'),
        ('截图差异度', f"{alert['screenshot_diff_percent']:.2f}%" if alert.get('screenshot_diff_percent') is not None else '-'),
    ]
    info_html = ''.join(
        f'<div class="info-item"><div class="info-label">{k}</div><div class="info-value">{v}</div></div>'
        for k, v in info_items
    )

    error_html = ''
    if alert.get('error_message'):
        error_html = f'''
                <div class="block-label">错误信息</div>
                <div class="error-box">{_esc(alert['error_message'])}</div>'''

    changes_html = _render_dom_changes(alert.get('dom_changes_list') or [])
    review_html = _render_review_block(alert)

    img_data = _embed_image(alert.get('diff_image_path')) or _embed_image(alert.get('screenshot_path'))
    img_html = ''
    if img_data:
        img_caption = '页面差异证据截图' if alert.get('diff_image_path') else '告警时页面截图'
        img_html = f'''
                <div class="block-label">证据截图</div>
                <div class="evidence-box">
                    <img src="{img_data}" alt="{img_caption}">
                    <div class="evidence-caption">{img_caption}（{_esc((alert.get('detected_at') or '')[:19])}）</div>
                </div>'''

    return f'''
        <div class="alert-card">
            <div class="alert-card-head">
                <span class="alert-idx">#{idx}</span>
                {_status_badge(alert.get('status'))}
                <span class="alert-title">{_esc(site_data['site']['name'])} / {_esc(p['name'])}</span>
                <span class="alert-time">发现于 {_esc((alert.get('detected_at') or '-')[:19])}</span>
            </div>
            <div class="alert-card-body">
                <div class="info-grid">{info_html}</div>
                {error_html}
                {changes_html}
                {review_html}
                {img_html}
            </div>
        </div>'''


def _render_baseline_table(data):
    rows = []
    for cust_data, site_data, page_data in _iter_pages(data):
        for bu in page_data['baseline_updates']:
            action = '新建基线' if bu['action'] == 'create' else '更新基线'
            rows.append(f'''
                <tr>
                    <td>{_esc(cust_data['customer']['name'])}</td>
                    <td>{_esc(site_data['site']['name'])}</td>
                    <td>{_esc(page_data['page']['name'])}</td>
                    <td>{_badge(action, 'info')}</td>
                    <td>{_esc(bu.get('reason') or '-')}</td>
                    <td class="num-cell">{_esc((bu.get('created_at') or '-')[:16])}</td>
                </tr>''')
    if not rows:
        return '<div class="empty-box">当日无基线变更</div>'
    return f'''
<table>
    <thead><tr><th>客户</th><th>站点</th><th>页面</th><th>操作</th><th>原因</th><th style="width:130px;">时间</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
</table>'''


def _render_report_html(data, date, title_extra=None):
    title = f'网页篡改与可用性监测日报'
    scope = title_extra if title_extra else '全部客户'

    total_customers = len(data)
    total_sites = sum(len(c['sites']) for c in data)
    total_pages = sum(c['page_count'] for c in data)
    total_alerts = sum(c['alert_count'] for c in data)
    total_detections = sum(
        page_data['detection_count'] for _c, _s, page_data in _iter_pages(data)
    )
    pending_reviews = sum(
        1 for _c, _s, page_data in _iter_pages(data)
        for a in page_data['alerts'] if not a.get('reviewed')
    )

    gen_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    all_alerts = [a for _c, _s, pd in _iter_pages(data) for a in pd['alerts']]
    overview_html = _render_overview_table(data)
    review_stats_html = _render_review_stats(all_alerts)
    alert_details_html = _render_alert_details(data)
    baseline_html = _render_baseline_table(data)

    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)} - {_esc(scope)} - {_esc(date)}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, "PingFang SC", "Microsoft YaHei", "Segoe UI", sans-serif;
        background: #f1f5f9; color: #1e293b; font-size: 13px; line-height: 1.6;
        -webkit-font-smoothing: antialiased;
    }}
    a {{ color: #4f6df5; text-decoration: none; word-break: break-all; }}
    .page {{ max-width: 960px; margin: 0 auto; padding: 24px 20px 48px; }}

    /* ===== 报告头 ===== */
    .report-banner {{
        background: linear-gradient(135deg, #101a33 0%, #1c2c52 100%);
        border-radius: 14px; padding: 28px 32px; color: #fff;
        display: flex; align-items: center; gap: 18px;
        box-shadow: 0 8px 24px rgba(16,26,51,.25);
    }}
    .banner-logo {{
        width: 52px; height: 52px; border-radius: 13px; flex-shrink: 0;
        background: linear-gradient(135deg, #4f6df5, #7c9bff);
        display: flex; align-items: center; justify-content: center;
        box-shadow: 0 4px 14px rgba(79,109,245,.5);
    }}
    .banner-logo svg {{ width: 28px; height: 28px; stroke: #fff; }}
    .banner-title {{ font-size: 22px; font-weight: 700; letter-spacing: .5px; }}
    .banner-sub {{ font-size: 12.5px; color: #a8b4d4; margin-top: 4px; }}
    .banner-meta {{ margin-left: auto; text-align: right; font-size: 12px; color: #a8b4d4; line-height: 1.9; flex-shrink: 0; }}
    .banner-meta strong {{ color: #fff; font-weight: 600; }}

    /* ===== 统计卡 ===== */
    .stat-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-top: 16px; }}
    .stat-card {{
        background: #fff; border: 1px solid #e3e8f0; border-radius: 10px;
        padding: 14px 16px; box-shadow: 0 1px 2px rgba(15,23,42,.05);
    }}
    .stat-num {{ font-size: 24px; font-weight: 700; line-height: 1.15; font-variant-numeric: tabular-nums; }}
    .stat-num.text-bad {{ color: #ef4444; }}
    .stat-num.text-warn {{ color: #f59e0b; }}
    .stat-label {{ font-size: 12px; color: #64748b; margin-top: 2px; }}

    /* ===== 章节 ===== */
    .section {{ margin-top: 26px; }}
    .section-head {{
        display: flex; align-items: baseline; gap: 10px;
        border-bottom: 2px solid #4f6df5; padding-bottom: 8px; margin-bottom: 14px;
    }}
    .section-title {{ font-size: 16px; font-weight: 700; color: #1e293b; }}
    .section-note {{ font-size: 12px; color: #94a3b8; }}

    /* ===== 表格 ===== */
    table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 2px rgba(15,23,42,.05); }}
    th {{
        padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600;
        color: #64748b; background: #f8fafc; border-bottom: 1px solid #e3e8f0; white-space: nowrap;
    }}
    td {{ padding: 10px 14px; border-bottom: 1px solid #f1f5f9; font-size: 12.5px; vertical-align: middle; }}
    tbody tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover {{ background: #f8fafc; }}
    .cell-sub {{ font-size: 11px; color: #94a3b8; word-break: break-all; }}
    .num-cell {{ font-variant-numeric: tabular-nums; }}

    /* ===== 徽章 ===== */
    .badge {{
        display: inline-flex; align-items: center; gap: 5px;
        padding: 2px 10px; border-radius: 999px; font-size: 11.5px; font-weight: 600; white-space: nowrap;
    }}
    .badge::before {{ content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }}
    .badge-ok {{ background: #ecfdf5; color: #047857; }}
    .badge-bad {{ background: #fef2f2; color: #b91c1c; }}
    .badge-warn {{ background: #fffbeb; color: #b45309; }}
    .badge-info {{ background: #eff6ff; color: #1d4ed8; }}
    .badge-muted {{ background: #f1f5f9; color: #64748b; }}

    /* ===== 处置统计 ===== */
    .mini-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 16px; }}
    .mini-stat {{
        background: #fff; border: 1px solid #e3e8f0; border-radius: 10px;
        padding: 12px 16px; display: flex; align-items: center; gap: 12px;
    }}
    .mini-num {{ font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }}
    .mini-num.text-bad {{ color: #ef4444; }}
    .mini-num.text-warn {{ color: #f59e0b; }}
    .mini-num.text-info {{ color: #3b82f6; }}
    .mini-label {{ font-size: 12px; color: #64748b; }}

    /* ===== 告警卡片 ===== */
    .alert-cards {{ display: flex; flex-direction: column; gap: 14px; }}
    .alert-card {{
        background: #fff; border: 1px solid #e3e8f0; border-radius: 12px;
        overflow: hidden; box-shadow: 0 1px 3px rgba(15,23,42,.06);
        break-inside: avoid;
    }}
    .alert-card-head {{
        display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
        padding: 12px 18px; background: #f8fafc; border-bottom: 1px solid #e3e8f0;
    }}
    .alert-idx {{ font-size: 12px; font-weight: 700; color: #94a3b8; font-variant-numeric: tabular-nums; }}
    .alert-title {{ font-size: 14px; font-weight: 600; }}
    .alert-time {{ margin-left: auto; font-size: 12px; color: #94a3b8; font-variant-numeric: tabular-nums; }}
    .alert-card-body {{ padding: 16px 18px; }}

    .info-grid {{
        display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 10px 20px; margin-bottom: 14px;
    }}
    .info-label {{ font-size: 11px; color: #94a3b8; margin-bottom: 1px; }}
    .info-value {{ font-size: 12.5px; font-weight: 500; word-break: break-all; }}

    .block-label {{
        font-size: 11.5px; font-weight: 600; color: #64748b; letter-spacing: .3px;
        margin: 14px 0 6px;
    }}
    .error-box {{
        background: #fef2f2; border: 1px solid #fecaca; color: #991b1b;
        border-radius: 8px; padding: 10px 14px; font-size: 12px;
        font-family: Consolas, "Courier New", monospace; word-break: break-all;
    }}
    .change-list {{ list-style: none; }}
    .change-list li {{
        display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
        padding: 7px 12px; border: 1px solid #f1f5f9; border-radius: 8px; margin-bottom: 6px;
        background: #fafbfd; font-size: 12.5px;
    }}
    .change-cat {{ font-weight: 600; color: #475569; flex-shrink: 0; }}
    .change-detail {{ color: #64748b; word-break: break-all; }}

    /* ===== 审核区块 ===== */
    .review-block {{
        margin-top: 14px; border: 1px solid #e3e8f0; border-left: 4px solid #4f6df5;
        border-radius: 8px; padding: 12px 16px; background: #fafbff;
    }}
    .review-block.pending {{ border-left-color: #f59e0b; background: #fffbeb; }}
    .review-head {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .review-title {{ font-size: 13px; font-weight: 700; }}
    .review-time {{ margin-left: auto; font-size: 11.5px; color: #94a3b8; font-variant-numeric: tabular-nums; }}
    .review-tip {{ font-size: 12px; color: #b45309; }}
    .review-comment {{
        background: #fff; border: 1px solid #e3e8f0; border-radius: 8px;
        padding: 10px 14px; font-size: 13px; white-space: pre-wrap; word-break: break-word;
    }}
    .review-comment.empty {{ color: #94a3b8; font-style: italic; }}

    /* ===== 证据截图 ===== */
    .evidence-box {{ border: 1px solid #e3e8f0; border-radius: 10px; overflow: hidden; background: #fff; }}
    .evidence-box img {{ display: block; width: 100%; max-height: 520px; object-fit: contain; background: #f8fafc; }}
    .evidence-caption {{
        padding: 8px 14px; font-size: 11.5px; color: #94a3b8;
        border-top: 1px solid #f1f5f9; text-align: center;
    }}

    /* ===== 空状态 / 页脚 ===== */
    .empty-box {{
        background: #fff; border: 1px dashed #cbd5e1; border-radius: 10px;
        padding: 28px; text-align: center; color: #94a3b8; font-size: 13px;
    }}
    .empty-box.success {{ color: #047857; border-color: #a7f3d0; background: #ecfdf5; }}
    .empty-box.success svg {{ width: 30px; height: 30px; display: block; margin: 0 auto 8px; }}
    .report-footer {{
        margin-top: 36px; padding-top: 14px; border-top: 1px solid #e3e8f0;
        text-align: center; color: #94a3b8; font-size: 11.5px; line-height: 1.9;
    }}

    @media print {{
        body {{ background: #fff; }}
        .page {{ max-width: none; padding: 0; }}
        .report-banner {{ box-shadow: none; }}
        .stat-card, .mini-stat, table, .alert-card {{ box-shadow: none; }}
        .alert-card {{ break-inside: avoid; }}
        a {{ color: #1e293b; }}
    }}
</style>
</head>
<body>
<div class="page">

    <div class="report-banner">
        <div class="banner-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
        </div>
        <div>
            <div class="banner-title">{_esc(title)}</div>
            <div class="banner-sub">Web Page Tampering &amp; Availability Monitoring Daily Report</div>
        </div>
        <div class="banner-meta">
            <div>监测范围：<strong>{_esc(scope)}</strong></div>
            <div>报告日期：<strong>{_esc(date)}</strong></div>
            <div>生成时间：{_esc(gen_time)}</div>
        </div>
    </div>

    <div class="stat-row">
        <div class="stat-card"><div class="stat-num">{total_customers}</div><div class="stat-label">监测客户</div></div>
        <div class="stat-card"><div class="stat-num">{total_sites}</div><div class="stat-label">监测站点</div></div>
        <div class="stat-card"><div class="stat-num">{total_pages}</div><div class="stat-label">监测页面</div></div>
        <div class="stat-card"><div class="stat-num">{total_detections}</div><div class="stat-label">当日检测次数</div></div>
        <div class="stat-card"><div class="stat-num {"text-bad" if total_alerts else ""}">{total_alerts}</div><div class="stat-label">安全告警</div></div>
        <div class="stat-card"><div class="stat-num {"text-warn" if pending_reviews else ""}">{pending_reviews}</div><div class="stat-label">待审核</div></div>
    </div>

    <div class="section">
        <div class="section-head">
            <span class="section-title">一、监控运行概况</span>
            <span class="section-note">各监测页面当日运行情况</span>
        </div>
        {overview_html}
    </div>

    <div class="section">
        <div class="section-head">
            <span class="section-title">二、告警处置统计</span>
            <span class="section-note">当日告警的人工审核处置汇总</span>
        </div>
        {review_stats_html}
    </div>

    <div class="section">
        <div class="section-head">
            <span class="section-title">三、告警与审核详情</span>
            <span class="section-note">含变更明细、证据截图与人工审核记录</span>
        </div>
        {alert_details_html}
    </div>

    <div class="section">
        <div class="section-head">
            <span class="section-title">四、基线变更记录</span>
            <span class="section-note">当日页面基线的新建与更新</span>
        </div>
        {baseline_html}
    </div>

    <div class="report-footer">
        网页篡改与可用性监测系统 · 本报告由系统自动生成<br>
        报告内容含人工审核结论，仅供内部安全工作参考
    </div>

</div>
</body>
</html>'''


def _render_alert_details(data):
    alerts_with_ctx = []
    for cust_data, site_data, page_data in _iter_pages(data):
        for alert in page_data['alerts']:
            alerts_with_ctx.append((cust_data, site_data, page_data, alert))

    if not alerts_with_ctx:
        return '''
        <div class="empty-box success">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
            当日未发现安全异常
        </div>'''

    cards = ''.join(
        _render_alert_card(c, s, p, a, i)
        for i, (c, s, p, a) in enumerate(alerts_with_ctx, 1)
    )
    return f'<div class="alert-cards">{cards}</div>'


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
                except OSError:
                    pass
