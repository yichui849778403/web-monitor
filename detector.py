import os
import re
import time
import hashlib
import json
import logging
from datetime import datetime
from bs4 import BeautifulSoup
from PIL import Image, ImageChops, ImageDraw
from io import BytesIO

from config import load_config, BASELINE_DIR, SCREENSHOT_DIR
from models import Baseline, DetectionResult, CustomKeyword, Page
from webdriver_setup import take_screenshot, fetch_rendered

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
TIMESTAMP_MS_RE = re.compile(r'\b\d{13}\b')
TIMESTAMP_SEC_RE = re.compile(r'\b\d{10}\b')
NONCE_RE = re.compile(r'nonce\s*=\s*["\'][^"\']+["\']', re.IGNORECASE)
# 日期时间文本：2026-07-28 / 2026/07/28 / 08:34:55 / 08:34
# 用数字环视代替 \b（中文字符与数字之间没有 \b 边界）
DATE_RE = re.compile(r'(?<!\d)\d{4}[-/年]\d{1,2}[-/月]\d{1,2}日?(?!\d)')
TIME_RE = re.compile(r'(?<!\d)\d{1,2}:\d{2}(:\d{2})?(?!\d)')
# 文件名中的构建 hash：chunk-f2820e3c.js / app.486a48a6.css / main_b8d5b9dc
FILE_HASH_RE = re.compile(r'([\-._])[0-9a-f]{8,}(?=[.\s"\']|$)', re.IGNORECASE)
# URL 查询串中的时间戳/随机参数：?_t= / &t= / &v= / &timestamp= / &r=
QUERY_TS_RE = re.compile(r'([?&](?:_?t|v|ts|timestamp|rand|r|_)=)[^&"\'\s]*', re.IGNORECASE)
# style 属性内的动态数值：translate3d(-6px, 0px, 0px) / width: 123.5px / left: 50%
STYLE_NUM_RE = re.compile(r'-?\d+\.?\d*(px|%|em|rem|vh|vw|vmin|vmax|s|ms|deg|fr)?')


def _normalize_style_attr(match):
    """style="..." 内的数值全部归一化，消灭 translate/宽高抖动。"""
    return 'style="' + STYLE_NUM_RE.sub('N', match.group(1)) + '"'


def _normalize_html(html):
    """归一化动态值，让"骨架相同"的页面指纹稳定。

    覆盖：UUID、nonce、时间戳(10/13位)、日期时间文本、文件名构建 hash、
    URL 时间戳参数、style 属性内的全部数值。
    """
    html = UUID_RE.sub('[UUID]', html)
    html = NONCE_RE.sub('nonce="[NONCE]"', html)
    html = TIMESTAMP_MS_RE.sub('[TS]', html)
    html = TIMESTAMP_SEC_RE.sub('[TS]', html)
    html = DATE_RE.sub('[DATE]', html)
    html = TIME_RE.sub('[TIME]', html)
    html = FILE_HASH_RE.sub(r'\1[H]', html)
    html = QUERY_TS_RE.sub(r'\1[V]', html)
    html = re.sub(r'style\s*=\s*"([^"]*)"', _normalize_style_attr, html)
    html = re.sub(r"style\s*=\s*'([^']*)'", _normalize_style_attr, html)
    return html


def load_webdriver():
    from webdriver_setup import get_driver
    return get_driver()


def scan_keywords(text):
    keywords = CustomKeyword.get_all_keywords()
    found = []
    text_lower = text.lower()
    for kw in keywords:
        if kw.lower() in text_lower:
            found.append(kw)
    return found




ID_NUM_RE = re.compile(r'\d{4,}')


def _skeleton_fingerprint(body):
    """结构指纹：body 后代元素的 tag#id 前序序列。

    只保留标签名和 id（id 中 4+ 位连续数字归一化），不含 class/style/
    data-*/文本——这些"表皮"抖动交给 text_hash 和专项对比，骨架变化
    （节点增删、标签替换、层级移动）才判定为结构变化。
    """
    parts = []
    for el in body.descendants:
        if not getattr(el, 'name', None):
            continue
        eid = el.get('id', '')
        if eid:
            eid = ID_NUM_RE.sub('N', eid)
            parts.append('%s#%s' % (el.name, eid))
        else:
            parts.append(el.name)
    return hashlib.md5('>'.join(parts).encode()).hexdigest()


def extract_dom_fingerprint(html, ignore_selectors=''):
    soup = BeautifulSoup(html, 'lxml')

    # 忽略区域：对比前直接剔除（地图/轮播/实时数据等天然动态区块）
    if ignore_selectors:
        for sel in [s.strip() for s in ignore_selectors.splitlines() if s.strip()]:
            try:
                for el in soup.select(sel):
                    el.decompose()
            except Exception:
                logging.getLogger('detector').warning(f'无效忽略选择器已跳过: {sel}')

    title = soup.title.string.strip() if soup.title and soup.title.string else ''

    scripts = []
    for s in soup.find_all('script'):
        src = s.get('src', '')
        if src:
            scripts.append({'src': _normalize_html(src), 'type': 'external'})
        else:
            content = s.string or ''
            content = _normalize_html(content)
            h = hashlib.md5(content.strip().encode()).hexdigest()
            scripts.append({'src': '', 'type': 'inline', 'hash': h})

    iframes = []
    for f in soup.find_all('iframe'):
        iframes.append({
            'src': _normalize_html(f.get('src', '')),
            'width': f.get('width', ''),
            'height': f.get('height', ''),
        })

    links = []
    for l in soup.find_all('link', rel='stylesheet'):
        links.append(_normalize_html(l.get('href', '')))

    meta_tags = []
    for m in soup.find_all('meta'):
        meta_tags.append({
            'name': m.get('name', m.get('http-equiv', '')),
            'content': m.get('content', ''),
        })

    visible_text = soup.get_text(separator=' ', strip=True)
    visible_text = _normalize_html(visible_text)
    text_hash = hashlib.md5(visible_text.encode()).hexdigest()
    text_length = len(visible_text)

    body_hash = ''
    body = soup.find('body')
    if body:
        for tag in body.find_all(['script', 'style']):
            tag.decompose()
        body_hash = _skeleton_fingerprint(body)

    return {
        '_version': 3,
        'title': title,
        'title_hash': hashlib.md5(title.encode()).hexdigest(),
        'scripts': scripts,
        'iframes': iframes,
        'links': links,
        'meta_tags': meta_tags,
        'text_hash': text_hash,
        'text_length': text_length,
        'body_hash': body_hash,
    }


def detect_suspicious_dom(fp):
    issues = []
    for s in fp.get('scripts', []):
        if s['type'] == 'external':
            src = s['src']
            if src.startswith('http') or src.startswith('//'):
                issues.append({
                    'type': 'external_script',
                    'severity': 'info',
                    'detail': f'外部脚本: {src}',
                })
            if 'eval' in src.lower() or 'base64' in src.lower():
                issues.append({
                    'type': 'suspicious_script_src',
                    'severity': 'warning',
                    'detail': f'可疑脚本路径: {src}',
                })
        elif s['type'] == 'inline':
            pass

    for f in fp.get('iframes', []):
        src = f['src']
        if src and (src.startswith('http') or src.startswith('//')):
            issues.append({
                'type': 'external_iframe',
                'severity': 'warning',
                'detail': f'外部 iframe: {src}',
            })
        if not src or src == '':
            issues.append({
                'type': 'hidden_iframe',
                'severity': 'warning',
                'detail': '空的或隐藏的 iframe',
            })

    return issues


def compare_dom(baseline_fp, current_fp, domain):
    changes = []

    if baseline_fp.get('title_hash') != current_fp.get('title_hash'):
        changes.append({
            'category': 'title',
            'type': 'modified',
            'severity': 'tamper',
            'old_value': baseline_fp.get('title', ''),
            'new_value': current_fp.get('title', ''),
            'detail': f'页面标题变更: "{baseline_fp.get("title", "")}" → "{current_fp.get("title", "")}"',
        })

    baseline_scripts_ext = {s['src'] for s in baseline_fp.get('scripts', []) if s['type'] == 'external'}
    current_scripts_ext = {s['src'] for s in current_fp.get('scripts', []) if s['type'] == 'external'}

    new_scripts = current_scripts_ext - baseline_scripts_ext
    removed_scripts = baseline_scripts_ext - current_scripts_ext

    for src in new_scripts:
        is_external_domain = True
        try:
            from urllib.parse import urlparse
            parsed = urlparse(src) if src.startswith('http') else urlparse('http://' + src.lstrip('/'))
            parsed_domain = urlparse(domain) if domain.startswith('http') else urlparse('http://' + domain)
            if parsed.netloc == parsed_domain.netloc or parsed.netloc.endswith('.' + parsed_domain.netloc):
                is_external_domain = False
        except:
            pass

        severity = 'malware' if is_external_domain else 'tamper'
        changes.append({
            'category': 'script',
            'type': 'added',
            'severity': severity,
            'value': src,
            'detail': f'新增外部脚本: {src}' + (' [本站域名]' if not is_external_domain else ' [外部域名]'),
        })

    for src in removed_scripts:
        changes.append({
            'category': 'script',
            'type': 'removed',
            'severity': 'tamper',
            'value': src,
            'detail': f'移除外部脚本: {src}',
        })

    baseline_scripts_inline = {s['hash'] for s in baseline_fp.get('scripts', []) if s['type'] == 'inline'}
    current_scripts_inline = {s['hash'] for s in current_fp.get('scripts', []) if s['type'] == 'inline'}
    if baseline_scripts_inline != current_scripts_inline:
        new_inline = current_scripts_inline - baseline_scripts_inline
        if new_inline:
            changes.append({
                'category': 'script',
                'type': 'inline_modified',
                'severity': 'malware',
                'value': f'{len(new_inline)} 个内联脚本变化',
                'detail': f'新增/修改 {len(new_inline)} 个内联脚本',
            })

    baseline_iframes = {(f['src'], f.get('width', ''), f.get('height', '')) for f in baseline_fp.get('iframes', [])}
    current_iframes = {(f['src'], f.get('width', ''), f.get('height', '')) for f in current_fp.get('iframes', [])}

    new_iframes = current_iframes - baseline_iframes
    removed_iframes = baseline_iframes - current_iframes

    for src, w, h in new_iframes:
        changes.append({
            'category': 'iframe',
            'type': 'added',
            'severity': 'malware',
            'value': src,
            'detail': f'新增 iframe: {src} ({w}x{h})',
        })

    for src, w, h in removed_iframes:
        changes.append({
            'category': 'iframe',
            'type': 'removed',
            'severity': 'tamper',
            'value': src,
            'detail': f'移除 iframe: {src}',
        })

    if baseline_fp.get('text_hash') != current_fp.get('text_hash'):
        text_diff_pct = abs(baseline_fp.get('text_length', 0) - current_fp.get('text_length', 0)) / max(baseline_fp.get('text_length', 1), 1) * 100
        changes.append({
            'category': 'content',
            'type': 'text_changed',
            'severity': 'tamper' if text_diff_pct > 5 else 'info',
            'value': f'文本长度变化 {text_diff_pct:.1f}%',
            'detail': f'页面文本内容发生变化 (长度: {baseline_fp.get("text_length", 0)} → {current_fp.get("text_length", 0)}, 差异: {text_diff_pct:.1f}%)',
        })

    if baseline_fp.get('body_hash') != current_fp.get('body_hash'):
        changes.append({
            'category': 'structure',
            'type': 'body_changed',
            'severity': 'tamper',
            'value': '',
            'detail': '页面 DOM 骨架发生变化（节点增删/标签替换/层级变动）',
        })

    return changes


def compare_screenshots(baseline_path, current_path, diff_output_path, threshold=5.0):
    if not os.path.exists(baseline_path) or not os.path.exists(current_path):
        return 100.0, None

    try:
        img1 = Image.open(baseline_path).convert('RGB')
        img2 = Image.open(current_path).convert('RGB')

        w1, h1 = img1.size
        w2, h2 = img2.size
        w = max(w1, w2)
        h = max(h1, h2)

        if img1.size != (w, h):
            bg = Image.new('RGB', (w, h), (255, 255, 255))
            bg.paste(img1, (0, 0))
            img1 = bg
        if img2.size != (w, h):
            bg = Image.new('RGB', (w, h), (255, 255, 255))
            bg.paste(img2, (0, 0))
            img2 = bg

        diff = ImageChops.difference(img1, img2)

        total_pixels = w * h
        if total_pixels == 0:
            return 0, None

        diff_pixels = 0
        diff_data = diff.getdata()
        for p in diff_data:
            if p[0] > 30 or p[1] > 30 or p[2] > 30:
                diff_pixels += 1

        diff_percent = (diff_pixels / total_pixels) * 100

        if diff_percent >= threshold and diff_output_path:
            overlay = img2.copy()
            d = ImageDraw.Draw(overlay)
            for y in range(0, h, 4):
                for x in range(0, w, 4):
                    p = diff.getpixel((x, y))
                    if p[0] > 30 or p[1] > 30 or p[2] > 30:
                        d.rectangle([x, y, x+4, y+4], fill=None, outline=(255, 0, 0), width=1)

            os.makedirs(os.path.dirname(diff_output_path), exist_ok=True)
            overlay.save(diff_output_path, 'PNG')

        return round(diff_percent, 2), diff_output_path if diff_percent >= threshold else None
    except Exception as e:
        return -1, None


def evaluate_rules(dom_changes, screenshot_diff_pct, suspicious_items):
    has_malware = False
    has_tamper = False
    has_screenshot_only = False

    for c in dom_changes:
        if c['severity'] == 'malware':
            has_malware = True
        elif c['severity'] == 'tamper':
            has_tamper = True

    if screenshot_diff_pct is not None and screenshot_diff_pct >= 5.0:
        if not has_tamper and not has_malware:
            has_screenshot_only = True
        else:
            has_tamper = True

    for item in suspicious_items:
        if item['severity'] in ('warning', 'critical'):
            has_malware = True

    if has_malware:
        return 'malware'
    elif has_tamper:
        return 'tampered'
    elif has_screenshot_only:
        return 'info'
    else:
        return 'normal'


def run_detection(page_id, url, domain):
    config = load_config()
    result = {
        'status': 'error',
        'dom_changes': None,
        'screenshot_diff_percent': None,
        'screenshot_path': None,
        'html_path': None,
        'diff_image_path': None,
        'response_status': None,
        'response_time': None,
        'error_message': None,
    }

    baseline = Baseline.get_latest(page_id)
    if not baseline:
        result['status'] = 'no_baseline'
        result['error_message'] = '该页面尚未建立基线'
        return result

    try:
        start = time.time()
        p = Page.get_by_id(page_id)
        render_wait = p['render_wait'] if p else 5
        ignore_sels = ''
        if p and 'ignore_selectors' in p.keys():
            ignore_sels = p['ignore_selectors'] or ''

        html = fetch_rendered(url, wait_seconds=render_wait)
        if not html:
            result['status'] = 'error'
            result['error_message'] = '浏览器渲染失败，获取页面内容为空'
            return result
        result['response_status'] = 200
        result['response_time'] = round(time.time() - start, 2)

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_dir = os.path.join(SCREENSHOT_DIR, str(page_id))
        os.makedirs(html_dir, exist_ok=True)
        html_path = os.path.join(html_dir, f'{ts}_page.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        result['html_path'] = html_path

        current_fp = extract_dom_fingerprint(html, ignore_sels)
        baseline_fp = json.loads(baseline['dom_fingerprint'])

        if baseline_fp.get('_version', 1) < 3:
            # 旧版本指纹（v1/v2 全量 MD5）：从基线 HTML 重算 v3 结构指纹
            if baseline['html_path'] and os.path.exists(baseline['html_path']):
                with open(baseline['html_path'], 'r', encoding='utf-8') as f:
                    baseline_fp = extract_dom_fingerprint(f.read(), ignore_sels)
                    logging.getLogger('detector').info(f'Upgraded baseline fingerprint for page {page_id} to v3')

        dom_changes = compare_dom(baseline_fp, current_fp, domain)
        result['dom_changes'] = dom_changes

        suspicious_items = detect_suspicious_dom(current_fp)

        found_keywords = scan_keywords(html)
        if found_keywords:
            if dom_changes is None:
                dom_changes = []
            dom_changes.append({
                'category': 'keyword',
                'type': 'found',
                'severity': 'malware',
                'value': ', '.join(found_keywords),
                'detail': f'发现敏感关键词: {", ".join(found_keywords)}',
            })
            result['dom_changes'] = dom_changes

        screenshot_wait = max(render_wait, 2)
        screenshot_path = take_screenshot(url, page_id, ts, wait_seconds=screenshot_wait)
        if screenshot_path:
            result['screenshot_path'] = screenshot_path

            baseline_screenshot = baseline['screenshot_path']
            if baseline_screenshot and os.path.exists(baseline_screenshot):
                diff_dir = os.path.join(SCREENSHOT_DIR, str(page_id), 'diff')
                os.makedirs(diff_dir, exist_ok=True)
                diff_path = os.path.join(diff_dir, f'{ts}_diff.png')
                diff_pct, diff_file = compare_screenshots(
                    baseline_screenshot, screenshot_path, diff_path,
                    config['screenshot_diff_threshold']
                )
                result['screenshot_diff_percent'] = diff_pct
                if diff_file:
                    result['diff_image_path'] = diff_file

        status = evaluate_rules(
            dom_changes,
            result['screenshot_diff_percent'],
            suspicious_items
        )
        result['status'] = status

    except Exception as e:
        result['status'] = 'error'
        result['error_message'] = f'检测异常: {str(e)[:300]}'
        result['response_status'] = 0

    return result


def create_baseline_for_page(page_id, url, reason=''):
    page = Page.get_by_id(page_id)
    render_wait = page['render_wait'] if page else 5
    ignore_sels = ''
    if page and 'ignore_selectors' in page.keys():
        ignore_sels = page['ignore_selectors'] or ''
    try:
        html = fetch_rendered(url, wait_seconds=render_wait)
        if not html:
            return None, '浏览器渲染失败，获取页面内容为空'

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        bl_dir = os.path.join(BASELINE_DIR, str(page_id))
        os.makedirs(bl_dir, exist_ok=True)
        html_path = os.path.join(bl_dir, f'{ts}_baseline.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)

        screenshot_path = take_screenshot(url, page_id, f'{ts}_baseline')
        if screenshot_path and not screenshot_path.startswith(BASELINE_DIR):
            new_path = os.path.join(bl_dir, os.path.basename(screenshot_path))
            import shutil
            shutil.copy2(screenshot_path, new_path)
            screenshot_path = new_path

        fp = extract_dom_fingerprint(html, ignore_sels)

        bid = Baseline.create(page_id, screenshot_path, html_path, fp, reason)
        return bid, None
    except Exception as e:
        return None, str(e)[:300]
