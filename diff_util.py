# -*- coding: utf-8 -*-
"""
源码对比渲染器。

问题背景：页面 HTML 是 Selenium 导出的单行无格式化 DOM（几十 KB 挤一行），
直接用 difflib.HtmlDiff 会做整行字符级比对（O(n^2)，几十秒），
且输出全量未折叠的表格，可读性极差。

本模块做法（与 git diff 一致）：
1. 先把 HTML 重新格式化（标签/属性/文本换行缩进），把"一行 100KB"拆成几千个短行；
2. 行级 SequenceMatcher 对齐（格式化后每行 < ~130 字符，速度快）；
3. 变更行对做行内词级高亮（此时行很短，字符级比对开销可忽略）；
4. 未变更区域折叠，只保留上下文。
"""

import difflib
import html as _html
from html.parser import HTMLParser

# ---------------------------------------------------------------------------
# HTML 格式化
# ---------------------------------------------------------------------------

VOID_TAGS = {
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
    'link', 'meta', 'param', 'source', 'track', 'wbr',
}
RAW_TEXT_TAGS = {'script', 'style'}
MAX_LINE = 110          # 超过该长度尝试拆分
MAX_ATTRS_INLINE = 3    # 属性不超过此数量才保持同行


def _split_attrs(tag_text):
    """把 '<tag a="1" b="2">' 拆成 ('<tag', ['a="1"', 'b="2"'], '>')。解析失败返回 None。"""
    try:
        inner = tag_text[1:-1].strip()
        self_close = inner.endswith('/')
        if self_close:
            inner = inner[:-1].rstrip()
        parts = []
        buf = ''
        quote = None
        for ch in inner:
            if quote:
                buf += ch
                if ch == quote:
                    quote = None
            elif ch in ('"', "'"):
                buf += ch
                quote = ch
            elif ch.isspace():
                if buf:
                    parts.append(buf)
                    buf = ''
            else:
                buf += ch
        if buf:
            parts.append(buf)
        if not parts:
            return None
        return '<' + parts[0], parts[1:], ('/>' if self_close else '>')
    except Exception:
        return None


class _Formatter(HTMLParser):
    """把无格式 HTML 输出为带缩进的短行序列。"""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.lines = []
        self.cur = ''            # 当前未闭合的行（用于 标签+短文本 同行）
        self.depth = 0
        self.raw_tag = None      # script/style 内部状态
        self.raw_buf = []

    # ---- 行管理 ----
    def _indent(self):
        return '  ' * min(self.depth, 30)

    def _flush(self):
        if self.cur.strip():
            self.lines.append(self.cur)
        self.cur = ''

    def _emit(self, text):
        self._flush()
        self.lines.append(self._indent() + text)

    def _emit_long(self, text):
        """长文本按词换行输出。"""
        self._flush()
        indent = self._indent()
        line = indent
        for word in text.split():
            if len(line) + len(word) + 1 > MAX_LINE and line.strip():
                self.lines.append(line)
                line = indent + '  ' + word
            else:
                line = (line + ' ' + word) if line.strip() else (indent + word)
        if line.strip():
            self.lines.append(line)

    # ---- 标签 ----
    def handle_starttag(self, tag, attrs):
        self._handle_tag(tag, attrs, self_close=False)

    def handle_startendtag(self, tag, attrs):
        self._handle_tag(tag, attrs, self_close=True)

    def _handle_tag(self, tag, attrs, self_close):
        if self.raw_tag:  # raw 文本中不应出现，但保险起见
            self.raw_buf.append(self.get_starttag_text() or '')
            return
        raw = self.get_starttag_text() or self._rebuild_tag(tag, attrs, self_close)
        is_void = self_close or tag in VOID_TAGS
        if len(raw) <= MAX_LINE and len(attrs) <= MAX_ATTRS_INLINE:
            self._flush()
            self.cur = self._indent() + raw
        else:
            parsed = _split_attrs(raw)
            if not parsed:
                self._emit(raw)
            else:
                head, attr_list, tail = parsed
                self._flush()
                pad = self._indent()
                self.lines.append(pad + head)
                for i, a in enumerate(attr_list):
                    end = tail if i == len(attr_list) - 1 else ''
                    # 单个属性过长（超长 href / base64）按长度硬切
                    while len(a) > MAX_LINE:
                        self.lines.append(pad + '    ' + a[:MAX_LINE])
                        a = a[MAX_LINE:]
                    self.lines.append(pad + '    ' + a + end)
        if not is_void:
            if tag in RAW_TEXT_TAGS:
                self.raw_tag = tag
                self.raw_buf = []
                self._flush()
            else:
                self.depth += 1

    def _rebuild_tag(self, tag, attrs, self_close):
        s = '<' + tag
        for k, v in attrs:
            s += ' ' + k if v is None else ' %s="%s"' % (k, v)
        return s + ('/>' if self_close else '>')

    def handle_endtag(self, tag):
        if self.raw_tag:
            if tag == self.raw_tag:
                self._flush_raw()
                self.raw_tag = None
                self._emit('</%s>' % tag)
            else:
                self.raw_buf.append('</%s>' % tag)
            return
        if tag in VOID_TAGS:
            return
        self.depth = max(0, self.depth - 1)
        close = '</%s>' % tag
        # 短行内闭合：<a href="x">文字</a> 保持一行
        if self.cur.strip() and len(self.cur) + len(close) <= MAX_LINE + 20 and '>' in self.cur:
            self.cur += close
            self._flush()
        else:
            self._flush()
            self.lines.append(self._indent() + close)

    def _flush_raw(self):
        """script/style 内容：按原始行输出，超长行按 ; { } 断行。"""
        text = ''.join(self.raw_buf)
        self.depth += 1
        pad = self._indent()
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            while len(line) > MAX_LINE:
                cut = max(line.rfind(';', 0, MAX_LINE), line.rfind('{', 0, MAX_LINE), line.rfind('}', 0, MAX_LINE))
                if cut <= 0:
                    cut = MAX_LINE
                else:
                    cut += 1
                self.lines.append(pad + line[:cut])
                line = line[cut:].strip()
            if line:
                self.lines.append(pad + line)
        self.depth -= 1

    # ---- 文本 ----
    def handle_data(self, data):
        if self.raw_tag:
            self.raw_buf.append(data)
            return
        text = data.strip()
        if not text:
            return
        if self.cur.strip() and not self.cur.rstrip().endswith('>'):
            # 续在文本后面（属性拆行场景罕见，直接换行）
            self._emit_long(text)
            return
        if self.cur.strip() and len(self.cur) + 1 + len(text) <= MAX_LINE and '\n' not in text:
            self.cur += text
        else:
            self._emit_long(text)

    def handle_entityref(self, name):
        self.handle_data('&%s;' % name)

    def handle_charref(self, name):
        self.handle_data('&#%s;' % name)

    def handle_comment(self, data):
        body = data.strip()
        if self.raw_tag:
            self.raw_buf.append('<!--%s-->' % data)
            return
        if len(body) <= MAX_LINE - 10:
            self._emit('<!-- %s -->' % body)
        else:
            self._emit('<!--')
            self._emit_long(body)
            self._emit('-->')

    def handle_decl(self, decl):
        self._emit('<!%s>' % decl)

    def handle_pi(self, data):
        self._emit('<?%s>' % data)

    def close(self):
        super().close()
        if self.raw_tag:
            self._flush_raw()
            self.raw_tag = None
        self._flush()


def format_html(text):
    """HTML 文本 → 带缩进的行列表。解析失败时退化为按 > < 硬切。"""
    if not text:
        return []
    fmt = _Formatter()
    try:
        fmt.feed(text)
        fmt.close()
        lines = fmt.lines
    except Exception:
        lines = []
    if not lines:
        # 退化方案：在标签边界断行
        rough = text.replace('><', '>\n<')
        lines = [ln.strip() for ln in rough.splitlines() if ln.strip()]
    return lines


# ---------------------------------------------------------------------------
# 词级高亮
# ---------------------------------------------------------------------------

def _esc(s):
    return _html.escape(s, quote=False)


def _intraline(old, new):
    """对一对变更行做字符级比对，返回 (old_html, new_html)，变更段包 <mark>。"""
    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    o_parts, n_parts = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            o_parts.append(_esc(old[i1:i2]))
            n_parts.append(_esc(new[j1:j2]))
        elif tag == 'delete':
            o_parts.append('<mark class="dl">%s</mark>' % _esc(old[i1:i2]))
        elif tag == 'insert':
            n_parts.append('<mark class="ins">%s</mark>' % _esc(new[j1:j2]))
        else:
            o_parts.append('<mark class="dl">%s</mark>' % _esc(old[i1:i2]))
            n_parts.append('<mark class="ins">%s</mark>' % _esc(new[j1:j2]))
    return ''.join(o_parts), ''.join(n_parts)


# ---------------------------------------------------------------------------
# 行级 diff + 折叠渲染
# ---------------------------------------------------------------------------

def _build_rows(old_lines, new_lines):
    """生成统一 diff 行序列。返回 (rows, stats)。"""
    sm = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    rows = []
    stats = {'add': 0, 'del': 0, 'chg': 0}
    o_no = n_no = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for k in range(i2 - i1):
                o_no += 1
                n_no += 1
                rows.append(('ctx', o_no, n_no, _esc(old_lines[i1 + k])))
        elif tag == 'delete':
            for k in range(i2 - i1):
                o_no += 1
                rows.append(('del', o_no, '', _esc(old_lines[i1 + k])))
                stats['del'] += 1
        elif tag == 'insert':
            for k in range(j2 - j1):
                n_no += 1
                rows.append(('add', '', n_no, _esc(new_lines[j1 + k])))
                stats['add'] += 1
        else:  # replace
            d_lines = old_lines[i1:i2]
            a_lines = new_lines[j1:j2]
            paired = min(len(d_lines), len(a_lines))
            for k in range(paired):
                o_no += 1
                n_no += 1
                o_html, n_html = _intraline(d_lines[k], a_lines[k])
                rows.append(('del', o_no, '', o_html))
                rows.append(('add', '', n_no, n_html))
                stats['chg'] += 1
            for k in range(paired, len(d_lines)):
                o_no += 1
                rows.append(('del', o_no, '', _esc(d_lines[k])))
                stats['del'] += 1
            for k in range(paired, len(a_lines)):
                n_no += 1
                rows.append(('add', '', n_no, _esc(a_lines[k])))
                stats['add'] += 1
    return rows, stats


def render_source_diff(old_text, new_text, context=3):
    """渲染统一视图 diff HTML 片段（样式类由页面提供）。"""
    if not old_text and not new_text:
        return '<p class="text-muted" style="padding:16px;">无可比对数据</p>'

    old_lines = format_html(old_text)
    new_lines = format_html(new_text)

    # 完全一致的快速通道
    if old_lines == new_lines:
        return ('<div class="udiff-summary same">两份源码格式化后完全一致（%d 行）'
                '，差异可能来自属性顺序、空白或动态值。</div>' % len(old_lines))

    rows, stats = _build_rows(old_lines, new_lines)

    out = []
    out.append(
        '<div class="udiff-summary">'
        '<span class="ud-stat add">+%d</span>'
        '<span class="ud-stat del">-%d</span>'
        '<span class="ud-stat chg">变更 %d 行</span>'
        '<span class="ud-stat dim">基线 %d 行 → 当前 %d 行（已格式化排版）</span>'
        '</div>' % (stats['add'], stats['del'], stats['chg'], len(old_lines), len(new_lines))
    )
    out.append('<div class="udiff">')

    # 折叠连续相同行
    i = 0
    total = len(rows)
    while i < total:
        row = rows[i]
        if row[0] == 'ctx':
            j = i
            while j < total and rows[j][0] == 'ctx':
                j += 1
            run = j - i
            if run > context * 2 + 3:
                head = rows[i:i + context]
                tail = rows[j - context:j]
                hidden = rows[i + context:j - context]
                for r in head:
                    out.append(_row_html(*r))
                out.append(
                    '<div class="ud-fold" onclick="this.classList.toggle(\'open\');'
                    'this.nextElementSibling.classList.toggle(\'open\')">'
                    '展开被折叠的 %d 行相同内容</div>' % len(hidden)
                )
                out.append('<div class="ud-fold-body">')
                for r in hidden:
                    out.append(_row_html(*r))
                out.append('</div>')
                for r in tail:
                    out.append(_row_html(*r))
            else:
                for r in rows[i:j]:
                    out.append(_row_html(*r))
            i = j
        else:
            out.append(_row_html(*row))
            i += 1

    out.append('</div>')
    return ''.join(out)


def _row_html(kind, o_no, n_no, code_html):
    sign = {'del': '-', 'add': '+', 'ctx': ''}[kind]
    return (
        '<div class="ud-line %s">'
        '<span class="ud-no">%s</span><span class="ud-no">%s</span>'
        '<span class="ud-sign">%s</span><code class="ud-code">%s</code>'
        '</div>' % (kind, o_no, n_no, sign, code_html or '&nbsp;')
    )


# ---------------------------------------------------------------------------
# 缓存（同一次告警的重复打开秒出）
# ---------------------------------------------------------------------------

_cache = {}


def render_source_diff_cached(key, old_text, new_text):
    if key in _cache:
        return _cache[key]
    result = render_source_diff(old_text, new_text)
    if len(_cache) > 40:
        _cache.clear()
    _cache[key] = result
    return result
