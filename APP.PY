# app.py
from flask import Flask, request, jsonify, send_from_directory, abort
import re
import time
from collections import deque

app = Flask(__name__, static_folder='static')

# Simple in-memory log store (deque for bounded memory)
LOG_LIMIT = 1000
waf_logs = deque(maxlen=LOG_LIMIT)

# Configuration
BLOCK_THRESHOLD = 5  # if a request gets a score >= this, block it
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 20  # max requests per IP per window

# simple rate limiter store: {ip: [(timestamp), ...]}
rate_store = {}

# Compile common regexes
SQLI_PATTERNS = [
    r"(?i)\b(select|union|insert|update|delete|drop|alter|create)\b",
    r"(--|#|/\*)\s*$",
    r"(?i)\b(or|and)\b\s+\d+=\d+",
    r"\b0x[0-9a-fA-F]+\b",
]
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"on\w+\s*=\s*\'?.+?\'?",  # e.g. onerror=, onclick=
    r"javascript:\w+",
    r"<iframe[^>]*>",
]
LFI_RFI_PATTERNS = [
    r"(\.|%2e){2}/",  # ../ or encoded
    r"/etc/passwd",
    r"(http|https)://",  # remote include attempts
]
SUSPICIOUS_USER_AGENTS = [
    r"sqlmap", r"nikto", r"nessus", r"acunetix"
]

compiled_sql = [re.compile(p) for p in SQLI_PATTERNS]
compiled_xss = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in XSS_PATTERNS]
compiled_lfi = [re.compile(p, re.IGNORECASE) for p in LFI_RFI_PATTERNS]
compiled_ua = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_USER_AGENTS]

# Helper to add a log entry
def add_log(ip, path, method, score, blocked, matched_rules):
    entry = {
        'time': int(time.time()),
        'ip': ip,
        'path': path,
        'method': method,
        'score': score,
        'blocked': blocked,
        'matched_rules': matched_rules,
    }
    waf_logs.appendleft(entry)

# Simple rate limiter
def check_rate_limit(ip):
    now = time.time()
    timestamps = rate_store.get(ip, [])
    # drop old
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    timestamps.append(now)
    rate_store[ip] = timestamps
    if len(timestamps) > RATE_LIMIT_MAX:
        return False, len(timestamps)
    return True, len(timestamps)

# WAF detection function: score and matched rules
def inspect_request(req):
    score = 0
    matched = []

    # Inspect path
    path = req.path or ''
    for p in compiled_lfi:
        if p.search(path):
            score += 3
            matched.append(('LFI_PATH', p.pattern))

    # Inspect query string
    qs = req.query_string.decode() if req.query_string else ''
    for p in compiled_sql:
        if p.search(qs):
            score += 3
            matched.append(('SQLI_QUERY', p.pattern))
    for p in compiled_xss:
        if p.search(qs):
            score += 3
            matched.append(('XSS_QUERY', p.pattern))

    # Inspect headers
    ua = req.headers.get('User-Agent', '')
    for p in compiled_ua:
        if p.search(ua):
            score += 4
            matched.append(('SUSPICIOUS_UA', p.pattern))

    # Inspect body (form, JSON, raw)
    body_text = ''
    try:
        if req.is_json:
            body_text = str(req.get_json())
        else:
            body_text = req.get_data(as_text=True) or ''
    except Exception:
        body_text = req.get_data(as_text=True) or ''

    # body checks
    for p in compiled_sql:
        if p.search(body_text):
            score += 4
            matched.append(('SQLI_BODY', p.pattern))
    for p in compiled_xss:
        if p.search(body_text):
            score += 4
            matched.append(('XSS_BODY', p.pattern))
    for p in compiled_lfi:
        if p.search(body_text):
            score += 3
            matched.append(('LFI_BODY', p.pattern))

    # Suspicious content-length / oversized
    try:
        cl = int(req.headers.get('Content-Length', '0') or '0')
    except ValueError:
        cl = 0
    if cl > 10_000_000:  # arbitrary 10MB
        score += 2
        matched.append(('LARGE_BODY', cl))

    # Many encoded characters or patterns
    if '%' in qs or '%' in body_text:
        score += 1
        matched.append(('ENCODED_CHARS', '%'))

    return score, matched

# WAF middleware-like decorator
@app.before_request
def waf_before():
    ip = request.remote_addr or 'unknown'

    # Rate limit check
    ok, count = check_rate_limit(ip)
    if not ok:
        add_log(ip, request.path, request.method, score=999, blocked=True, matched_rules=[('RATE_LIMIT', count)])
        abort(429, 'Too Many Requests - WAF')

    # Inspect
    score, matched = inspect_request(request)

    blocked = score >= BLOCK_THRESHOLD
    add_log(ip, request.path, request.method, score, blocked, matched)

    if blocked:
        # custom block response
        return jsonify({
            'status': 'blocked',
            'reason': 'Request matched WAF rules',
            'score': score,
            'matched': matched,
        }), 403

# Simple test endpoint simulating a backend app
@app.route('/app', methods=['GET', 'POST'])
def backend_app():
    return jsonify({
        'status': 'ok',
        'message': 'Request reached backend app',
        'method': request.method,
        'args': request.args,
        'form': request.form,
        'json': request.get_json(silent=True),
    })

# Admin endpoint to fetch logs (in production protect with auth)
@app.route('/admin/logs', methods=['GET'])
def admin_logs():
    # Optional query params: since (epoch), limit
    since = int(request.args.get('since', '0'))
    limit = int(request.args.get('limit', '50'))
    results = []
    for entry in list(waf_logs):
        if entry['time'] >= since:
            results.append(entry)
        if len(results) >= limit:
            break
    return jsonify({'count': len(results), 'logs': results})

# Serve frontend
@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)