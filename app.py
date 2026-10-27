#!/usr/bin/env python3
"""Garena Bind Tool - Premium Web Edition v4 (Full + Fixed)"""

import os, sys, json, io, csv, re, hashlib, base64, secrets, socket, threading
import urllib.parse, sqlite3, traceback
from datetime import datetime, timedelta
from functools import wraps

import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import (Flask, request, session, redirect, url_for,
                   render_template_string, flash, make_response)
from werkzeug.exceptions import HTTPException
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    import MajoRLogin_pb2 as mLpB
    import MajorLoginRes_pb2 as mLrPb
    PROTO_AVAILABLE = True
except ImportError:
    PROTO_AVAILABLE = False

try:
    import qrcode, qrcode.image.svg
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

# ================== CONFIG ==================
SECRET_KEY     = os.environ.get('SECRET_KEY', 'garena_bindtool_premium_secret_v4')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', '1')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '1')
DATABASE       = os.environ.get('DATABASE_PATH', 'bindtool.db')

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(days=3650)

# ================== DB ==================
_init_lock = threading.Lock()
_init_done = False

def db():
    c = sqlite3.connect(DATABASE, timeout=15, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()

def _ensure_column(conn, table, col, defn):
    try:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if col not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
            conn.commit()
    except Exception as e:
        print(f"[init] column {col} error: {e}", flush=True)

def init_db():
    global _init_done
    with _init_lock:
        if _init_done: return
        try:
            conn = db()
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TEXT,
                last_login TEXT,
                banned INTEGER DEFAULT 0,
                ban_reason TEXT,
                active_session_token TEXT
            )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS token_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT, feature TEXT, access_token TEXT,
                details TEXT, status TEXT, timestamp TEXT
            )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS token_vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT, name TEXT, token TEXT, notes TEXT, created_at TEXT
            )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS saved_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT, account_name TEXT, uid TEXT,
                token TEXT, region TEXT, created_at TEXT
            )''')
            conn.commit()

            for col, defn in [('banned','INTEGER DEFAULT 0'),
                              ('ban_reason','TEXT'),
                              ('active_session_token','TEXT')]:
                _ensure_column(conn, 'users', col, defn)

            conn.execute(
                "INSERT OR IGNORE INTO users (username,password_hash,is_admin,created_at) VALUES (?,?,1,?)",
                (ADMIN_USERNAME, hash_pw(ADMIN_PASSWORD), datetime.now().isoformat()))
            conn.execute("UPDATE users SET is_admin=1 WHERE username=?", (ADMIN_USERNAME,))
            conn.commit()
            conn.close()
            _init_done = True
            print(f"[init] DB ready, admin='{ADMIN_USERNAME}'", flush=True)
        except Exception as e:
            print(f"[init] FATAL: {e}", flush=True)
            traceback.print_exc()

init_db()

def log_token(username, feature, access_token, details="", status="used"):
    try:
        conn = db()
        conn.execute("INSERT INTO token_logs (username,feature,access_token,details,status,timestamp) VALUES (?,?,?,?,?,?)",
                     (username, feature, str(access_token)[:200], details, status,
                      datetime.now().isoformat(timespec='seconds')))
        conn.commit(); conn.close()
    except Exception as e:
        print(f"[log_token] {e}", flush=True)

# ================== ERROR HANDLERS ==================
@app.errorhandler(500)
def handle_500(e):
    tb = traceback.format_exc()
    print(f"[500 ERROR]\n{tb}", flush=True)
    return render_template_string('''<!DOCTYPE html>
<html><head><title>Error</title>
<style>body{font-family:sans-serif;background:#06080f;color:#e5e7eb;padding:40px;max-width:800px;margin:auto}
h1{color:#ef4444}pre{background:#151a2e;padding:20px;border-radius:8px;overflow-x:auto;font-size:.85em;border:1px solid #2a3050;white-space:pre-wrap;word-break:break-all}
a{color:#a78bfa;display:inline-block;margin-top:20px}</style></head><body>
<h1>Internal Server Error</h1>
<p>Something broke. Here's the traceback (admin: check Render logs):</p>
<pre>{{ tb }}</pre>
<a href="/login">Back to Login</a></body></html>''', tb=tb), 500

@app.errorhandler(Exception)
def handle_exc(e):
    if isinstance(e, (SystemExit, KeyboardInterrupt)): raise e
    if isinstance(e, HTTPException) and e.code < 500:
        return e
    tb = traceback.format_exc()
    print(f"[EXC] {type(e).__name__}: {e}\n{tb}", flush=True)
    return handle_500(e)

# ================== MIDDLEWARE ==================
@app.before_request
def enforce_admin_single():
    if request.endpoint in (None, 'static'): return
    if session.get('is_admin'):
        try:
            conn = db()
            row = conn.execute("SELECT active_session_token FROM users WHERE username=?",
                               (session['username'],)).fetchone()
            conn.close()
            if row:
                try:
                    stored = row['active_session_token']
                except (IndexError, KeyError):
                    stored = None
                cur = session.get('session_token')
                if stored and cur and stored != cur:
                    session.clear()
                    flash('Session terminated: You logged in from another device.', 'error')
                    return redirect(url_for('login'))
        except Exception as e:
            print(f"[admin_single] {e}", flush=True)

@app.before_request
def enforce_ban():
    if request.endpoint in (None, 'static', 'login', 'register'): return
    if session.get('username') and not session.get('is_admin'):
        try:
            conn = db()
            row = conn.execute("SELECT banned, ban_reason FROM users WHERE username=?",
                               (session['username'],)).fetchone()
            conn.close()
            if row:
                try:
                    banned = row['banned'] or 0
                    reason = row['ban_reason']
                except (IndexError, KeyError):
                    banned, reason = 0, None
                if banned:
                    session.clear()
                    flash('Your account has been banned.' + (f" Reason: {reason}" if reason else ''), 'error')
                    return redirect(url_for('login'))
        except Exception as e:
            print(f"[enforce_ban] {e}", flush=True)

@app.before_request
def auto_restore_user():
    if request.endpoint in (None, 'static'): return
    if 'username' in session and not session.get('is_admin') and 'password_hash' in session:
        try:
            conn = db()
            row = conn.execute("SELECT id FROM users WHERE username=?", (session['username'],)).fetchone()
            if not row:
                conn.execute("INSERT OR IGNORE INTO users (username,password_hash,is_admin,created_at) VALUES (?,?,0,?)",
                             (session['username'], session['password_hash'], datetime.now().isoformat()))
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"[auto_restore] {e}", flush=True)

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if 'username' not in session: return redirect(url_for('login'))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if 'username' not in session: return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*a, **k)
    return w

# ================== ICONS ==================
ICONS = {
 'logo':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>',
 'search':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>',
 'mail-plus':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 7 10 6 10-6"/></svg>',
 'mail-x':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 7 10 6 10-6M15 13l-4 4M11 13l4 4"/></svg>',
 'refresh':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>',
 'x-circle':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/></svg>',
 'key':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="7" cy="17" r="3"/><path d="m9 15 11-11M18 4l3 3M15 7l3 3"/></svg>',
 'shield-off':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18M4.73 4.73 4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38M1 1l22 22"/></svg>',
 'clock':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>',
 'layers':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m12 2 10 5-10 5L2 7l10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>',
 'list':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
 'crown':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 4l3 12h14l3-12-6 7-4-7-4 7-6-7z"/></svg>',
 'logout':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',
 'user':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M6 21v-2a6 6 0 0 1 12 0v2"/></svg>',
 'lock':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
 'arrow-left':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>',
 'check':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>',
 'alert':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>',
 'copy':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
 'qr':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM21 14v3M14 21h3M18 21h3"/></svg>',
 'download':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>',
 'trash':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M10 11v6M14 11v6"/></svg>',
 'plus':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>',
 'ban':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 14.14 14.14"/></svg>',
 'chart':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18M7 12h2v7H7zM12 5h2v14h-2zM17 9h2v10h-2z"/></svg>',
 'filter':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/></svg>',
}

# ================== BASE TEMPLATE ==================
BASE_HTML = '''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0">
<meta name="theme-color" content="#06080f"><title>{{ title }} — Garena Bind Tool</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root{--bg:#06080f;--card:rgba(255,255,255,.03);--border:rgba(255,255,255,.08);--border-h:rgba(139,92,246,.5);--text:#e5e7eb;--muted:#94a3b8;--primary:#8b5cf6;--primary2:#a78bfa;--accent:#06b6d4;--success:#10b981;--danger:#ef4444;--warn:#f59e0b;--radius:14px}
html,body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Roboto,sans-serif;line-height:1.6;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 20% 0%,rgba(139,92,246,.15),transparent 50%),radial-gradient(ellipse at 80% 100%,rgba(6,182,212,.1),transparent 50%);pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1}
svg{width:18px;height:18px;display:inline-block;vertical-align:middle;flex-shrink:0}
.nav{position:sticky;top:0;z-index:100;background:rgba(6,8,15,.9);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:12px 16px}
.nav-inner{max-width:1100px;margin:0 auto;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:8px;color:var(--primary2);font-weight:700;font-size:1em;text-decoration:none;margin-right:8px}
.brand svg{width:20px;height:20px;color:var(--primary)}
.nav a.navlink{color:var(--muted);text-decoration:none;padding:8px 10px;border-radius:8px;font-size:.85em;transition:.2s;display:inline-flex;align-items:center;gap:5px}
.nav a.navlink:hover{color:var(--text);background:rgba(139,92,246,.12)}
.nav .spacer{flex:1}
.user-chip{display:inline-flex;align-items:center;gap:5px;padding:5px 10px;background:rgba(139,92,246,.12);border:1px solid rgba(139,92,246,.25);border-radius:20px;font-size:.78em;color:var(--primary2);font-weight:600}
.user-chip svg{width:13px;height:13px}
.container{max-width:1000px;margin:0 auto;padding:24px 16px 60px}
@media(max-width:640px){.container{padding:18px 12px 50px}.nav-inner{gap:4px}.nav a.navlink{padding:6px 8px;font-size:.8em}.brand{font-size:.9em}}
.page-title{font-size:1.5em;font-weight:700;margin-bottom:6px;letter-spacing:-.02em;display:flex;align-items:center;gap:10px}
@media(max-width:640px){.page-title{font-size:1.25em}}
.page-title svg{width:24px;height:24px;color:var(--primary)}
.page-sub{color:var(--muted);font-size:.9em;margin-bottom:22px}
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth-card{width:100%;max-width:420px;background:linear-gradient(145deg,rgba(255,255,255,.04),rgba(255,255,255,.01));border:1px solid var(--border);border-radius:24px;padding:40px 28px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:0 20px 60px rgba(0,0,0,.5);position:relative;overflow:hidden}
.auth-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,.6),transparent)}
.auth-logo{width:60px;height:60px;background:linear-gradient(135deg,var(--primary),var(--accent));border-radius:16px;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;box-shadow:0 8px 24px rgba(139,92,246,.4)}
.auth-logo svg{width:30px;height:30px;color:#fff}
.auth-title{font-size:1.5em;font-weight:700;text-align:center;margin-bottom:6px;background:linear-gradient(135deg,#fff,var(--primary2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.auth-sub{text-align:center;color:var(--muted);font-size:.85em;margin-bottom:26px}
.form-group{margin-bottom:14px;position:relative}
.form-group .icon{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
.form-group input{padding-left:42px!important}
.auth-footer{text-align:center;margin-top:20px;font-size:.85em;color:var(--muted)}
.auth-footer a{color:var(--primary2);text-decoration:none;font-weight:600}
input[type=text],input[type=password],input[type=email],textarea,select{width:100%;padding:13px 16px;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:12px;color:var(--text);font-size:.92em;font-family:inherit;outline:none;transition:.2s}
input:focus,textarea:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(139,92,246,.15)}
textarea{resize:vertical;min-height:120px;font-family:ui-monospace,monospace;font-size:.85em}
input::placeholder,textarea::placeholder{color:var(--muted);opacity:.6}
select{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2'%3e%3cpath d='m6 9 6 6 6-6'/%3e%3c/svg%3e");background-repeat:no-repeat;background-position:right 12px center;background-size:16px;padding-right:40px}
label.lbl{display:block;color:var(--muted);font-size:.78em;margin-bottom:6px;font-weight:500;text-transform:uppercase;letter-spacing:.05em}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:13px 22px;border:none;border-radius:12px;font-size:.9em;font-weight:600;font-family:inherit;cursor:pointer;transition:.2s;text-decoration:none;width:100%}
.btn-primary{background:linear-gradient(135deg,var(--primary),#7c3aed);color:#fff;box-shadow:0 4px 16px rgba(139,92,246,.35)}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(139,92,246,.5)}
.btn-primary:disabled{opacity:.5;cursor:not-allowed;transform:none}
.btn-danger{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff}
.btn-sm{padding:7px 12px;font-size:.78em;width:auto;border-radius:8px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:22px;margin-bottom:16px;backdrop-filter:blur(10px)}
@media(max-width:640px){.card{padding:16px}}
.card-title{font-size:1em;font-weight:600;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card-title svg{color:var(--primary);width:18px;height:18px}
.section-title{font-size:.78em;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:600;margin:22px 0 10px;display:flex;align-items:center;gap:8px}
.feature-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
@media(max-width:560px){.feature-grid{grid-template-columns:1fr}}
.feature-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:18px;text-decoration:none;color:var(--text);transition:.25s;position:relative;overflow:hidden;display:block}
.feature-card:hover{border-color:var(--border-h);transform:translateY(-2px);box-shadow:0 10px 28px rgba(139,92,246,.15)}
.feature-card .icon-wrap{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,rgba(139,92,246,.2),rgba(6,182,212,.15));border:1px solid rgba(139,92,246,.25);display:flex;align-items:center;justify-content:center;margin-bottom:10px}
.feature-card .icon-wrap svg{width:20px;height:20px;color:var(--primary2)}
.feature-card h3{font-size:.92em;font-weight:600;margin-bottom:3px}
.feature-card p{font-size:.78em;color:var(--muted)}
.result-box{background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:12px;padding:16px;margin-top:8px}
.row{display:flex;align-items:center;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:.88em;gap:10px;flex-wrap:wrap}
.row:last-child{border-bottom:none;padding-bottom:0}
.row:first-child{padding-top:0}
.row .key{color:var(--muted);min-width:130px;font-weight:500;flex-shrink:0}
.row .val{color:var(--text);word-break:break-all;flex:1;font-family:ui-monospace,monospace;font-size:.9em}
@media(max-width:560px){.row .key{min-width:100%;margin-bottom:2px}}
.badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:20px;font-size:.72em;font-weight:600}
.badge-success{background:rgba(16,185,129,.15);color:#6ee7b7;border:1px solid rgba(16,185,129,.3)}
.badge-danger{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3)}
.badge-info{background:rgba(6,182,212,.15);color:#67e8f9;border:1px solid rgba(6,182,212,.3)}
.badge-warn{background:rgba(245,158,11,.15);color:#fcd34d;border:1px solid rgba(245,158,11,.3)}
.flash{padding:12px 16px;border-radius:12px;margin-bottom:16px;font-size:.86em;display:flex;align-items:flex-start;gap:8px}
.flash svg{flex-shrink:0;margin-top:1px;width:16px;height:16px}
.flash-success{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);color:#6ee7b7}
.flash-error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5}
.flash-info{background:rgba(6,182,212,.1);border:1px solid rgba(6,182,212,.3);color:#67e8f9}
.loading-box{display:none;background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.3);border-radius:12px;padding:22px;margin-top:14px;text-align:center}
.loading-box.active{display:block}
.spinner{width:32px;height:32px;border:3px solid rgba(139,92,246,.2);border-top-color:var(--primary);border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 10px}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-text{color:var(--primary2);font-size:.9em;font-weight:500}
.step-header{display:flex;align-items:center;gap:10px;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.step-num{width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,var(--primary),#7c3aed);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85em;flex-shrink:0}
.step-title{font-size:.98em;font-weight:600}
.back-link{display:inline-flex;align-items:center;gap:5px;color:var(--muted);text-decoration:none;font-size:.84em;margin-bottom:16px;padding:6px 12px;border-radius:8px;transition:.2s}
.back-link:hover{color:var(--primary2);background:rgba(139,92,246,.1)}
.back-link svg{width:15px;height:15px}
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:12px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.82em;min-width:480px}
th{background:rgba(139,92,246,.1);padding:11px 12px;text-align:left;color:var(--primary2);font-size:.75em;text-transform:uppercase;letter-spacing:.05em;font-weight:600;white-space:nowrap}
td{padding:11px 12px;border-top:1px solid var(--border);vertical-align:top;color:var(--muted)}
td.mono{font-family:ui-monospace,monospace;font-size:.8em;max-width:240px;word-break:break-all}
tr:hover td{background:rgba(139,92,246,.03)}
.copy-btn{background:rgba(139,92,246,.15);color:var(--primary2);border:1px solid rgba(139,92,246,.3);padding:4px 9px;border-radius:6px;cursor:pointer;font-size:.72em;font-weight:500;display:inline-flex;align-items:center;gap:4px;transition:.2s;margin-left:6px;font-family:inherit}
.copy-btn:hover{background:rgba(139,92,246,.25);color:#fff}
.copy-btn svg{width:11px;height:11px}
.copy-btn.copied{background:rgba(16,185,129,.2);color:#6ee7b7;border-color:rgba(16,185,129,.4)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;text-align:center}
.stat-num{font-size:1.7em;font-weight:700;background:linear-gradient(135deg,var(--primary2),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1.2}
.stat-label{color:var(--muted);font-size:.75em;margin-top:3px;text-transform:uppercase;letter-spacing:.05em}
.hidden{display:none!important}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:.85em}
.bar-label{min-width:100px;color:var(--muted);flex-shrink:0}
.bar-track{flex:1;background:rgba(0,0,0,.3);border-radius:6px;height:22px;overflow:hidden}
.bar-fill{background:linear-gradient(90deg,var(--primary),var(--accent));height:100%;border-radius:6px;display:flex;align-items:center;justify-content:flex-end;padding-right:8px;color:#fff;font-size:.75em;font-weight:600;min-width:24px}
.qr-svg{background:#fff;padding:16px;border-radius:12px;display:inline-block;max-width:100%}
.qr-svg svg{width:220px;height:220px;color:#000}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:rgba(139,92,246,.3);border-radius:4px}
</style></head>
<body><div class="wrap">
{% if username %}
<nav class="nav"><div class="nav-inner">
  <a class="brand" href="{{ url_for('dashboard') }}">{{ ICONS.logo|safe }} Bind Tool</a>
  <a class="navlink" href="{{ url_for('dashboard') }}">Home</a>
  <a class="navlink" href="{{ url_for('my_tokens') }}">Logs</a>
  {% if is_admin %}<a class="navlink" href="{{ url_for('admin_panel') }}">{{ ICONS.crown|safe }} Admin</a>{% endif %}
  <span class="spacer"></span>
  <span class="user-chip">{% if is_admin %}{{ ICONS.crown|safe }}{% else %}{{ ICONS.user|safe }}{% endif %}{{ username }}</span>
  <a class="navlink" href="{{ url_for('logout') }}">{{ ICONS.logout|safe }}</a>
</div></nav>
{% endif %}
{{ content|safe }}
</div>
<script>
function copyText(id,btn){var el=document.getElementById(id);if(!el)return;var txt=(el.tagName==='INPUT'||el.tagName==='TEXTAREA')?el.value:el.textContent;var done=function(){var old=btn.innerHTML;btn.classList.add('copied');btn.innerHTML='Copied';setTimeout(function(){btn.classList.remove('copied');btn.innerHTML=old;},1400);};if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done).catch(fb);}else{fb();}function fb(){var ta=document.createElement('textarea');ta.value=txt;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(ta);}}
function bindAjax(){document.querySelectorAll('form.ajax-form').forEach(function(form){if(form.dataset.bound)return;form.dataset.bound='1';form.addEventListener('submit',async function(e){e.preventDefault();var loader=document.getElementById('loading-box');var btn=form.querySelector('button[type=submit]');var orig=btn?btn.innerHTML:'';if(btn)btn.disabled=true;if(loader){loader.style.display='block';loader.className='loading-box active';loader.innerHTML='<div class="spinner"></div><p class="loading-text">Processing request...</p>';}try{var res=await fetch(form.action||window.location.href,{method:'POST',body:new FormData(form),credentials:'same-origin'});var text=await res.text();var doc=new DOMParser().parseFromString(text,'text/html');var nc=doc.querySelector('.feature-content');var cc=document.querySelector('.feature-content');if(nc&&cc){cc.innerHTML=nc.innerHTML;bindAjax();}else if(loader){loader.className='loading-box active';}}catch(err){if(loader){loader.style.display='block';loader.className='loading-box active';loader.innerHTML='<p class="loading-text" style="color:#fca5a5">Network error: '+err.message+'</p>';}}finally{if(btn){btn.disabled=false;if(orig)btn.innerHTML=orig;}if(loader){loader.style.display='none';}}});});}
document.addEventListener('DOMContentLoaded',bindAjax);
</script></body></html>'''

def render_page(title, content_tpl, **kw):
    try:
        kw['ICONS'] = ICONS
        content = render_template_string(content_tpl, **kw)
        return render_template_string(BASE_HTML, title=title, content=content,
                                       username=session.get('username'),
                                       is_admin=session.get('is_admin', False),
                                       ICONS=ICONS)
    except Exception as e:
        print(f"[render_page] {title} err: {e}\n{traceback.format_exc()}", flush=True)
        raise

# ================== HELPERS ==================
def friendly_error(err):
    if not err: return 'Unknown error'
    e = str(err).lower()
    mapping = {
        'error_email_used': 'This email is already bound to another account.',
        'error_invalid_otp': 'Invalid or expired OTP.', 'error_otp': 'Invalid OTP.',
        'error_email_not_found': 'Email not found on this account.',
        'error_expired': 'Session expired. Try again.', 'error_rate_limit': 'Too many requests. Wait a minute.',
        'error_invalid_token': 'Invalid access token.', 'error_no_email': 'No email bound to this account.',
        'error_invalid_code': 'Invalid security code.', 'error_too_many_attempts': 'Too many attempts. Try later.',
    }
    for k, v in mapping.items():
        if k in e: return v
    return str(err).replace('error_','').replace('_',' ').capitalize()

def parse_api(txt):
    try:
        d = json.loads(txt)
        if d.get('result') == 0: return {'ok': True, 'data': d}
        return {'ok': False, 'err': friendly_error(d.get('error', f"Code {d.get('result')}")), 'raw': d}
    except:
        if '"result": 0' in txt.replace(' ', ''): return {'ok': True, 'data': {}}
        return {'ok': False, 'err': friendly_error(txt[:200]), 'raw': {}}

def convert_secs(s):
    try: s = int(s)
    except: return str(s)
    d,h = divmod(s,86400); h,m = divmod(h,3600); m,s = divmod(m,60)
    return f"{d}d {h}h {m}m {s}s"

def fetch_player(token):
    try:
        url = f"https://api-otrss.garena.com/support/callback/?access_token={token}"
        r = requests.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=15, allow_redirects=True)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query)
        return {'uid':q.get("account_id",["?"])[0],
                'nickname':urllib.parse.unquote(q.get("nickname",["?"])[0]),
                'region':q.get("region",["?"])[0]}
    except Exception as e: return {'error': str(e)}

def fetch_bind_info(token):
    try:
        r = requests.get("https://100067.connect.garena.com/game/account_security/bind:get_bind_info",
                         params={'app_id':"100067",'access_token':token},
                         headers={'User-Agent':"GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)"}, timeout=15)
        if r.status_code != 200: return {'error': f"HTTP {r.status_code}"}
        d = r.json()
        return {'email':d.get("email",""),'email_to_be':d.get("email_to_be",""),
                'countdown':d.get("request_exec_countdown",0),'result':d.get("result",-1)}
    except Exception as e: return {'error': str(e)}

def fetch_platforms(token):
    try:
        r = requests.get("https://100067.connect.garena.com/bind/app/platform/info/get",
                         params={"access_token":token},
                         headers={"User-Agent":"GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)"}, timeout=10)
        if r.status_code == 200: return r.json()
    except: pass
    return None

def revoke_token_raw(token):
    try:
        refresh = "1380dcb63ab3a077dc05bdf0b25ba4497c403a5b4eae96d7203010eafa6c83a8"
        r = requests.get(f"https://100067.connect.garena.com/oauth/logout?access_token={token}&refresh_token={refresh}",
                         headers={"User-Agent":"Mozilla/5.0"}, timeout=15)
        return r.status_code == 200 and "error" not in r.text
    except: return False

# ================== AUTH ROUTES ==================
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'username' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if 'username' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','').strip()
        if not u or not p:
            flash('Username and password required', 'error')
        else:
            try:
                conn = db()
                row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
                if row and row['password_hash'] == hash_pw(p):
                    is_banned = 0
                    ban_reason = None
                    try:
                        is_banned = row['banned'] if 'banned' in row.keys() else 0
                        ban_reason = row['ban_reason'] if 'ban_reason' in row.keys() else None
                    except: pass
                    if is_banned:
                        conn.close()
                        flash('Account banned' + (f": {ban_reason}" if ban_reason else ''), 'error')
                    else:
                        session.permanent = True
                        session['username'] = u
                        session['password_hash'] = row['password_hash']
                        session['is_admin'] = bool(row['is_admin'])
                        session['session_token'] = secrets.token_hex(32)
                        try:
                            conn.execute("UPDATE users SET last_login=?, active_session_token=? WHERE id=?",
                                         (datetime.now().isoformat(), session['session_token'], row['id']))
                            conn.commit()
                        except Exception as ue:
                            print(f"[login] update session err: {ue}", flush=True)
                            try:
                                conn.execute("UPDATE users SET last_login=? WHERE id=?",
                                             (datetime.now().isoformat(), row['id']))
                                conn.commit()
                            except: pass
                        conn.close()
                        log_token(u, 'login', '-', 'login', 'success')
                        return redirect(url_for('dashboard'))
                else:
                    conn.close()
                    flash('Invalid username or password', 'error')
            except Exception as e:
                print(f"[login] err: {e}\n{traceback.format_exc()}", flush=True)
                flash('Login error. Try again.', 'error')

    tpl = '''
    <div class="auth-wrap"><div class="auth-card">
      <div class="auth-logo">{{ ICONS.logo|safe }}</div>
      <h1 class="auth-title">Welcome Back</h1>
      <p class="auth-sub">Sign in to access your tools</p>
      {% with msgs = get_flashed_messages(with_categories=true) %}{% for cat,msg in msgs %}
      <div class="flash flash-{{ cat }}">{{ ICONS['alert']|safe }}<span>{{ msg }}</span></div>{% endfor %}{% endwith %}
      <form method="POST">
        <div class="form-group"><span class="icon">{{ ICONS['user']|safe }}</span>
          <input type="text" name="username" placeholder="Username" required autofocus></div>
        <div class="form-group"><span class="icon">{{ ICONS['lock']|safe }}</span>
          <input type="password" name="password" placeholder="Password" required></div>
        <button type="submit" class="btn btn-primary" style="margin-top:8px">{{ ICONS['logout']|safe }} Sign In</button>
      </form>
      <div class="auth-footer">New here? <a href="{{ url_for('register') }}">Create account</a></div>
    </div></div>'''
    return render_page('Login', tpl)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','').strip()
        if not u or not p: flash('All fields required','error')
        elif len(u) < 3 or len(p) < 3: flash('Username & password must be 3+ chars','error')
        elif u == ADMIN_USERNAME: flash('Reserved username','error')
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
                session['session_token'] = secrets.token_hex(32)
                log_token(u,'register','-','new user','success')
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError: flash('Username already exists','error')
            except Exception as e:
                print(f"[register] {e}", flush=True)
                flash('Registration error','error')

    tpl = '''
    <div class="auth-wrap"><div class="auth-card">
      <div class="auth-logo">{{ ICONS.logo|safe }}</div>
      <h1 class="auth-title">Create Account</h1>
      <p class="auth-sub">Join to access premium tools</p>
      {% with msgs = get_flashed_messages(with_categories=true) %}{% for cat,msg in msgs %}
      <div class="flash flash-{{ cat }}">{{ ICONS['alert']|safe }}<span>{{ msg }}</span></div>{% endfor %}{% endwith %}
      <form method="POST">
        <div class="form-group"><span class="icon">{{ ICONS['user']|safe }}</span>
          <input type="text" name="username" placeholder="Username" required autofocus></div>
        <div class="form-group"><span class="icon">{{ ICONS['lock']|safe }}</span>
          <input type="password" name="password" placeholder="Password" required></div>
        <button type="submit" class="btn btn-primary" style="margin-top:8px">{{ ICONS['check']|safe }} Register</button>
      </form>
      <div class="auth-footer">Already have account? <a href="{{ url_for('login') }}">Sign in</a></div>
    </div></div>'''
    return render_page('Register', tpl)

@app.route('/logout')
def logout():
    if session.get('is_admin'):
        try:
            conn = db()
            conn.execute("UPDATE users SET active_session_token=NULL WHERE username=?", (session['username'],))
            conn.commit(); conn.close()
        except: pass
    session.clear()
    return redirect(url_for('login'))

# ================== DASHBOARD ==================
FEATURES = {
 'Account Management': [
    ('bind_info','search','Check Bind Info','View current binding status'),
    ('full_snapshot','layers','Account Snapshot','All-in-one account overview'),
    ('bind_email','mail-plus','Bind Email','Attach a recovery email'),
    ('unbind_email','mail-x','Unbind Email','Remove bound email'),
    ('change_bind','refresh','Change Email','Replace bound email'),
    ('cancel_bind','x-circle','Cancel Bind','Cancel pending request'),
    ('bind_monitor','clock','Bind Monitor','Track pending bind countdown'),
 ],
 'Token Tools': [
    ('eat_to_token','key','EAT to Token','Convert EAT to access token'),
    ('revoke_token','shield-off','Revoke Token','Logout & invalidate token'),
    ('token_validator','check','Validate Token','Check token validity'),
    ('bulk_checker','list','Bulk Checker','Check multiple tokens at once'),
    ('batch_revoke','shield-off','Batch Revoke','Revoke many tokens together'),
    ('jwt_decoder','key','JWT Decoder','Decode JWT payload'),
    ('qr_generator','qr','QR Generator','Turn token into QR code'),
    ('token_vault','lock','Token Vault','Save tokens safely'),
 ],
 'Lookup & Info': [
    ('player_lookup','user','Player Lookup','Find player by UID'),
    ('login_history','clock','Login History','View device login records'),
    ('bound_accounts','layers','Platform Binds','Check linked platforms'),
    ('account_manager','user','Account Manager','Save multiple accounts'),
    ('email_validator','mail-plus','Email Checker','Validate email format'),
    ('export_logs','download','Export Logs','Download your activity'),
 ],
}

@app.route('/dashboard')
@login_required
def dashboard():
    sections_html = ''
    for section, feats in FEATURES.items():
        cards = ''.join(f'<a class="feature-card" href="/feature/{slug}"><div class="icon-wrap">{ICONS[icon]}</div><h3>{title}</h3><p>{desc}</p></a>' for slug,icon,title,desc in feats)
        sections_html += f'<div class="section-title">{section}</div><div class="feature-grid">{cards}</div>'
    if session.get('is_admin'):
        admin_card = f'<div class="section-title">Admin</div><div class="feature-grid"><a class="feature-card" href="/admin" style="border-color:rgba(245,158,11,.3)"><div class="icon-wrap" style="background:linear-gradient(135deg,rgba(245,158,11,.2),rgba(239,68,68,.15))">{ICONS["crown"]}</div><h3>Admin Panel</h3><p>Manage users and logs</p></a></div>'
        sections_html += admin_card
    tpl = f'''
    <div class="container">
      <h1 class="page-title">{ICONS['layers']} Dashboard</h1>
      <p class="page-sub">All tools at your fingertips</p>
      {sections_html}
    </div>'''
    return render_page('Dashboard', tpl)

@app.template_filter('human_secs')
def _hs(s): return convert_secs(s)

# ================== FEATURE: BIND INFO ==================
@app.route('/feature/bind_info', methods=['GET','POST'])
@login_required
def feature_bind_info():
    result = None
    if request.method == 'POST':
        t = request.form.get('access_token','').strip()
        if not t: result = {'error': 'Token required'}
        else:
            player = fetch_player(t); bind = fetch_bind_info(t)
            log_token(session['username'],'bind_info',t,f"nick={player.get('nickname','?')}",'used')
            result = {'player': player, 'bind': bind}
    tpl = '''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['search']|safe }} Check Bind Info</h1>
      <p class="page-sub">View player and current email bind status</p>
      <div class="feature-content">
      {% if result and result.error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ result.error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Token</label>
          <input type="text" name="access_token" placeholder="Paste access token" required>
          <button type="submit" class="btn btn-primary" style="margin-top:12px">{{ ICONS['search']|safe }} Check</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result and result.player and not result.error %}
      <div class="card"><div class="card-title">{{ ICONS['user']|safe }} Player Info</div>
        <div class="result-box">
          {% if result.player.error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ result.player.error }}</span></div>
          {% else %}
          <div class="row"><span class="key">UID</span><span class="val" id="u1">{{ result.player.uid }}</span><button type="button" class="copy-btn" onclick="copyText('u1',this)">{{ ICONS['copy']|safe }}</button></div>
          <div class="row"><span class="key">Nickname</span><span class="val">{{ result.player.nickname }}</span></div>
          <div class="row"><span class="key">Region</span><span class="val">{{ result.player.region }}</span></div>
          {% endif %}
        </div>
      </div>
      {% endif %}
      {% if result and result.bind and not result.error %}
      <div class="card"><div class="card-title">{{ ICONS['mail-plus']|safe }} Bind Info</div>
        <div class="result-box">
          {% if result.bind.error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ result.bind.error }}</span></div>
          {% else %}
          <div class="row"><span class="key">Current Email</span><span class="val" id="em1">{{ result.bind.email or "Not set" }}</span>
            {% if result.bind.email %}<button type="button" class="copy-btn" onclick="copyText('em1',this)">{{ ICONS['copy']|safe }}</button>{% endif %}</div>
          <div class="row"><span class="key">Pending Email</span><span class="val">{{ result.bind.email_to_be or "None" }}</span></div>
          {% if result.bind.email_to_be %}<div class="row"><span class="key">Countdown</span><span class="val">{{ result.bind.countdown|human_secs }}</span></div>{% endif %}
          <div class="row"><span class="key">Status</span><span class="val"><span class="badge badge-{{ 'success' if result.bind.result == 0 else 'danger' }}">{% if result.bind.result == 0 %}Success{% else %}Code {{ result.bind.result }}{% endif %}</span></span></div>
          {% endif %}
        </div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Check Bind Info', tpl, result=result)

# ================== FEATURE: BIND EMAIL ==================
@app.route('/feature/bind_email', methods=['GET','POST'])
@login_required
def feature_bind_email():
    result=None; error=None; step=1
    if request.method=='POST':
        fs = request.form.get('step','1')
        if fs=='1':
            t = request.form.get('access_token','').strip()
            e = request.form.get('email','').strip()
            if not t or not e: error='Token and email required'
            else:
                try:
                    h = {"User-Agent":"GarenaMSDK/4.0.30","Content-Type":"application/x-www-form-urlencoded"}
                    r = requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                                     headers=h, data={"email":e,"locale":"en_PK","region":"PK","app_id":"100067","access_token":t}, timeout=15)
                    p = parse_api(r.text)
                    log_token(session['username'],'bind_email_otp',t,f"email={e}|{'ok' if p['ok'] else p['err']}",'success' if p['ok'] else 'failed')
                    if p['ok']:
                        session['bind_email_flow']={'token':t,'email':e}; step=2; result={'msg':f'OTP sent to {e}'}
                    else: error=p['err']
                except Exception as ex: error=str(ex)
        elif fs=='2':
            flow = session.get('bind_email_flow')
            if not flow: error='Session expired. Start over.'
            else:
                otp=request.form.get('otp','').strip(); sc=request.form.get('security_code','').strip()
                if not otp or not sc: error='OTP & security code required'; step=2
                else:
                    try:
                        h={"User-Agent":"GarenaMSDK/4.0.30","Content-Type":"application/x-www-form-urlencoded"}
                        r1=requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp",
                                       headers=h,data={"app_id":"100067","access_token":flow['token'],"email":flow['email'],"code":otp,"otp":otp,"type":"1"},timeout=15)
                        p1=parse_api(r1.text)
                        if not p1['ok']: error=p1['err']; step=2
                        else:
                            vt = p1['data'].get('verifier_token','')
                            r2=requests.post("https://100067.connect.garena.com/game/account_security/bind:create_bind_request",
                                           headers=h,data={"email":flow['email'],"app_id":"100067","access_token":flow['token'],"verifier_token":vt,"secondary_password":sc},timeout=15)
                            p2=parse_api(r2.text)
                            log_token(session['username'],'bind_email_final',flow['token'],f"email={flow['email']}|{'ok' if p2['ok'] else p2['err']}",'success' if p2['ok'] else 'failed')
                            if p2['ok']: result={'msg':f'Successfully bound {flow["email"]}'}; session.pop('bind_email_flow',None); step=3
                            else: error=p2['err']; step=2
                    except Exception as ex: error=str(ex); step=2
    else:
        if session.get('bind_email_flow'): step=2
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['mail-plus']|safe }} Bind Email</h1>
      <p class="page-sub">Attach a recovery email to your account</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
      {% if step == 1 %}
        <div class="step-header"><div class="step-num">1</div><div class="step-title">Send OTP to email</div></div>
        <form method="POST" class="ajax-form"><input type="hidden" name="step" value="1">
          <label class="lbl">Access Token</label><input type="text" name="access_token" placeholder="Paste token" required>
          <label class="lbl" style="margin-top:12px">Email</label><input type="email" name="email" placeholder="your@email.com" required>
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Send OTP</button>
        </form>
      {% elif step == 2 %}
        <div class="step-header"><div class="step-num">2</div><div class="step-title">Verify OTP & set security code</div></div>
        <form method="POST" class="ajax-form"><input type="hidden" name="step" value="2">
          <label class="lbl">OTP Code</label><input type="text" name="otp" placeholder="6-digit code" required autofocus>
          <label class="lbl" style="margin-top:12px">Security Code</label><input type="text" name="security_code" placeholder="Set 6-digit security code" required maxlength="6">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Verify & Bind</button>
        </form>
      {% else %}
        <div class="flash flash-success">{{ ICONS['check']|safe }}<span>{{ result.msg if result else 'Email bound successfully' }}</span></div>
        <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
      {% endif %}
        <div id="loading-box" class="loading-box"></div>
      </div>
      </div>
    </div>'''
    return render_page('Bind Email', tpl, result=result, error=error, step=step)

# ================== FEATURE: UNBIND EMAIL ==================
@app.route('/feature/unbind_email', methods=['GET','POST'])
@login_required
def feature_unbind_email():
    result=None; error=None; state = session.get('unbind_state')
    if request.method=='POST':
        action = request.form.get('action','')
        if action=='start':
            method = request.form.get('method','otp'); t = request.form.get('access_token','').strip()
            if not t: error='Token required'
            else:
                info = fetch_bind_info(t); email = info.get('email','')
                if not email: error='No email bound'
                elif method=='otp':
                    try:
                        h={"User-Agent":"GarenaMSDK/4.0.30","Content-Type":"application/x-www-form-urlencoded"}
                        r=requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",
                                      headers=h,data={"email":email,"locale":"en_PK","region":"PK","app_id":"100067","access_token":t},timeout=15)
                        p=parse_api(r.text)
                        if p['ok']: session['unbind_state']={'token':t,'email':email,'method':'otp'}; state=session['unbind_state']; result={'msg':f'OTP sent to {email}'}
                        else: error=p['err']
                    except Exception as ex: error=str(ex)
                else: session['unbind_state']={'token':t,'email':email,'method':'sc'}; state=session['unbind_state']
        elif action in ('verify_otp','verify_sc'):
            if not state: error='Session expired'
            else:
                h={"User-Agent":"GarenaMSDK/4.0.30","Content-Type":"application/x-www-form-urlencoded"}
                try:
                    if action=='verify_otp':
                        otp=request.form.get('otp','').strip()
                        r=requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                                      headers=h,data={"email":state['email'],"app_id":"100067","access_token":state['token'],"otp":otp},timeout=15)
                    else:
                        sc=request.form.get('security_code','').strip()
                        r=requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                                      headers=h,data={"email":state['email'],"app_id":"100067","access_token":state['token'],"secondary_password":hashlib.sha256(sc.encode()).hexdigest()},timeout=15)
                    p=parse_api(r.text)
                    it = p['data'].get('identity_token') if p['ok'] else None
                    if it:
                        r2=requests.post("https://100067.connect.garena.com/game/account_security/bind:create_unbind_request",
                                       headers=h,data={"app_id":"100067","access_token":state['token'],"identity_token":it},timeout=15)
                        p2=parse_api(r2.text)
                        log_token(session['username'],'unbind_email',state['token'],f"email={state['email']}|{'ok' if p2['ok'] else p2['err']}",'success' if p2['ok'] else 'failed')
                        if p2['ok']: result={'msg':'Unbind request submitted'}; session.pop('unbind_state',None); state=None
                        else: error=p2['err']
                    else: error=p['err']
                except Exception as ex: error=str(ex)
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['mail-x']|safe }} Unbind Email</h1>
      <p class="page-sub">Remove currently bound email</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      {% if result %}<div class="flash flash-success">{{ ICONS['check']|safe }}<span>{{ result.msg }}</span></div>{% endif %}
      <div class="card">
      {% if not state %}
        <form method="POST" class="ajax-form"><input type="hidden" name="action" value="start">
          <label class="lbl">Access Token</label><input type="text" name="access_token" placeholder="Paste token" required>
          <label class="lbl" style="margin-top:12px">Method</label>
          <select name="method"><option value="otp">Via OTP</option><option value="sc">Via security code</option></select>
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Continue</button>
        </form>
      {% elif state.method == 'otp' %}
        <div class="step-header"><div class="step-num">2</div><div class="step-title">OTP to {{ state.email }}</div></div>
        <form method="POST" class="ajax-form"><input type="hidden" name="action" value="verify_otp">
          <label class="lbl">OTP</label><input type="text" name="otp" placeholder="Enter OTP" required autofocus>
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Verify & Unbind</button>
        </form>
      {% else %}
        <div class="step-header"><div class="step-num">2</div><div class="step-title">Security code</div></div>
        <form method="POST" class="ajax-form"><input type="hidden" name="action" value="verify_sc">
          <label class="lbl">Security Code</label><input type="text" name="security_code" placeholder="6-digit code" required autofocus maxlength="6">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Verify & Unbind</button>
        </form>
      {% endif %}
        <div id="loading-box" class="loading-box"></div>
      </div>
      </div>
    </div>'''
    return render_page('Unbind Email', tpl, result=result, error=error, state=state)

# ================== FEATURE: CHANGE BIND ==================
@app.route('/feature/change_bind', methods=['GET','POST'])
@login_required
def feature_change_bind():
    result=None; error=None; state=session.get('change_bind_state')
    if request.method=='POST':
        action=request.form.get('action','')
        h={"User-Agent":"GarenaMSDK/4.0.30","Content-Type":"application/x-www-form-urlencoded"}
        if action=='start':
            t=request.form.get('access_token','').strip(); method=request.form.get('method','otp')
            if not t: error='Token required'
            else:
                info=fetch_bind_info(t); old=info.get('email','')
                if not old: error='No email bound'
                elif method=='otp':
                    try:
                        r=requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",headers=h,
                                       data={"email":old,"locale":"en_PK","region":"PK","app_id":"100067","access_token":t},timeout=15)
                        p=parse_api(r.text)
                        if p['ok']: session['change_bind_state']={'token':t,'old_email':old,'method':'otp','stage':'verify_old'}; state=session['change_bind_state']; result={'msg':f'OTP sent to {old}'}
                        else: error=p['err']
                    except Exception as ex: error=str(ex)
                else: session['change_bind_state']={'token':t,'old_email':old,'method':'sc','stage':'verify_old'}; state=session['change_bind_state']
        elif action in ('verify_old_otp','verify_old_sc'):
            if not state: error='Session expired'
            else:
                try:
                    if action=='verify_old_otp':
                        otp=request.form.get('otp','').strip()
                        r=requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",headers=h,
                                       data={"email":state['old_email'],"app_id":"100067","access_token":state['token'],"otp":otp},timeout=15)
                    else:
                        sc=request.form.get('security_code','').strip()
                        r=requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_identity",headers=h,
                                       data={"email":state['old_email'],"app_id":"100067","access_token":state['token'],"secondary_password":hashlib.sha256(sc.encode()).hexdigest()},timeout=15)
                    p=parse_api(r.text); it=p['data'].get('identity_token') if p['ok'] else None
                    if it: state['identity_token']=it; state['stage']='new_email'; session['change_bind_state']=state; result={'msg':'Identity verified. Enter new email.'}
                    else: error=p['err']
                except Exception as ex: error=str(ex)
        elif action=='send_new_otp':
            if not state: error='Session expired'
            else:
                ne=request.form.get('new_email','').strip()
                if not ne: error='Email required'
                else:
                    try:
                        r=requests.post("https://100067.connect.garena.com/game/account_security/bind:send_otp",headers=h,
                                       data={"email":ne,"locale":"en_PK","region":"PK","app_id":"100067","access_token":state['token']},timeout=15)
                        p=parse_api(r.text)
                        if p['ok']: state['new_email']=ne; state['stage']='verify_new'; session['change_bind_state']=state; result={'msg':f'OTP sent to {ne}'}
                        else: error=p['err']
                    except Exception as ex: error=str(ex)
        elif action=='finalize':
            if not state: error='Session expired'
            else:
                try:
                    otp=request.form.get('otp','').strip()
                    r=requests.post("https://100067.connect.garena.com/game/account_security/bind:verify_otp",headers=h,
                                   data={"email":state['new_email'],"app_id":"100067","access_token":state['token'],"otp":otp},timeout=15)
                    p=parse_api(r.text); vt=p['data'].get('verifier_token') if p['ok'] else None
                    if not vt: error=p['err']
                    else:
                        r2=requests.post("https://100067.connect.garena.com/game/account_security/bind:create_rebind_request",headers=h,
                                        data={"identity_token":state['identity_token'],"email":state['new_email'],"app_id":"100067","verifier_token":vt,"access_token":state['token']},timeout=15)
                        p2=parse_api(r2.text)
                        log_token(session['username'],'change_bind',state['token'],f"{state['old_email']}->{state['new_email']}|{'ok' if p2['ok'] else p2['err']}",'success' if p2['ok'] else 'failed')
                        if p2['ok']: result={'msg':f'Rebind success: {state["new_email"]}'}; session.pop('change_bind_state',None); state=None
                        else: error=p2['err']
                except Exception as ex: error=str(ex)
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['refresh']|safe }} Change Bind Email</h1>
      <p class="page-sub">Replace the currently bound email</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      {% if result %}<div class="flash flash-success">{{ ICONS['check']|safe }}<span>{{ result.msg }}</span></div>{% endif %}
      <div class="card">
      {% if not state %}
        <form method="POST" class="ajax-form"><input type="hidden" name="action" value="start">
          <label class="lbl">Access Token</label><input type="text" name="access_token" required placeholder="Paste token">
          <label class="lbl" style="margin-top:12px">Verify Method</label>
          <select name="method"><option value="otp">Via old email OTP</option><option value="sc">Via security code</option></select>
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Continue</button>
        </form>
      {% elif state.stage == 'verify_old' and state.method == 'otp' %}
        <div class="step-header"><div class="step-num">2</div><div class="step-title">OTP to {{ state.old_email }}</div></div>
        <form method="POST" class="ajax-form"><input type="hidden" name="action" value="verify_old_otp">
          <label class="lbl">OTP</label><input type="text" name="otp" required autofocus placeholder="Enter OTP">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Verify</button>
        </form>
      {% elif state.stage == 'verify_old' and state.method == 'sc' %}
        <div class="step-header"><div class="step-num">2</div><div class="step-title">Security code</div></div>
        <form method="POST" class="ajax-form"><input type="hidden" name="action" value="verify_old_sc">
          <label class="lbl">Security Code</label><input type="text" name="security_code" required autofocus maxlength="6" placeholder="6-digit code">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Verify</button>
        </form>
      {% elif state.stage == 'new_email' %}
        <div class="step-header"><div class="step-num">3</div><div class="step-title">Enter new email</div></div>
        <form method="POST" class="ajax-form"><input type="hidden" name="action" value="send_new_otp">
          <label class="lbl">New Email</label><input type="email" name="new_email" required autofocus placeholder="new@email.com">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Send OTP</button>
        </form>
      {% elif state.stage == 'verify_new' %}
        <div class="step-header"><div class="step-num">4</div><div class="step-title">OTP to {{ state.new_email }}</div></div>
        <form method="POST" class="ajax-form"><input type="hidden" name="action" value="finalize">
          <label class="lbl">OTP</label><input type="text" name="otp" required autofocus placeholder="Enter new OTP">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Verify & Rebind</button>
        </form>
      {% endif %}
        <div id="loading-box" class="loading-box"></div>
      </div>
      </div>
    </div>'''
    return render_page('Change Bind Email', tpl, result=result, error=error, state=state)

# ================== FEATURE: CANCEL BIND ==================
@app.route('/feature/cancel_bind', methods=['GET','POST'])
@login_required
def feature_cancel_bind():
    result=None; error=None
    if request.method=='POST':
        t=request.form.get('access_token','').strip()
        if not t: error='Token required'
        else:
            try:
                h={"User-Agent":"GarenaMSDK/4.0.30","Content-Type":"application/x-www-form-urlencoded"}
                r=requests.post("https://100067.connect.garena.com/game/account_security/bind:cancel_request",headers=h,data={"app_id":"100067","access_token":t},timeout=15)
                p=parse_api(r.text)
                log_token(session['username'],'cancel_bind',t,'ok' if p['ok'] else p['err'],'success' if p['ok'] else 'failed')
                if p['ok']: result={'msg':'Cancel request submitted'}
                else: error=p['err']
            except Exception as ex: error=str(ex)
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['x-circle']|safe }} Cancel Bind Request</h1>
      <p class="page-sub">Cancel any pending bind request</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      {% if result %}<div class="flash flash-success">{{ ICONS['check']|safe }}<span>{{ result.msg }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Token</label><input type="text" name="access_token" required placeholder="Paste token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Cancel Bind</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      </div>
    </div>'''
    return render_page('Cancel Bind', tpl, result=result, error=error)

# ================== FEATURE: BIND MONITOR ==================
@app.route('/feature/bind_monitor', methods=['GET','POST'])
@login_required
def feature_bind_monitor():
    result=None; error=None
    if request.method=='POST':
        t=request.form.get('access_token','').strip()
        if not t: error='Token required'
        else:
            info=fetch_bind_info(t)
            result={'info': info, 'token': t}
            log_token(session['username'],'bind_monitor',t,f"pending={info.get('email_to_be','none')}",'used')
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['clock']|safe }} Bind Request Monitor</h1>
      <p class="page-sub">Track pending bind requests and countdowns</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Token</label><input type="text" name="access_token" required placeholder="Paste token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Check Status</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result and result.info and not result.info.error %}
      <div class="card"><div class="card-title">{{ ICONS['clock']|safe }} Current Bind Status</div>
        <div class="result-box">
          <div class="row"><span class="key">Bound Email</span><span class="val">{{ result.info.email or "None" }}</span></div>
          <div class="row"><span class="key">Pending Email</span><span class="val">{{ result.info.email_to_be or "None" }}</span></div>
          {% if result.info.email_to_be %}
          <div class="row"><span class="key">Time Remaining</span><span class="val"><span class="badge badge-warn">{{ result.info.countdown|human_secs }}</span></span></div>
          <div class="row"><span class="key">Status</span><span class="val"><span class="badge badge-info">Pending Confirmation</span></span></div>
          {% else %}
          <div class="row"><span class="key">Status</span><span class="val"><span class="badge badge-success">No pending requests</span></span></div>
          {% endif %}
        </div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Bind Monitor', tpl, result=result, error=error)

# ================== FEATURE: EAT TO TOKEN ==================
@app.route('/feature/eat_to_token', methods=['GET','POST'])
@login_required
def feature_eat_to_token():
    result=None; error=None
    if request.method=='POST':
        raw=request.form.get('input','').strip(); eat=None
        if 'http' in raw or '?' in raw:
            q=urllib.parse.parse_qs(urllib.parse.urlparse(raw).query); eat=q.get('eat',[None])[0]
        else: eat=raw
        if not eat: error='No EAT token found'
        else:
            try:
                r=requests.get(f"https://api-otrss.garena.com/support/callback/?access_token={eat}",headers={"User-Agent":"Mozilla/5.0 (Android 13)"},allow_redirects=True,timeout=15)
                q=urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query)
                if 'access_token' in q:
                    at=q['access_token'][0]
                    result={'access_token':at,'account_id':q.get('account_id',['?'])[0],'nickname':urllib.parse.unquote(q.get('nickname',['?'])[0]),'region':q.get('region',['?'])[0]}
                    log_token(session['username'],'eat_to_token',at,f"nick={result['nickname']}",'success')
                else: error='Access token not found. EAT may be expired.'
            except Exception as ex: error=str(ex)
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['key']|safe }} EAT to Access Token</h1>
      <p class="page-sub">Convert EAT token/URL into access token</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">EAT Token or URL</label><input type="text" name="input" required placeholder="Paste EAT token or URL">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Convert</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result %}
      <div class="card"><div class="card-title">{{ ICONS['check']|safe }} Success</div>
        <div class="result-box">
          <div class="row"><span class="key">Nickname</span><span class="val">{{ result.nickname }}</span></div>
          <div class="row"><span class="key">Account ID</span><span class="val">{{ result.account_id }}</span></div>
          <div class="row"><span class="key">Region</span><span class="val">{{ result.region }}</span></div>
          <div class="row"><span class="key">Access Token</span><span class="val" id="tok-out">{{ result.access_token }}</span>
            <button type="button" class="copy-btn" onclick="copyText('tok-out',this)">{{ ICONS['copy']|safe }} Copy</button></div>
        </div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('EAT to Token', tpl, result=result, error=error)

# ================== FEATURE: REVOKE TOKEN ==================
@app.route('/feature/revoke_token', methods=['GET','POST'])
@login_required
def feature_revoke_token():
    result=None; error=None
    if request.method=='POST':
        t=request.form.get('access_token','').strip()
        if not t: error='Token required'
        else:
            player=fetch_player(t)
            if player.get('error'): error='Token invalid or already revoked'
            elif revoke_token_raw(t):
                result={'nickname':player.get('nickname','?'),'account_id':player.get('uid','?'),'region':player.get('region','?')}
                log_token(session['username'],'revoke_token',t,f"nick={player.get('nickname','?')}",'success')
            else: error='Server rejected revoke'
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['shield-off']|safe }} Revoke Access Token</h1>
      <p class="page-sub">Force logout and invalidate token</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Token</label><input type="text" name="access_token" required placeholder="Paste token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Revoke</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result %}
      <div class="card"><div class="card-title">{{ ICONS['check']|safe }} Revoked</div>
        <div class="result-box">
          <div class="row"><span class="key">Nickname</span><span class="val">{{ result.nickname }}</span></div>
          <div class="row"><span class="key">Account ID</span><span class="val">{{ result.account_id }}</span></div>
          <div class="row"><span class="key">Region</span><span class="val">{{ result.region }}</span></div>
          <div class="row"><span class="key">Status</span><span class="val"><span class="badge badge-success">Revoked</span></span></div>
        </div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Revoke Token', tpl, result=result, error=error)

# ================== FEATURE: TOKEN VALIDATOR ==================
@app.route('/feature/token_validator', methods=['GET','POST'])
@login_required
def feature_token_validator():
    result=None; error=None
    if request.method=='POST':
        t=request.form.get('access_token','').strip()
        if not t: error='Token required'
        else:
            player=fetch_player(t)
            if player.get('error'):
                result={'valid': False, 'reason': player['error']}
            else:
                result={'valid': True, 'player': player, 'inspect': None}
                try:
                    r=requests.get(f"https://100067.connect.garena.com/oauth/token/inspect?token={t}",
                                   headers={"User-Agent":"Mozilla/5.0"},timeout=5).json()
                    result['inspect'] = r
                except: pass
            log_token(session['username'],'token_validator',t,'valid' if result.get('valid') else 'invalid','success' if result.get('valid') else 'failed')
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['check']|safe }} Validate Token</h1>
      <p class="page-sub">Verify if an access token is active</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Token</label><input type="text" name="access_token" required placeholder="Paste token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Validate</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result %}
      <div class="card"><div class="card-title">{{ ICONS['check']|safe }} Result</div>
        <div class="result-box">
          <div class="row"><span class="key">Status</span><span class="val"><span class="badge badge-{{ 'success' if result.valid else 'danger' }}">{{ 'Valid' if result.valid else 'Invalid' }}</span></span></div>
          {% if result.valid %}
          <div class="row"><span class="key">Nickname</span><span class="val">{{ result.player.nickname }}</span></div>
          <div class="row"><span class="key">UID</span><span class="val">{{ result.player.uid }}</span></div>
          <div class="row"><span class="key">Region</span><span class="val">{{ result.player.region }}</span></div>
          {% if result.inspect %}<div class="row"><span class="key">Inspect</span><span class="val">{{ result.inspect }}</span></div>{% endif %}
          {% else %}
          <div class="row"><span class="key">Reason</span><span class="val">{{ result.reason }}</span></div>
          {% endif %}
        </div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Validate Token', tpl, result=result, error=error)

# ================== FEATURE: BULK CHECKER ==================
@app.route('/feature/bulk_checker', methods=['GET','POST'])
@login_required
def feature_bulk_checker():
    results=None; error=None
    if request.method=='POST':
        raw=request.form.get('tokens','').strip()
        if not raw: error='No tokens provided'
        else:
            tokens=[t.strip() for t in raw.split('\n') if t.strip()][:50]
            results=[]
            for tok in tokens:
                player=fetch_player(tok); bind=fetch_bind_info(tok)
                log_token(session['username'],'bulk_check',tok,f"nick={player.get('nickname','?')}",'used')
                results.append({'token':tok,'player':player,'bind':bind})
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['list']|safe }} Bulk Token Checker</h1>
      <p class="page-sub">Check up to 50 tokens in one go</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Tokens (one per line)</label>
          <textarea name="tokens" placeholder="token1&#10;token2&#10;token3" required></textarea>
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Check All</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if results %}
      <div class="card"><div class="card-title">{{ ICONS['list']|safe }} {{ results|length }} Results</div>
        <div class="table-wrap"><table>
          <tr><th>Token</th><th>Nickname</th><th>Region</th><th>Email</th><th>Status</th></tr>
          {% for r in results %}
          <tr>
            <td class="mono">{{ r.token[:20] }}...</td>
            <td>{{ r.player.nickname if not r.player.error else 'Invalid' }}</td>
            <td>{{ r.player.region if not r.player.error else '-' }}</td>
            <td>{{ r.bind.email or 'None' if not r.bind.error else '-' }}</td>
            <td><span class="badge badge-{{ 'success' if not r.player.error else 'danger' }}">{{ 'OK' if not r.player.error else 'Failed' }}</span></td>
          </tr>
          {% endfor %}
        </table></div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Bulk Checker', tpl, results=results, error=error)

# ================== FEATURE: BATCH REVOKE ==================
@app.route('/feature/batch_revoke', methods=['GET','POST'])
@login_required
def feature_batch_revoke():
    results=None; error=None
    if request.method=='POST':
        raw=request.form.get('tokens','').strip()
        if not raw: error='No tokens provided'
        else:
            tokens=[t.strip() for t in raw.split('\n') if t.strip()][:20]
            results=[]
            for tok in tokens:
                player=fetch_player(tok)
                if player.get('error'):
                    results.append({'token':tok,'status':'invalid','msg':'Invalid token'})
                elif revoke_token_raw(tok):
                    results.append({'token':tok,'status':'revoked','msg':f"Revoked ({player.get('nickname','?')})"})
                else:
                    results.append({'token':tok,'status':'failed','msg':'Server rejected'})
                log_token(session['username'],'batch_revoke',tok,results[-1]['msg'],results[-1]['status'])
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['shield-off']|safe }} Batch Revoke</h1>
      <p class="page-sub">Revoke up to 20 tokens at once</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Tokens (one per line)</label>
          <textarea name="tokens" placeholder="token1&#10;token2" required></textarea>
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Revoke All</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if results %}
      <div class="card"><div class="card-title">{{ ICONS['shield-off']|safe }} {{ results|length }} Results</div>
        <div class="table-wrap"><table>
          <tr><th>Token</th><th>Status</th><th>Message</th></tr>
          {% for r in results %}
          <tr><td class="mono">{{ r.token[:20] }}...</td>
            <td><span class="badge badge-{{ 'success' if r.status=='revoked' else ('danger' if r.status=='failed' else 'warn') }}">{{ r.status }}</span></td>
            <td>{{ r.msg }}</td></tr>
          {% endfor %}
        </table></div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Batch Revoke', tpl, results=results, error=error)

# ================== FEATURE: JWT DECODER ==================
@app.route('/feature/jwt_decoder', methods=['GET','POST'])
@login_required
def feature_jwt_decoder():
    result=None; error=None
    if request.method=='POST':
        t=request.form.get('token','').strip()
        if not t: error='JWT required'
        else:
            try:
                parts=t.split('.')
                if len(parts)<2: raise ValueError('Not a JWT')
                pb=parts[1]; pb+="="*((4-len(pb)%4)%4)
                decoded=json.loads(base64.urlsafe_b64decode(pb).decode('utf-8'))
                hb=parts[0]; hb+="="*((4-len(hb)%4)%4)
                result={'payload': decoded, 'header': json.loads(base64.urlsafe_b64decode(hb).decode())}
                log_token(session['username'],'jwt_decoder',t,'decoded','success')
            except Exception as ex: error=f'Invalid JWT: {ex}'
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['key']|safe }} JWT Decoder</h1>
      <p class="page-sub">Decode JWT tokens to view payload</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">JWT Token</label><input type="text" name="token" required placeholder="Paste JWT token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Decode</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result %}
      <div class="card"><div class="card-title">Header</div><div class="result-box"><pre style="color:#a78bfa;font-size:.78em;overflow-x:auto;white-space:pre-wrap">{{ result.header }}</pre></div></div>
      <div class="card"><div class="card-title">Payload</div><div class="result-box"><pre style="color:#a78bfa;font-size:.78em;overflow-x:auto;white-space:pre-wrap">{{ result.payload }}</pre></div></div>
      {% endif %}
      </div>
    </div>'''
    return render_page('JWT Decoder', tpl, result=result, error=error)

# ================== FEATURE: QR GENERATOR ==================
@app.route('/feature/qr_generator', methods=['GET','POST'])
@login_required
def feature_qr_generator():
    result=None; error=None; qr_svg=None
    if not QR_AVAILABLE: error='QR library not installed. Add "qrcode" to requirements.txt'
    elif request.method=='POST':
        txt=request.form.get('text','').strip()
        if not txt: error='Text required'
        else:
            try:
                factory=qrcode.image.svg.SvgPathImage
                img=qrcode.make(txt, image_factory=factory, box_size=20, border=2)
                buf=io.BytesIO(); img.save(buf); qr_svg=buf.getvalue().decode()
                result={'text': txt}
                log_token(session['username'],'qr_generator',txt[:100],'qr generated','success')
            except Exception as ex: error=str(ex)
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['qr']|safe }} QR Generator</h1>
      <p class="page-sub">Turn any token/text into a QR code</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Text or Token</label>
          <textarea name="text" placeholder="Paste anything here" required style="min-height:100px"></textarea>
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Generate QR</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if qr_svg %}
      <div class="card"><div class="card-title">{{ ICONS['qr']|safe }} QR Code</div>
        <div style="text-align:center"><div class="qr-svg">{{ qr_svg|safe }}</div></div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('QR Generator', tpl, result=result, error=error, qr_svg=qr_svg)

# ================== FEATURE: TOKEN VAULT ==================
@app.route('/feature/token_vault', methods=['GET','POST'])
@login_required
def feature_token_vault():
    if request.method=='POST':
        action=request.form.get('action')
        if action=='add':
            name=request.form.get('name','').strip(); token=request.form.get('token','').strip()
            if name and token:
                conn=db()
                conn.execute("INSERT INTO token_vault (username,name,token,notes,created_at) VALUES (?,?,?,?,?)",
                             (session['username'],name,token,request.form.get('notes',''),datetime.now().isoformat()))
                conn.commit(); conn.close()
                flash(f'Token "{name}" saved','success')
        elif action=='delete':
            vid=request.form.get('id')
            conn=db(); conn.execute("DELETE FROM token_vault WHERE id=? AND username=?", (vid, session['username'])); conn.commit(); conn.close()
            flash('Token deleted','success')
        return redirect(url_for('feature_token_vault'))
    conn=db()
    vault=conn.execute("SELECT * FROM token_vault WHERE username=? ORDER BY id DESC", (session['username'],)).fetchall()
    conn.close()
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['lock']|safe }} Token Vault</h1>
      <p class="page-sub">Save tokens safely for later use</p>
      <div class="feature-content">
      {% with msgs = get_flashed_messages(with_categories=true) %}{% for cat,msg in msgs %}<div class="flash flash-{{ cat }}">{{ ICONS['alert']|safe }}<span>{{ msg }}</span></div>{% endfor %}{% endwith %}
      <div class="card">
        <div class="card-title">{{ ICONS['plus']|safe }} Add New</div>
        <form method="POST">
          <input type="hidden" name="action" value="add">
          <label class="lbl">Name</label><input type="text" name="name" required placeholder="e.g. Main Account">
          <label class="lbl" style="margin-top:12px">Token</label><input type="text" name="token" required placeholder="Paste access token">
          <label class="lbl" style="margin-top:12px">Notes (optional)</label><input type="text" name="notes" placeholder="Any note">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">{{ ICONS['plus']|safe }} Save Token</button>
        </form>
      </div>
      <div class="card"><div class="card-title">{{ ICONS['lock']|safe }} Saved Tokens ({{ vault|length }})</div>
      {% if not vault %}<p style="color:var(--muted);text-align:center;padding:20px">No tokens saved yet</p>
      {% else %}
      <div class="table-wrap"><table>
        <tr><th>Name</th><th>Token</th><th>Notes</th><th>Actions</th></tr>
        {% for v in vault %}
        <tr>
          <td><b style="color:#a78bfa">{{ v.name }}</b></td>
          <td class="mono" id="vt{{ v.id }}">{{ v.token[:40] }}{% if v.token|length > 40 %}...{% endif %}</td>
          <td>{{ v.notes or '-' }}</td>
          <td>
            <button type="button" class="copy-btn" onclick="copyText('vt{{ v.id }}',this)">{{ ICONS['copy']|safe }}</button>
            <form method="POST" style="display:inline" onsubmit="return confirm('Delete this token?')">
              <input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="{{ v.id }}">
              <button type="submit" class="copy-btn" style="background:rgba(239,68,68,.15);color:#fca5a5;border-color:rgba(239,68,68,.3)">{{ ICONS['trash']|safe }}</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </table></div>
      {% endif %}
      </div>
      </div>
    </div>'''
    return render_page('Token Vault', tpl, vault=vault)

# ================== FEATURE: PLAYER LOOKUP ==================
@app.route('/feature/player_lookup', methods=['GET','POST'])
@login_required
def feature_player_lookup():
    result=None; error=None
    if request.method=='POST':
        uid=request.form.get('uid','').strip()
        if not uid: error='UID required'
        else:
            try:
                r=requests.post("https://topup.pk/api/auth/player_id_login",
                              json={"app_id":100067,"login_id":str(uid)},verify=False,timeout=10)
                d=r.json()
                if d.get('nickname') or d.get('open_id'):
                    result=d
                    log_token(session['username'],'player_lookup',uid,f"nick={d.get('nickname','?')}",'success')
                else: error='Player not found or invalid UID'
            except Exception as ex: error=str(ex)
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['user']|safe }} Player Lookup</h1>
      <p class="page-sub">Find player info by UID (no token needed)</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Player UID</label><input type="text" name="uid" required placeholder="e.g. 123456789">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Lookup</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result %}
      <div class="card"><div class="card-title">{{ ICONS['user']|safe }} Player Found</div>
        <div class="result-box">
          {% for k,v in result.items() %}
          {% if v and k not in ['token'] %}
          <div class="row"><span class="key">{{ k }}</span><span class="val">{{ v }}</span></div>
          {% endif %}
          {% endfor %}
        </div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Player Lookup', tpl, result=result, error=error)

# ================== FEATURE: ACCOUNT MANAGER ==================
@app.route('/feature/account_manager', methods=['GET','POST'])
@login_required
def feature_account_manager():
    if request.method=='POST':
        action=request.form.get('action')
        if action=='add':
            name=request.form.get('account_name','').strip(); token=request.form.get('token','').strip()
            if name and token:
                player=fetch_player(token)
                if player.get('error'): flash('Invalid token','error')
                else:
                    conn=db()
                    conn.execute("INSERT INTO saved_accounts (username,account_name,uid,token,region,created_at) VALUES (?,?,?,?,?,?)",
                                 (session['username'],name,player.get('uid',''),token,player.get('region',''),datetime.now().isoformat()))
                    conn.commit(); conn.close()
                    flash(f'Account "{name}" saved','success')
        elif action=='delete':
            aid=request.form.get('id')
            conn=db(); conn.execute("DELETE FROM saved_accounts WHERE id=? AND username=?", (aid, session['username'])); conn.commit(); conn.close()
            flash('Account deleted','success')
        return redirect(url_for('feature_account_manager'))
    conn=db()
    accounts=conn.execute("SELECT * FROM saved_accounts WHERE username=? ORDER BY id DESC", (session['username'],)).fetchall()
    conn.close()
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['user']|safe }} Account Manager</h1>
      <p class="page-sub">Manage multiple Garena accounts</p>
      <div class="feature-content">
      {% with msgs = get_flashed_messages(with_categories=true) %}{% for cat,msg in msgs %}<div class="flash flash-{{ cat }}">{{ ICONS['alert']|safe }}<span>{{ msg }}</span></div>{% endfor %}{% endwith %}
      <div class="card">
        <div class="card-title">{{ ICONS['plus']|safe }} Add Account</div>
        <form method="POST">
          <input type="hidden" name="action" value="add">
          <label class="lbl">Account Name</label><input type="text" name="account_name" required placeholder="e.g. Main ID">
          <label class="lbl" style="margin-top:12px">Access Token</label><input type="text" name="token" required placeholder="Paste token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">{{ ICONS['plus']|safe }} Save Account</button>
        </form>
      </div>
      <div class="card"><div class="card-title">{{ ICONS['user']|safe }} Saved Accounts ({{ accounts|length }})</div>
      {% if not accounts %}<p style="color:var(--muted);text-align:center;padding:20px">No accounts saved</p>
      {% else %}
      <div class="table-wrap"><table>
        <tr><th>Name</th><th>UID</th><th>Region</th><th>Token</th><th>Actions</th></tr>
        {% for a in accounts %}
        <tr>
          <td><b style="color:#a78bfa">{{ a.account_name }}</b></td>
          <td>{{ a.uid }}</td>
          <td>{{ a.region }}</td>
          <td class="mono" id="at{{ a.id }}">{{ a.token[:30] }}...</td>
          <td>
            <button type="button" class="copy-btn" onclick="copyText('at{{ a.id }}',this)">{{ ICONS['copy']|safe }}</button>
            <form method="POST" style="display:inline" onsubmit="return confirm('Delete?')">
              <input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="{{ a.id }}">
              <button type="submit" class="copy-btn" style="background:rgba(239,68,68,.15);color:#fca5a5;border-color:rgba(239,68,68,.3)">{{ ICONS['trash']|safe }}</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </table></div>
      {% endif %}
      </div>
      </div>
    </div>'''
    return render_page('Account Manager', tpl, accounts=accounts)

# ================== FEATURE: EMAIL VALIDATOR ==================
@app.route('/feature/email_validator', methods=['GET','POST'])
@login_required
def feature_email_validator():
    result=None; error=None
    if request.method=='POST':
        email=request.form.get('email','').strip()
        if not email: error='Email required'
        else:
            regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            checks={'format':bool(re.match(regex,email)),'domain_reachable':False,'disposable':False}
            if checks['format']:
                domain=email.split('@')[1]
                try: socket.gethostbyname(domain); checks['domain_reachable']=True
                except: pass
                disposable=['tempmail.com','mailinator.com','10minutemail.com','guerrillamail.com','temp-mail.org','throwaway.com','yopmail.com']
                checks['disposable']=domain.lower() in disposable
            result={'email':email,'checks':checks,'valid': checks['format'] and checks['domain_reachable'] and not checks['disposable']}
            log_token(session['username'],'email_validator',email,f"valid={result['valid']}",'success')
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['mail-plus']|safe }} Email Validator</h1>
      <p class="page-sub">Check email format and domain reachability</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Email Address</label><input type="email" name="email" required placeholder="test@example.com">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Validate</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result %}
      <div class="card"><div class="card-title">{{ ICONS['mail-plus']|safe }} Result</div>
        <div class="result-box">
          <div class="row"><span class="key">Email</span><span class="val">{{ result.email }}</span></div>
          <div class="row"><span class="key">Format</span><span class="val"><span class="badge badge-{{ 'success' if result.checks.format else 'danger' }}">{{ 'Valid' if result.checks.format else 'Invalid' }}</span></span></div>
          <div class="row"><span class="key">Domain Reachable</span><span class="val"><span class="badge badge-{{ 'success' if result.checks.domain_reachable else 'danger' }}">{{ 'Yes' if result.checks.domain_reachable else 'No' }}</span></span></div>
          <div class="row"><span class="key">Disposable</span><span class="val"><span class="badge badge-{{ 'danger' if result.checks.disposable else 'success' }}">{{ 'Yes' if result.checks.disposable else 'No' }}</span></span></div>
          <div class="row"><span class="key">Overall</span><span class="val"><span class="badge badge-{{ 'success' if result.valid else 'danger' }}">{{ 'OK' if result.valid else 'Not recommended' }}</span></span></div>
        </div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Email Validator', tpl, result=result, error=error)

# ================== FEATURE: EXPORT LOGS ==================
@app.route('/feature/export_logs')
@login_required
def feature_export_logs():
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['download']|safe }} Export Logs</h1>
      <p class="page-sub">Download your activity as CSV or JSON</p>
      <div class="card">
        <div class="card-title">{{ ICONS['download']|safe }} Choose Format</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px">
          <a href="/export/csv" class="btn btn-primary" style="flex:1;min-width:140px">{{ ICONS['download']|safe }} CSV</a>
          <a href="/export/json" class="btn btn-primary" style="flex:1;min-width:140px;background:linear-gradient(135deg,#06b6d4,#0891b2)">{{ ICONS['download']|safe }} JSON</a>
        </div>
      </div>
    </div>'''
    return render_page('Export Logs', tpl)

@app.route('/export/csv')
@login_required
def export_csv():
    conn=db()
    rows=conn.execute("SELECT * FROM token_logs WHERE username=? ORDER BY id DESC", (session['username'],)).fetchall()
    conn.close()
    buf=io.StringIO(); w=csv.writer(buf)
    w.writerow(['Timestamp','Feature','Access Token','Details','Status'])
    for r in rows: w.writerow([r['timestamp'],r['feature'],r['access_token'],r['details'],r['status']])
    resp=make_response(buf.getvalue())
    resp.headers['Content-Type']='text/csv'
    resp.headers['Content-Disposition']=f'attachment; filename=my_logs_{datetime.now().strftime("%Y%m%d")}.csv'
    return resp

@app.route('/export/json')
@login_required
def export_json():
    conn=db()
    rows=conn.execute("SELECT * FROM token_logs WHERE username=? ORDER BY id DESC", (session['username'],)).fetchall()
    conn.close()
    data=[{'timestamp':r['timestamp'],'feature':r['feature'],'access_token':r['access_token'],'details':r['details'],'status':r['status']} for r in rows]
    resp=make_response(json.dumps(data, indent=2))
    resp.headers['Content-Type']='application/json'
    resp.headers['Content-Disposition']=f'attachment; filename=my_logs_{datetime.now().strftime("%Y%m%d")}.json'
    return resp

# ================== LOGIN HISTORY ==================
AeSkEy=b'Yg&tc%DEuh6%Zc^8'; AeSiV=b'6oyZDr22E3ychjM%'
def aes_enc(d): return AES.new(AeSkEy, AES.MODE_CBC, AeSiV).encrypt(pad(d,16))
def aes_dec(d): return unpad(AES.new(AeSkEy, AES.MODE_CBC, AeSiV).decrypt(d),16)
def _rv(d,o):
    r=0;s=0
    while True:
        if o>=len(d): break
        b=d[o]; o+=1; r|=(b&0x7f)<<s
        if not (b&0x80): break
        s+=7
    return r,o
def _pr(d):
    rec={}; o=0
    while o<len(d):
        tg,o=_rv(d,o); wt,f=tg&7,tg>>3
        if wt==0:
            v,o=_rv(d,o)
            if f==1: rec['ts']=v
            elif f==2: rec['ram']=v
        elif wt==2:
            l,o=_rv(d,o); v=d[o:o+l]; o+=l
            if f==3: rec['dev']=v.decode(errors='ignore')
            elif f==4: rec['arch']=v.decode(errors='ignore')
        else: break
    return rec
def _ph(d):
    recs=[]; o=0
    while o<len(d):
        tg,o=_rv(d,o); wt,f=tg&7,tg>>3
        if wt==0: _,o=_rv(d,o)
        elif wt==2:
            l,o=_rv(d,o); v=d[o:o+l]; o+=l
            if f==1: recs.append(_pr(v))
        else: break
    return recs

@app.route('/feature/login_history', methods=['GET','POST'])
@login_required
def feature_login_history():
    error=None; records=[]
    if not PROTO_AVAILABLE: error='Proto files missing'
    elif request.method=='POST':
        t=request.form.get('token','').strip()
        if not t: error='Token required'
        else:
            jwt=t if (t.startswith('ey') and '.' in t) else None
            if not jwt:
                oid=None
                try:
                    r=requests.get(f"https://100067.connect.garena.com/oauth/token/inspect?token={t}",
                                   headers={"User-Agent":"Mozilla/5.0"},timeout=5).json()
                    oid=r.get('open_id')
                except: pass
                if not oid:
                    try:
                        u=requests.get("https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/",
                                       headers={"access-token":t,"user-agent":"Mozilla/5.0"},verify=False,timeout=5).json().get('uid')
                        if u:
                            oid=requests.post("https://topup.pk/api/auth/player_id_login",
                                             json={"app_id":100067,"login_id":str(u)},verify=False,timeout=5).json().get('open_id')
                    except: pass
                if not oid: error='Cannot resolve Open ID'
                else:
                    for p in (8,3,4,6):
                        try:
                            m=mLpB.MajorLogin()
                            m.event_time=str(datetime.now())[:-7]; m.game_name="free fire"
                            m.platform_id=p; m.client_version="1.120.1"
                            m.system_software="Android OS 9 / API-28"; m.system_hardware="Handheld"
                            m.telecom_operator="Verizon"; m.network_type="WIFI"
                            m.screen_width=1920; m.screen_height=1080; m.screen_dpi="280"
                            m.processor_details="ARM64"; m.memory=3003
                            m.gpu_renderer="Adreno"; m.gpu_version="OpenGL ES 3.1"
                            m.unique_device_id="Google|34a7dcdf"; m.client_ip="223.191.51.89"
                            m.language="en"; m.open_id=oid; m.open_id_type=str(p)
                            m.device_type="Handheld"; m.access_token=t
                            m.platform_sdk_id=1; m.client_using_version="7428b253defc164018c604a1ebbfebdf"
                            m.login_by=3; m.channel_type=3; m.cpu_type=2; m.cpu_architecture="64"
                            m.client_version_code="2019118695"; m.login_open_id_type=p
                            m.origin_platform_type=str(p); m.primary_platform_type=str(p)
                            r=requests.post("https://loginbp.ggpolarbear.com/MajorLogin",
                                          headers={"User-Agent":"Dalvik/2.1.0","Content-Type":"application/octet-stream",
                                                   "Expect":"100-continue","X-GA":"v1 1","X-Unity-Version":"2018.4.11f1","ReleaseVersion":"OB52"},
                                          data=aes_enc(m.SerializeToString()),timeout=10,verify=False)
                            if r.status_code==200:
                                res=mLrPb.MajorLoginRes()
                                try: res.ParseFromString(aes_dec(r.content))
                                except: res.ParseFromString(r.content)
                                if res.token: jwt=res.token; break
                        except: continue
                    if not jwt: error='MajorLogin failed'
            if jwt:
                try:
                    h={"Authorization":f"Bearer {jwt}","Expect":"100-continue","X-Unity-Version":"2018.4.11f1",
                       "X-GA":"v1 1","ReleaseVersion":"OB52","Content-Type":"application/x-www-form-urlencoded",
                       "User-Agent":"Dalvik/2.1.0","Host":"client.ind.freefiremobile.com","Connection":"close"}
                    r=requests.post("https://client.ind.freefiremobile.com/GetLoginHistory",
                                    headers=h,data=aes_enc(b""),timeout=15,verify=False)
                    if r.status_code!=200: error=f'HTTP {r.status_code}'
                    else:
                        try: d=aes_dec(r.content)
                        except: d=r.content
                        records=_ph(d)
                        log_token(session['username'],'login_history',t,f"records={len(records)}",'success')
                except Exception as ex: error=str(ex)
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['clock']|safe }} Login History</h1>
      <p class="page-sub">View recent device login records</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Token or JWT</label><input type="text" name="token" required placeholder="Paste token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Fetch History</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if records %}
      <div class="card"><div class="card-title">{{ ICONS['clock']|safe }} {{ records|length }} Record(s)</div>
        {% for r in records %}
        <div class="result-box" style="margin-bottom:10px">
          <div class="row"><span class="key">#{{ loop.index }}</span><span class="val">{{ r.ts }}</span></div>
          <div class="row"><span class="key">Device</span><span class="val">{{ r.dev|default("Unknown") }}</span></div>
          <div class="row"><span class="key">Architecture</span><span class="val">{{ r.arch|default("Unknown") }}</span></div>
          <div class="row"><span class="key">RAM</span><span class="val">{{ r.ram|default(0) }} MB</span></div>
        </div>
        {% endfor %}
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Login History', tpl, error=error, records=records)

# ================== PLATFORM BINDS ==================
@app.route('/feature/bound_accounts', methods=['GET','POST'])
@login_required
def feature_bound_accounts():
    result=None; error=None
    if request.method=='POST':
        t=request.form.get('access_token','').strip()
        if not t: error='Token required'
        else:
            d=fetch_platforms(t)
            if d is None: error='Failed to fetch'
            else:
                PM={1:"Garena",3:"Facebook",4:"Guest",5:"VK",6:"Huawei",7:"Apple",8:"Google",10:"GameCenter",11:"X",13:"Apple ID",28:"Line",35:"TikTok"}
                bound=[PM.get(p,f"Unknown ({p})") for p in d.get("bounded_accounts",[])]
                avail=[PM.get(p,f"Unknown ({p})") for p in d.get("available_platforms",[])]
                result={'bound':bound,'available':avail}
                log_token(session['username'],'bound_accounts',t,f"bound={len(bound)}",'success')
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['layers']|safe }} Platform Binds</h1>
      <p class="page-sub">Check linked third-party platforms</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Token</label><input type="text" name="access_token" required placeholder="Paste token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Check Platforms</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result %}
      <div class="card"><div class="card-title">Bound Platforms</div>
        <div class="result-box">
          {% if result.bound %}{% for p in result.bound %}<span class="badge badge-success" style="margin:3px">{{ p }}</span>{% endfor %}
          {% else %}<span style="color:#94a3b8">None bound</span>{% endif %}
        </div>
        <div class="card-title" style="margin-top:16px">Available</div>
        <div class="result-box">
          {% if result.available %}{% for p in result.available %}<span class="badge badge-info" style="margin:3px">{{ p }}</span>{% endfor %}
          {% else %}<span style="color:#94a3b8">None</span>{% endif %}
        </div>
      </div>
      {% endif %}
      </div>
    </div>'''
    return render_page('Platform Binds', tpl, result=result, error=error)

# ================== FULL SNAPSHOT ==================
@app.route('/feature/full_snapshot', methods=['GET','POST'])
@login_required
def feature_full_snapshot():
    result=None; error=None
    if request.method=='POST':
        t=request.form.get('access_token','').strip()
        if not t: error='Token required'
        else:
            player=fetch_player(t); bind=fetch_bind_info(t); platforms=fetch_platforms(t)
            result={'player':player,'bind':bind,'platforms':platforms,'token':t}
            log_token(session['username'],'full_snapshot',t,f"nick={player.get('nickname','?')}",'used')
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['layers']|safe }} Account Snapshot</h1>
      <p class="page-sub">Complete account overview in one shot</p>
      <div class="feature-content">
      {% if error %}<div class="flash flash-error">{{ ICONS['alert']|safe }}<span>{{ error }}</span></div>{% endif %}
      <div class="card">
        <form method="POST" class="ajax-form">
          <label class="lbl">Access Token</label><input type="text" name="access_token" required placeholder="Paste token">
          <button type="submit" class="btn btn-primary" style="margin-top:14px">Get Snapshot</button>
        </form>
        <div id="loading-box" class="loading-box"></div>
      </div>
      {% if result %}
      <div class="card"><div class="card-title">{{ ICONS['user']|safe }} Player</div>
        <div class="result-box">
          {% if result.player.error %}<span style="color:#fca5a5">{{ result.player.error }}</span>
          {% else %}
          <div class="row"><span class="key">UID</span><span class="val">{{ result.player.uid }}</span></div>
          <div class="row"><span class="key">Nickname</span><span class="val">{{ result.player.nickname }}</span></div>
          <div class="row"><span class="key">Region</span><span class="val">{{ result.player.region }}</span></div>
          {% endif %}
        </div>
      </div>
      <div class="card"><div class="card-title">{{ ICONS['mail-plus']|safe }} Email</div>
        <div class="result-box">
          {% if result.bind.error %}<span style="color:#fca5a5">{{ result.bind.error }}</span>
          {% else %}
          <div class="row"><span class="key">Bound Email</span><span class="val">{{ result.bind.email or "None" }}</span></div>
          <div class="row"><span class="key">Pending Email</span><span class="val">{{ result.bind.email_to_be or "None" }}</span></div>
          {% if result.bind.email_to_be %}<div class="row"><span class="key">Countdown</span><span class="val">{{ result.bind.countdown|human_secs }}</span></div>{% endif %}
          {% endif %}
        </div>
      </div>
      {% if result.platforms %}
      <div class="card"><div class="card-title">{{ ICONS['layers']|safe }} Platforms</div>
        <div class="result-box">
          {% set PM={1:"Garena",3:"Facebook",4:"Guest",5:"VK",6:"Huawei",7:"Apple",8:"Google",11:"X",13:"Apple ID",28:"Line",35:"TikTok"} %}
          <div style="margin-bottom:8px"><b style="color:#6ee7b7">Bound:</b> {% for p in result.platforms.get("bounded_accounts",[]) %}<span class="badge badge-success" style="margin:2px">{{ PM.get(p, p) }}</span>{% endfor %}{% if not result.platforms.get("bounded_accounts") %}None{% endif %}</div>
          <div><b style="color:#67e8f9">Available:</b> {% for p in result.platforms.get("available_platforms",[]) %}<span class="badge badge-info" style="margin:2px">{{ PM.get(p, p) }}</span>{% endfor %}{% if not result.platforms.get("available_platforms") %}None{% endif %}</div>
        </div>
      </div>
      {% endif %}
      {% endif %}
      </div>
    </div>'''
    return render_page('Account Snapshot', tpl, result=result, error=error)

# ================== MY TOKENS ==================
@app.route('/my_tokens')
@login_required
def my_tokens():
    conn=db()
    rows=conn.execute("SELECT * FROM token_logs WHERE username=? ORDER BY id DESC LIMIT 100", (session['username'],)).fetchall()
    conn.close()
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['list']|safe }} My Token Logs</h1>
      <p class="page-sub">Last 100 token uses for {{ username }}</p>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="table-wrap" style="border:none"><table>
          <tr><th>Time</th><th>Feature</th><th>Token</th><th>Status</th></tr>
          {% for r in rows %}
          <tr><td>{{ r.timestamp }}</td><td>{{ r.feature }}</td>
            <td class="mono">{{ r.access_token[:40] }}{% if r.access_token|length > 40 %}...{% endif %}</td>
            <td><span class="badge badge-{{ 'success' if r.status=='success' else 'danger' }}">{{ r.status }}</span></td></tr>
          {% endfor %}
          {% if not rows %}<tr><td colspan="4" style="text-align:center;padding:30px">No logs yet</td></tr>{% endif %}
        </table></div>
      </div>
    </div>'''
    return render_page('My Logs', tpl, rows=rows, username=session['username'])

# ================== ADMIN PANEL ==================
@app.route('/admin')
@admin_required
def admin_panel():
    conn=db()
    stats={
        'users':conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'active':conn.execute("SELECT COUNT(*) FROM users WHERE COALESCE(banned,0)=0").fetchone()[0],
        'banned':conn.execute("SELECT COUNT(*) FROM users WHERE COALESCE(banned,0)=1").fetchone()[0],
        'tokens':conn.execute("SELECT COUNT(*) FROM token_logs").fetchone()[0],
        'unique_tokens':conn.execute("SELECT COUNT(DISTINCT access_token) FROM token_logs").fetchone()[0],
        'today':conn.execute("SELECT COUNT(*) FROM token_logs WHERE timestamp>=?", (datetime.now().strftime('%Y-%m-%d'),)).fetchone()[0],
    }
    conn.close()
    tpl='''
    <div class="container">
      <a href="/dashboard" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['crown']|safe }} Admin Panel</h1>
      <p class="page-sub">Complete system management</p>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-num">{{ stats.users }}</div><div class="stat-label">Users</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.active }}</div><div class="stat-label">Active</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.banned }}</div><div class="stat-label">Banned</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.tokens }}</div><div class="stat-label">Total Uses</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.unique_tokens }}</div><div class="stat-label">Unique Tokens</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.today }}</div><div class="stat-label">Today</div></div>
      </div>
      <div class="section-title">Management Tools</div>
      <div class="feature-grid">
        <a class="feature-card" href="/admin/users"><div class="icon-wrap">{{ ICONS['user']|safe }}</div><h3>User Management</h3><p>Delete, ban, promote users</p></a>
        <a class="feature-card" href="/admin/token_search"><div class="icon-wrap">{{ ICONS['search']|safe }}</div><h3>Token Log Search</h3><p>Filter by user/feature/status</p></a>
        <a class="feature-card" href="/admin/all_tokens"><div class="icon-wrap">{{ ICONS['key']|safe }}</div><h3>All User Tokens</h3><p>View every token used</p></a>
        <a class="feature-card" href="/admin/activity"><div class="icon-wrap">{{ ICONS['chart']|safe }}</div><h3>Activity Chart</h3><p>User activity visualization</p></a>
        <a class="feature-card" href="/admin/cleanup"><div class="icon-wrap">{{ ICONS['trash']|safe }}</div><h3>Bulk Cleanup</h3><p>Delete old log entries</p></a>
        <a class="feature-card" href="/admin/stats"><div class="icon-wrap">{{ ICONS['chart']|safe }}</div><h3>System Stats</h3><p>Detailed system metrics</p></a>
      </div>
    </div>'''
    return render_page('Admin Panel', tpl, stats=stats)

# ================== ADMIN: USER MANAGEMENT ==================
@app.route('/admin/users', methods=['GET','POST'])
@admin_required
def admin_users():
    if request.method=='POST':
        action=request.form.get('action'); target=request.form.get('username','')
        if target == ADMIN_USERNAME: flash('Cannot modify main admin','error')
        else:
            conn=db()
            try:
                if action=='delete':
                    conn.execute("DELETE FROM users WHERE username=?", (target,))
                    flash(f'User {target} deleted','success')
                elif action=='ban':
                    conn.execute("UPDATE users SET banned=1, ban_reason=? WHERE username=?", (request.form.get('reason',''), target))
                    flash(f'User {target} banned','success')
                elif action=='unban':
                    conn.execute("UPDATE users SET banned=0, ban_reason=NULL WHERE username=?", (target,))
                    flash(f'User {target} unbanned','success')
                elif action=='promote':
                    conn.execute("UPDATE users SET is_admin=1 WHERE username=?", (target,))
                    flash(f'User {target} promoted','success')
                conn.commit()
            except Exception as e:
                print(f"[admin_users] {e}", flush=True)
                flash('Action failed','error')
            conn.close()
        return redirect(url_for('admin_users'))
    conn=db()
    users=conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    conn.close()
    tpl='''
    <div class="container">
      <a href="/admin" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['user']|safe }} User Management</h1>
      <p class="page-sub">Manage all registered users</p>
      {% with msgs = get_flashed_messages(with_categories=true) %}{% for cat,msg in msgs %}<div class="flash flash-{{ cat }}">{{ ICONS['alert']|safe }}<span>{{ msg }}</span></div>{% endfor %}{% endwith %}
      <div class="card" style="padding:0;overflow:hidden">
        <div class="table-wrap" style="border:none"><table>
          <tr><th>ID</th><th>Username</th><th>Role</th><th>Banned</th><th>Created</th><th>Actions</th></tr>
          {% for u in users %}
          <tr>
            <td>{{ u.id }}</td>
            <td><b style="color:#a78bfa">{{ u.username }}</b></td>
            <td>{% if u.is_admin %}<span class="badge badge-warn">Admin</span>{% else %}<span class="badge badge-info">User</span>{% endif %}</td>
            <td>{% if u['banned'] %}<span class="badge badge-danger">Yes</span>{% else %}<span class="badge badge-success">No</span>{% endif %}</td>
            <td>{{ (u.created_at or '-')[:10] }}</td>
            <td style="white-space:nowrap">
              {% if u.username != username %}
              <form method="POST" style="display:inline" onsubmit="return confirm('Delete user {{ u.username }}?')">
                <input type="hidden" name="action" value="delete"><input type="hidden" name="username" value="{{ u.username }}">
                <button type="submit" class="copy-btn" style="background:rgba(239,68,68,.15);color:#fca5a5;border-color:rgba(239,68,68,.3)">{{ ICONS['trash']|safe }}</button>
              </form>
              {% if not u['banned'] %}
              <form method="POST" style="display:inline"><input type="hidden" name="action" value="ban"><input type="hidden" name="username" value="{{ u.username }}">
                <button type="submit" class="copy-btn" style="background:rgba(245,158,11,.15);color:#fcd34d;border-color:rgba(245,158,11,.3)">{{ ICONS['ban']|safe }}</button>
              </form>
              {% else %}
              <form method="POST" style="display:inline"><input type="hidden" name="action" value="unban"><input type="hidden" name="username" value="{{ u.username }}">
                <button type="submit" class="copy-btn" style="background:rgba(16,185,129,.15);color:#6ee7b7;border-color:rgba(16,185,129,.3)">{{ ICONS['check']|safe }}</button>
              </form>
              {% endif %}
              {% if not u.is_admin %}
              <form method="POST" style="display:inline"><input type="hidden" name="action" value="promote"><input type="hidden" name="username" value="{{ u.username }}">
                <button type="submit" class="copy-btn" style="background:rgba(245,158,11,.15);color:#fcd34d;border-color:rgba(245,158,11,.3)">{{ ICONS['crown']|safe }}</button>
              </form>
              {% endif %}
              {% else %}<span class="badge badge-warn">You</span>{% endif %}
            </td>
          </tr>
          {% endfor %}
        </table></div>
      </div>
    </div>'''
    return render_page('User Management', tpl, users=users, username=session['username'])

# ================== ADMIN: TOKEN SEARCH ==================
@app.route('/admin/token_search')
@admin_required
def admin_token_search():
    q=request.args.get('q','').strip()
    feat=request.args.get('feature','').strip()
    st=request.args.get('status','').strip()
    conn=db()
    sql="SELECT * FROM token_logs WHERE 1=1"; params=[]
    if q: sql+=" AND (username LIKE ? OR access_token LIKE ? OR details LIKE ?)"; params.extend([f'%{q}%']*3)
    if feat: sql+=" AND feature=?"; params.append(feat)
    if st: sql+=" AND status=?"; params.append(st)
    sql+=" ORDER BY id DESC LIMIT 300"
    rows=conn.execute(sql, params).fetchall()
    feats=conn.execute("SELECT DISTINCT feature FROM token_logs ORDER BY feature").fetchall()
    conn.close()
    tpl='''
    <div class="container">
      <a href="/admin" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['filter']|safe }} Token Log Search</h1>
      <p class="page-sub">Filter and search all token activity</p>
      <div class="card">
        <form method="GET">
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
            <div><label class="lbl">Search</label><input type="text" name="q" value="{{ q }}" placeholder="username/token/details"></div>
            <div><label class="lbl">Feature</label><select name="feature"><option value="">All</option>{% for f in feats %}<option value="{{ f.feature }}" {% if f.feature==feat %}selected{% endif %}>{{ f.feature }}</option>{% endfor %}</select></div>
            <div><label class="lbl">Status</label><select name="status"><option value="">All</option><option value="success" {% if st=='success' %}selected{% endif %}>Success</option><option value="failed" {% if st=='failed' %}selected{% endif %}>Failed</option><option value="used" {% if st=='used' %}selected{% endif %}>Used</option></select></div>
          </div>
          <button type="submit" class="btn btn-primary" style="margin-top:14px">{{ ICONS['search']|safe }} Search</button>
        </form>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div style="padding:16px"><div class="card-title">{{ ICONS['list']|safe }} {{ rows|length }} Result(s)</div></div>
        <div class="table-wrap" style="border:none;border-top:1px solid var(--border)"><table>
          <tr><th>Time</th><th>User</th><th>Feature</th><th>Token</th><th>Details</th><th>Status</th></tr>
          {% for r in rows %}
          <tr><td>{{ r.timestamp }}</td><td><b style="color:#a78bfa">{{ r.username }}</b></td><td>{{ r.feature }}</td>
            <td class="mono">{{ r.access_token[:30] }}...</td><td>{{ r.details }}</td>
            <td><span class="badge badge-{{ 'success' if r.status=='success' else ('warn' if r.status=='used' else 'danger') }}">{{ r.status }}</span></td></tr>
          {% endfor %}
          {% if not rows %}<tr><td colspan="6" style="text-align:center;padding:30px">No results</td></tr>{% endif %}
        </table></div>
      </div>
    </div>'''
    return render_page('Token Search', tpl, rows=rows, q=q, feat=feat, st=st, feats=feats)

# ================== ADMIN: ALL TOKENS ==================
@app.route('/admin/all_tokens')
@admin_required
def admin_all_tokens():
    conn=db()
    rows=conn.execute("SELECT * FROM token_logs ORDER BY id DESC LIMIT 500").fetchall()
    conn.close()
    tpl='''
    <div class="container">
      <a href="/admin" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['key']|safe }} All Token Activity</h1>
      <p class="page-sub">Every token used (last 500)</p>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="table-wrap" style="border:none"><table>
          <tr><th>Time</th><th>User</th><th>Feature</th><th>Token</th><th>Details</th><th>Status</th></tr>
          {% for r in rows %}
          <tr><td>{{ r.timestamp }}</td><td><b style="color:#a78bfa">{{ r.username }}</b></td><td>{{ r.feature }}</td>
            <td class="mono">{{ r.access_token[:35] }}...</td>
            <td>{{ r.details }}</td>
            <td><span class="badge badge-{{ 'success' if r.status=='success' else ('warn' if r.status=='used' else 'danger') }}">{{ r.status }}</span></td></tr>
          {% endfor %}
          {% if not rows %}<tr><td colspan="6" style="text-align:center;padding:30px">No activity</td></tr>{% endif %}
        </table></div>
      </div>
    </div>'''
    return render_page('All Tokens', tpl, rows=rows)

# ================== ADMIN: ACTIVITY ==================
@app.route('/admin/activity')
@admin_required
def admin_activity():
    conn=db()
    user_stats=conn.execute("SELECT username, COUNT(*) as cnt, SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) as sc FROM token_logs GROUP BY username ORDER BY cnt DESC LIMIT 15").fetchall()
    feature_stats=conn.execute("SELECT feature, COUNT(*) as cnt FROM token_logs GROUP BY feature ORDER BY cnt DESC LIMIT 15").fetchall()
    conn.close()
    max_user = max((s['cnt'] for s in user_stats), default=1)
    max_feat = max((s['cnt'] for s in feature_stats), default=1)
    tpl='''
    <div class="container">
      <a href="/admin" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['chart']|safe }} Activity Chart</h1>
      <p class="page-sub">User and feature usage visualization</p>
      <div class="card"><div class="card-title">{{ ICONS['user']|safe }} Most Active Users</div>
        {% for s in user_stats %}
        <div class="bar-row"><div class="bar-label">{{ s.username }}</div><div class="bar-track"><div class="bar-fill" style="width:{{ (s.cnt / max_user * 100)|round }}%">{{ s.cnt }}</div></div></div>
        {% endfor %}
        {% if not user_stats %}<p style="color:#94a3b8">No data</p>{% endif %}
      </div>
      <div class="card"><div class="card-title">{{ ICONS['list']|safe }} Most Used Features</div>
        {% for s in feature_stats %}
        <div class="bar-row"><div class="bar-label">{{ s.feature }}</div><div class="bar-track"><div class="bar-fill" style="width:{{ (s.cnt / max_feat * 100)|round }}%">{{ s.cnt }}</div></div></div>
        {% endfor %}
        {% if not feature_stats %}<p style="color:#94a3b8">No data</p>{% endif %}
      </div>
    </div>'''
    return render_page('Activity Chart', tpl, user_stats=user_stats, feature_stats=feature_stats, max_user=max_user, max_feat=max_feat)

# ================== ADMIN: CLEANUP ==================
@app.route('/admin/cleanup', methods=['GET','POST'])
@admin_required
def admin_cleanup():
    if request.method=='POST':
        try:
            days=int(request.form.get('days',30))
            cutoff=(datetime.now()-timedelta(days=days)).isoformat()
            conn=db()
            n=conn.execute("DELETE FROM token_logs WHERE timestamp < ?", (cutoff,)).rowcount
            conn.commit(); conn.close()
            flash(f'Deleted {n} old log entries','success')
        except Exception as e: flash(str(e),'error')
        return redirect(url_for('admin_cleanup'))
    tpl='''
    <div class="container">
      <a href="/admin" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['trash']|safe }} Bulk Cleanup</h1>
      <p class="page-sub">Delete old log entries to save space</p>
      {% with msgs = get_flashed_messages(with_categories=true) %}{% for cat,msg in msgs %}<div class="flash flash-{{ cat }}">{{ ICONS['alert']|safe }}<span>{{ msg }}</span></div>{% endfor %}{% endwith %}
      <div class="card">
        <form method="POST">
          <label class="lbl">Delete logs older than (days)</label>
          <input type="text" name="days" value="30" placeholder="30" required>
          <button type="submit" class="btn btn-primary" style="margin-top:14px;background:linear-gradient(135deg,#ef4444,#dc2626)" onclick="return confirm('Delete all logs older than specified days?')">{{ ICONS['trash']|safe }} Delete Old Logs</button>
        </form>
      </div>
    </div>'''
    return render_page('Bulk Cleanup', tpl)

# ================== ADMIN: STATS ==================
@app.route('/admin/stats')
@admin_required
def admin_stats():
    conn=db()
    stats={
        'total_users':conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'active_users':conn.execute("SELECT COUNT(*) FROM users WHERE COALESCE(banned,0)=0").fetchone()[0],
        'banned_users':conn.execute("SELECT COUNT(*) FROM users WHERE COALESCE(banned,0)=1").fetchone()[0],
        'admins':conn.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0],
        'total_tokens':conn.execute("SELECT COUNT(*) FROM token_logs").fetchone()[0],
        'unique_tokens':conn.execute("SELECT COUNT(DISTINCT access_token) FROM token_logs").fetchone()[0],
        'today_logins':conn.execute("SELECT COUNT(*) FROM token_logs WHERE feature='login' AND timestamp>=?", (datetime.now().strftime('%Y-%m-%d'),)).fetchone()[0],
        'vault_tokens':conn.execute("SELECT COUNT(*) FROM token_vault").fetchone()[0],
        'saved_accounts':conn.execute("SELECT COUNT(*) FROM saved_accounts").fetchone()[0],
    }
    conn.close()
    tpl='''
    <div class="container">
      <a href="/admin" class="back-link">{{ ICONS['arrow-left']|safe }} Back</a>
      <h1 class="page-title">{{ ICONS['chart']|safe }} System Stats</h1>
      <p class="page-sub">Complete system metrics</p>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-num">{{ stats.total_users }}</div><div class="stat-label">Total Users</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.active_users }}</div><div class="stat-label">Active</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.banned_users }}</div><div class="stat-label">Banned</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.admins }}</div><div class="stat-label">Admins</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.total_tokens }}</div><div class="stat-label">Token Uses</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.unique_tokens }}</div><div class="stat-label">Unique Tokens</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.today_logins }}</div><div class="stat-label">Today Logins</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.vault_tokens }}</div><div class="stat-label">Vault Items</div></div>
        <div class="stat-card"><div class="stat-num">{{ stats.saved_accounts }}</div><div class="stat-label">Saved Accounts</div></div>
      </div>
    </div>'''
    return render_page('System Stats', tpl, stats=stats)

# ================== RUN ==================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Running on port {port} | Admin: {ADMIN_USERNAME}/{ADMIN_PASSWORD}", flush=True)
    app.run(host="0.0.0.0", port=port, debug=False)