"""
PHISH-NET SECURE BACKEND
========================
Security: JWT auth, bcrypt passwords, rate limiting, env-based secrets
Intel:    Real VirusTotal (URL), AbuseIPDB (IP), Google DNS
AI:       OpenAI GPT-4o in PentestGPT mode as JARVIS brain
Team:     Cases, notes, shared audit log
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import hashlib, socket, base64, json, re as _re, ssl, html, sqlite3, os
import urllib.request, urllib.error, urllib.parse
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# ── Optional heavy deps (graceful fallback if not installed) ──────────────────
try:
    import bcrypt
    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False

try:
    import jwt as pyjwt
    JWT_OK = True
except ImportError:
    JWT_OK = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_OK = True
except ImportError:
    LIMITER_OK = False

try:
    import openai
    OPENAI_OK = True
except ImportError:
    OPENAI_OK = False

load_dotenv()

# Serve frontend files from the same folder as app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")

# ── CORS ──────────────────────────────────────────────────────────────────────
allowed_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000"
).split(",")
CORS(app, origins=allowed_origins, supports_credentials=True)

# ── Secrets from .env ─────────────────────────────────────────────────────────
JWT_SECRET    = os.getenv("JWT_SECRET", "")
VT_API_KEY    = os.getenv("VT_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
OPENAI_KEY    = os.getenv("OPENAI_API_KEY", "")

# Auto-generate JWT secret if missing (dev mode). Set it in .env for production.
if not JWT_SECRET:
    import secrets as _sec
    JWT_SECRET = _sec.token_hex(32)
    print("[WARN] JWT_SECRET not in .env — generated temporary secret.")
    print("  Sessions reset on each restart. Add to .env to persist logins.")

# ── Rate limiting ─────────────────────────────────────────────────────────────
if LIMITER_OK:
    limiter = Limiter(get_remote_address, app=app, default_limits=["300 per day", "60 per hour"])
    def rl(limit): return limiter.limit(limit)
else:
    def rl(limit):
        def decorator(f): return f
        return decorator


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("phishnet.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role          TEXT DEFAULT 'analyst',
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        email          TEXT,
        action         TEXT,
        target         TEXT,
        result_summary TEXT,
        ip_address     TEXT,
        timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS cases (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        title       TEXT NOT NULL,
        description TEXT,
        severity    TEXT DEFAULT 'medium',
        status      TEXT DEFAULT 'open',
        created_by  TEXT,
        assigned_to TEXT,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS case_notes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id    INTEGER,
        author     TEXT,
        note       TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id)
    )""")
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect("phishnet.db")
    conn.row_factory = sqlite3.Row
    return conn

def log_action(email, action, target, summary="", ip=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (email, action, target, result_summary, ip_address) VALUES (?,?,?,?,?)",
        (email or "GUEST", action, str(target)[:200], str(summary)[:500], ip)
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    if BCRYPT_OK:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # Fallback: salted SHA-256 (install bcrypt for production!)
    salt = os.urandom(16).hex()
    return salt + ":" + hashlib.sha256((salt + password).encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    if BCRYPT_OK and stored_hash.startswith("$2"):
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    if ":" in stored_hash:
        salt, hashed = stored_hash.split(":", 1)
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    return hashlib.sha256(password.encode()).hexdigest() == stored_hash

def make_token(email: str, role: str) -> str:
    if not JWT_OK:
        return email
    payload = {
        "sub":  email,
        "role": role,
        "exp":  datetime.now(timezone.utc) + timedelta(hours=8),
        "iat":  datetime.now(timezone.utc),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    if not JWT_OK:
        return {"sub": token, "role": "analyst"}
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def get_operator(req) -> dict | None:
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return decode_token(auth[7:])
    return None

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        op = get_operator(request)
        if not op:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
# ── Health check (lets the frontend verify backend is alive) ──────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ai": bool(OPENAI_KEY), "vt": bool(VT_API_KEY)})


@app.route("/api/register", methods=["POST"])
@rl("10 per hour")
def register():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or "@" not in email:
        return jsonify({"status": "error", "message": "Valid email required."})
    if len(password) < 8:
        return jsonify({"status": "error", "message": "Password must be ≥ 8 characters."})

    try:
        conn = get_db()
        conn.execute("INSERT INTO users (email, password_hash) VALUES (?,?)",
                     (email, hash_password(password)))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Operator registered."})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Email already registered."})


@app.route("/api/login", methods=["POST"])
@rl("20 per hour")
def login():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"status": "error", "message": "Invalid credentials."})

    token = make_token(email, user["role"])
    log_action(email, "LOGIN", "", "success", request.remote_addr)
    return jsonify({"status": "success", "token": token, "email": email, "role": user["role"]})


# ─────────────────────────────────────────────────────────────────────────────
# JARVIS — OpenAI GPT-4o (PentestGPT mode)
# ─────────────────────────────────────────────────────────────────────────────
JARVIS_SYSTEM = """You are J.A.R.V.I.S., an elite autonomous SOC analyst and PentestGPT-powered cybersecurity assistant built into the Phish-Net platform.

Your role: Act as a tactical mentor for security analysts working on threat intelligence, incident response, CTF challenges, forensics, and penetration testing.

FORMATTING RULES — respond with HTML only, no markdown:
- Use <span class='text-yellow-muted font-bold'>[ADVISORY]</span> for section headers
- Use <span class='text-cyan-muted'>text</span> for general highlights and key terms
- Use <span class='text-green-muted'>text</span> for recommended commands and safe states
- Use <span class='text-red-muted'>text</span> for threats, warnings, malicious indicators
- Use <code>command</code> for all terminal commands
- Use <br><br> for paragraph breaks — no markdown, no backtick fences, no asterisks

Be concise, specific, and tactical. Always explain what a suggested command does and why."""


@app.route("/api/jarvis", methods=["POST"])
@require_auth
@rl("60 per hour")
def jarvis():
    operator = get_operator(request)
    data     = request.json or {}
    prompt   = data.get("prompt", "").strip()

    if not prompt:
        return jsonify({"status": "error", "message": "Empty prompt."})
    if len(prompt) > 4000:
        return jsonify({"status": "error", "message": "Prompt too long (max 4000 chars)."})

    if not OPENAI_KEY:
        fallback = _jarvis_fallback(prompt)
        return jsonify({
            "status":   "success",
            "response": fallback,
            "speech":   "Offline advisory mode active. Set OPENAI_API_KEY for full GPT-4o intelligence."
        })

    if not OPENAI_OK:
        return jsonify({
            "status":   "error",
            "response": "<span class='text-red-muted'>[-] openai package missing. Run: pip install openai</span>",
            "speech":   "OpenAI package not installed."
        })

    try:
        client     = openai.OpenAI(api_key=OPENAI_KEY)
        completion = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=1024,
            messages=[
                {"role": "system", "content": JARVIS_SYSTEM},
                {"role": "user",   "content": prompt}
            ]
        )
        response_text = completion.choices[0].message.content
        # Strip HTML tags for TTS
        speech_text = _re.sub(r"<[^>]+>", "", response_text)[:300].strip()

        log_action(operator["sub"] if operator else "GUEST",
                   "JARVIS", prompt[:100], "ok", request.remote_addr)
        return jsonify({"status": "success", "response": response_text, "speech": speech_text})

    except openai.AuthenticationError:
        return jsonify({
            "status":   "error",
            "response": "<span class='text-red-muted'>[-] Invalid OpenAI API key. Check OPENAI_API_KEY in .env</span>",
            "speech":   "Authentication error. Check your API key."
        })
    except openai.RateLimitError:
        return jsonify({
            "status":   "error",
            "response": "<span class='text-red-muted'>[-] OpenAI rate limit reached. Try again shortly.</span>",
            "speech":   "Rate limit reached."
        })
    except Exception as e:
        return jsonify({
            "status":   "error",
            "response": f"<span class='text-red-muted'>[-] JARVIS API ERROR: {html.escape(str(e))}</span>",
            "speech":   "An error occurred."
        })


def _jarvis_fallback(prompt: str) -> str:
    p = prompt.lower()
    if any(k in p for k in ["nmap", "port", "scan", "enumerate"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] ENUMERATION</span><br><br>"
                "Firewall may be blocking ICMP. Try <code>nmap -Pn -sV --open TARGET</code> to skip ping.<br>"
                "Also scan UDP: <code>nmap -sU --top-ports 100 TARGET</code> — SNMP (161) is often missed.")
    if any(k in p for k in ["privesc", "root", "privilege", "escalat"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] PRIVILEGE ESCALATION</span><br><br>"
                "Linux: <code>sudo -l</code> and <code>find / -perm -4000 2>/dev/null</code>.<br>"
                "Windows: <code>whoami /priv</code> and check unquoted service paths.")
    if any(k in p for k in ["shell", "reverse", "payload", "meterpreter"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] REVERSE SHELLS</span><br><br>"
                "Try egress on ports <span class='text-cyan-muted'>443, 80, 53</span> — firewalls rarely block these.<br>"
                "Listener: <code>nc -lvnp 443</code>")
    if any(k in p for k in ["web", "sqli", "xss", "waf", "inject"]):
        return ("<span class='text-yellow-muted font-bold'>[ADVISORY] WEB EXPLOITATION</span><br><br>"
                "WAF bypass: try URL-encoding or double-encoding keywords.<br>"
                "Blind SQLi: <code>'; WAITFOR DELAY '0:0:5'--</code>")
    if any(k in p for k in ["hello", "hi", "hey", "who are you"]):
        return "Hello Operator. <span class='text-green-muted'>JARVIS online.</span> Set OPENAI_API_KEY in .env for full GPT-4o intelligence."
    return "Specify a target or scenario — nmap, privilege escalation, web exploitation, or a CTF challenge."


# ─────────────────────────────────────────────────────────────────────────────
# FORENSIC TOOLS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/tool/<tool_code>", methods=["POST"])
@require_auth
@rl("100 per hour")
def run_tool(tool_code):
    operator = get_operator(request)
    data     = request.json or {}
    payload  = data.get("payload", "").strip()
    email    = operator["sub"] if operator else "GUEST"

    if not payload:
        return jsonify({"status": "error", "result": "Empty payload."})
    if len(payload) > 2000:
        return jsonify({"status": "error", "result": "Payload too large (max 2000 chars)."})

    result = ""
    try:
        if tool_code == "hash":
            md5    = hashlib.md5(payload.encode()).hexdigest()
            sha1   = hashlib.sha1(payload.encode()).hexdigest()
            sha256 = hashlib.sha256(payload.encode()).hexdigest()
            sha512 = hashlib.sha512(payload.encode()).hexdigest()
            result = f"MD5:    {md5}\nSHA1:   {sha1}\nSHA256: {sha256}\nSHA512: {sha512}"

        elif tool_code == "url":
            target = payload if payload.startswith("http") else "https://" + payload
            if not VT_API_KEY:
                return jsonify({"status": "error", "result": "VT_API_KEY not set in .env"})
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            req = urllib.request.Request(f"https://www.virustotal.com/api/v3/urls/{url_id}")
            req.add_header("x-apikey", VT_API_KEY)
            ctx = ssl.create_default_context()  # Proper SSL — no verification bypass
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
                    vt    = json.loads(resp.read().decode())
                    attrs = vt["data"]["attributes"]
                    stats = attrs.get("last_analysis_stats", {})
                    mal   = stats.get("malicious", 0)
                    sus   = stats.get("suspicious", 0)
                    clean = stats.get("harmless", 0) + stats.get("undetected", 0)
                    total = mal + sus + clean
                    score   = round(((mal + sus) / total) * 100) if total else 0
                    verdict = "CRITICAL THREAT" if mal > 2 else ("SUSPICIOUS" if sus > 0 else "CLEAN")
                    cats    = ", ".join(list(attrs.get("categories", {}).values())[:3]) or "N/A"
                    result  = (f"[*] VIRUSTOTAL REAL-TIME SCAN\nTARGET: {target}\n"
                               f"\nEngines:    {total}\nMalicious:  {mal}\nSuspicious: {sus}\nClean:      {clean}"
                               f"\nRisk Score: {score}/100\nCategories: {cats}\n\nVERDICT: {verdict}")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    result = f"[*] URL not in VT database yet.\nTARGET: {target}\nSTATUS: UNKNOWN"
                else:
                    result = f"[-] VirusTotal API Error: HTTP {e.code}"

        elif tool_code == "ip_scan":
            if not ABUSEIPDB_KEY:
                return jsonify({"status": "error", "result": "ABUSEIPDB_KEY not set in .env"})
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(payload)}&maxAgeInDays=90"
            req = urllib.request.Request(url)
            req.add_header("Key", ABUSEIPDB_KEY)
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=12) as resp:
                d       = json.loads(resp.read().decode())["data"]
                score   = d.get("abuseConfidenceScore", 0)
                country = d.get("countryCode", "?")
                isp     = d.get("isp", "Unknown")
                domain  = d.get("domain", "Unknown")
                reports = d.get("totalReports", 0)
                usage   = d.get("usageType", "Unknown")
                verdict = "CRITICAL THREAT" if score > 75 else ("SUSPICIOUS" if score > 25 else "CLEAN")
                result  = (f"[*] ABUSEIPDB REAL-TIME REPORT\nIP: {payload}\n"
                           f"\nCountry:  {country}  |  ISP: {isp}\nDomain:   {domain}\nUsage:    {usage}"
                           f"\n\nAbuse Score: {score}/100\nTotal Reports: {reports}\n\nVERDICT: {verdict}")

        elif tool_code == "dns":
            domain = payload.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            ip = socket.gethostbyname(domain)
            result = f"Domain: {domain}\nA Record: {ip}"

        elif tool_code == "conv_b64_enc":
            result = f"BASE64 ENCODED:\n{base64.b64encode(payload.encode()).decode()}"
        elif tool_code == "conv_b64_dec":
            result = f"BASE64 DECODED:\n{base64.b64decode(payload).decode('utf-8', errors='ignore')}"
        elif tool_code == "conv_hex_enc":
            result = f"HEX ENCODED:\n{payload.encode().hex()}"
        elif tool_code == "conv_hex_dec":
            cleaned = payload.replace(" ", "").replace("0x", "").replace("0X", "")
            result  = f"HEX DECODED:\n{bytes.fromhex(cleaned).decode('utf-8', errors='ignore')}"
        else:
            return jsonify({"status": "error", "result": f"Unknown tool: {tool_code}"})

        log_action(email, tool_code.upper(), payload[:100], "ok", request.remote_addr)
        return jsonify({"status": "success", "result": result})

    except Exception as e:
        return jsonify({"status": "error", "result": f"Error: {html.escape(repr(e))}"})


# ─────────────────────────────────────────────────────────────────────────────
# TEAM / CASE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/team/activity", methods=["GET"])
@require_auth
def team_activity():
    conn = get_db()
    logs = conn.execute(
        "SELECT email, action, target, result_summary, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify({"status": "success", "activity": [dict(r) for r in logs]})


@app.route("/api/cases", methods=["GET", "POST"])
@require_auth
def manage_cases():
    op   = get_operator(request)
    conn = get_db()

    if request.method == "GET":
        rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        conn.close()
        return jsonify({"status": "success", "cases": [dict(r) for r in rows]})

    data = request.json or {}
    conn.execute(
        "INSERT INTO cases (title, description, severity, created_by) VALUES (?,?,?,?)",
        (data.get("title", "Untitled"), data.get("description", ""),
         data.get("severity", "medium"), op["sub"])
    )
    conn.commit()
    conn.close()
    log_action(op["sub"], "CASE_CREATE", data.get("title", ""), "", request.remote_addr)
    return jsonify({"status": "success", "message": "Case created."})


@app.route("/api/cases/<int:case_id>", methods=["PATCH"])
@require_auth
def update_case(case_id):
    data = request.json or {}
    conn = get_db()
    if "status" in data:
        conn.execute("UPDATE cases SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (data["status"], case_id))
    if "assigned_to" in data:
        conn.execute("UPDATE cases SET assigned_to=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (data["assigned_to"], case_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/cases/<int:case_id>/notes", methods=["GET", "POST"])
@require_auth
def case_notes(case_id):
    op   = get_operator(request)
    conn = get_db()

    if request.method == "GET":
        notes = conn.execute(
            "SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at", (case_id,)
        ).fetchall()
        conn.close()
        return jsonify({"status": "success", "notes": [dict(n) for n in notes]})

    data = request.json or {}
    note = data.get("note", "").strip()
    if not note:
        return jsonify({"status": "error", "message": "Note is empty."})
    conn.execute("INSERT INTO case_notes (case_id, author, note) VALUES (?,?,?)",
                 (case_id, op["sub"], note))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/audit-log", methods=["GET"])
@require_auth
def audit_log():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return jsonify({"status": "success", "logs": [dict(r) for r in rows]})


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    missing = []
    if not VT_API_KEY:    missing.append("VT_API_KEY")
    if not ABUSEIPDB_KEY: missing.append("ABUSEIPDB_KEY")
    if not OPENAI_KEY:    missing.append("OPENAI_API_KEY")
    if not BCRYPT_OK:     missing.append("bcrypt (pip install bcrypt)")
    if not JWT_OK:        missing.append("PyJWT (pip install PyJWT)")
    if not OPENAI_OK:     missing.append("openai (pip install openai)")

    print("=" * 52)
    print("  🚀 PHISH-NET SECURE BACKEND ONLINE")
    print(f"  🔐 JWT: {'✓' if JWT_OK else '✗'}  |  bcrypt: {'✓' if BCRYPT_OK else '✗'}  |  Rate-limit: {'✓' if LIMITER_OK else '✗'}")
    print(f"  🧠 GPT-4o PentestGPT: {'✓' if OPENAI_KEY else '✗ (set OPENAI_API_KEY)'}")
    print(f"  🌐 VT: {'✓' if VT_API_KEY else '✗'}  |  AbuseIPDB: {'✓' if ABUSEIPDB_KEY else '✗'}")
    if missing:
        print(f"\n  ⚠  Missing: {', '.join(missing)}")
        print("     Copy .env.example → .env and fill in your keys.")
    print("=" * 52)
    app.run(debug=False, port=5000)