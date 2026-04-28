# 🛡️ Phish-Net — AI-Powered SOC Platform

<p align="center">
  <img src="giphy.gif" width="120" alt="JARVIS Core"/>
  <br/>
  <strong>A full-stack cybersecurity operations platform with real-time threat intelligence and a GPT-4o powered AI analyst (J.A.R.V.I.S.)</strong>
  <br/><br/>
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask"/>
  <img src="https://img.shields.io/badge/AI-GPT--4o%20PentestGPT-412991?style=flat-square&logo=openai"/>
  <img src="https://img.shields.io/badge/Auth-JWT%20%2B%20bcrypt-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Intel-VirusTotal%20%7C%20AbuseIPDB-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square"/>
</p>

---

## 📸 Screenshots

| URL Scanner | IP Scanner | JARVIS AI |
|---|---|---|
| Real-time VirusTotal scan | AbuseIPDB threat intel | GPT-4o tactical advisory |

---

## ✨ Features

### 🧠 J.A.R.V.I.S. — AI Advisory Engine
- Powered by **OpenAI GPT-4o** in PentestGPT mode
- Tactical guidance for CTF challenges, nmap, privilege escalation, web exploitation, forensics
- HTML-formatted cyberpunk terminal responses with colour-coded threat levels
- Text-to-speech voice output with selectable voice engine
- Offline keyword fallback when API key is not set

### 🔍 Threat Intelligence Tools
| Tool | Source | What it does |
|---|---|---|
| **URL Scanner** | VirusTotal API v3 | Submits URL, polls until scan complete, returns engine verdicts & risk score |
| **IP Scanner** | AbuseIPDB API v2 | Returns country, ISP, usage type, Tor exit node status, abuse score & report count |
| **DNS Lookup** | Google DNS over HTTPS | Resolves domain → IP in real time |
| **Domain Heuristics** | Client-side | Keyword & structure analysis for phishing patterns |
| **QR Scanner** | Client-side (jsQR) | Decodes QR codes from uploaded images |
| **PCAP Analyser** | Client-side | Packet capture traffic summary & C2 detection heuristics |
| **EXIF Reader** | Client-side (piexif) | Extracts metadata from JPEG images |
| **String Extractor** | Client-side (Web Worker) | Extracts printable strings from binary files |
| **File Signature** | Client-side | Identifies file type from magic bytes |

### 🔐 Security & Auth
- **JWT authentication** (HS256, 8-hour expiry)
- **bcrypt password hashing** with salted SHA-256 fallback
- **Rate limiting** via Flask-Limiter (per-route, per-IP)
- **Environment-variable secrets** — no hardcoded keys anywhere
- **Input length guards** on all API endpoints
- **Full audit log** — every action logged with email, IP, timestamp

### 🗂️ Team / Case Management
- Create, assign and update investigation cases with severity levels
- Collaborative case notes
- Shared team activity feed
- Full audit log viewer

### 🎨 UI
- Cyberpunk terminal aesthetic with matrix rain background
- Share Tech Mono font throughout
- Responsive Tailwind CSS layout
- Google Translate integration
- Animated thinking states, password strength meter

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/phish-net.git
cd phish-net
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure environment
```bash
cp .env.example .env
```
Open `.env` and fill in your keys:

```env
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
JWT_SECRET=your_long_random_secret_here

# https://platform.openai.com/api-keys
OPENAI_API_KEY=sk-...

# https://www.virustotal.com/gui/my-apikey
VT_API_KEY=your_vt_key

# https://www.abuseipdb.com/account/api
ABUSEIPDB_KEY=your_abuseipdb_key
```

### 4. Start the backend
```bash
python app.py
```
You should see:
```
🚀 PHISH-NET SECURE BACKEND ONLINE
🔐 JWT: ✓  |  bcrypt: ✓  |  Rate-limit: ✓
🧠 GPT-4o PentestGPT: ✓
🌐 VT: ✓   |  AbuseIPDB: ✓
```

### 5. Open in browser
```
http://127.0.0.1:5000/login.html
```

> ⚠️ **Do not** open the HTML files by double-clicking — always use the URL above. Flask serves all frontend files.

---

## 📁 Project Structure

```
phish-net/
├── app.py              # Flask backend — all API routes, auth, AI, tools
├── jarvis_api.py       # Standalone CLI tester for JARVIS (GPT-4o)
├── train_jarvis.py     # Local ML intent classifier (optional / offline mode)
├── index.html          # Main SOC dashboard
├── jarvis.html         # JARVIS AI chat interface
├── login.html          # JWT login page
├── signup.html         # Registration page
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable template
├── giphy.gif           # JARVIS orb animation
├── widget.gif          # UI widget animation
└── phishnet.db         # SQLite database (auto-created on first run)
```

---

## 🔌 API Reference

All routes (except `/api/health`, `/api/register`, `/api/login`) require:
```
Authorization: Bearer <jwt_token>
```

| Method | Route | Description |
|---|---|---|
| GET | `/api/health` | Backend status check |
| POST | `/api/register` | Register new operator |
| POST | `/api/login` | Login → returns JWT token |
| POST | `/api/jarvis` | GPT-4o tactical advisory |
| POST | `/api/tool/url` | VirusTotal URL scan |
| POST | `/api/tool/ip_scan` | AbuseIPDB IP lookup |
| POST | `/api/tool/dns` | DNS resolution |
| POST | `/api/tool/hash` | MD5/SHA1/SHA256/SHA512 hashing |
| POST | `/api/tool/conv_b64_enc` | Base64 encode |
| POST | `/api/tool/conv_b64_dec` | Base64 decode |
| POST | `/api/tool/conv_hex_enc` | Hex encode |
| POST | `/api/tool/conv_hex_dec` | Hex decode |
| GET | `/api/cases` | List all cases |
| POST | `/api/cases` | Create new case |
| PATCH | `/api/cases/<id>` | Update case status/assignment |
| GET/POST | `/api/cases/<id>/notes` | Get or add case notes |
| GET | `/api/team/activity` | Team activity feed |
| GET | `/api/audit-log` | Full audit log |

---

## 🔑 API Keys (all free tier)

| Service | Free Tier | Link |
|---|---|---|
| OpenAI (GPT-4o) | Pay-per-use, ~$0.005/query | [platform.openai.com](https://platform.openai.com/api-keys) |
| VirusTotal | 500 requests/day | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| AbuseIPDB | 1,000 checks/day | [abuseipdb.com](https://www.abuseipdb.com/account/api) |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.0 |
| AI | OpenAI GPT-4o (PentestGPT mode) |
| Auth | PyJWT (HS256), bcrypt |
| Database | SQLite (via sqlite3) |
| Rate Limiting | Flask-Limiter |
| Threat Intel | VirusTotal API v3, AbuseIPDB API v2 |
| SSL | certifi (trusted CA bundle) |
| Frontend | Vanilla JS, Tailwind CSS, Font Awesome |
| Fonts | Share Tech Mono (Google Fonts) |

---

## ⚠️ Security Notes

- Never commit your `.env` file — it is listed in `.gitignore`
- Rotate API keys immediately if they are ever exposed
- This platform is intended for **authorised security research and SOC operations only**
- The JARVIS AI provides advisory output — always verify commands before executing on live systems

---

## 🗺️ Roadmap

- [ ] Shodan integration for port/service intelligence
- [ ] Email header analyser
- [ ] Hash lookup (VirusTotal file hash)
- [ ] PDF malware indicator extraction
- [ ] Slack / Teams webhook alerts
- [ ] Docker compose setup
- [ ] Dark/light theme toggle

---

## 👤 Author

**Girish Wadhwani**
- 📧 [girishwadhwani1000@gmail.com](mailto:girishwadhwani1000@gmail.com)
- 💬 [WhatsApp +91 9664380661](https://wa.me/919664380661)

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built for the security community 🔐 — Use responsibly.
</p>
