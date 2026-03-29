# 🔐 AI API Security Gateway

![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat&logo=flask&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-HS256-000000?style=flat)
![Zero Trust](https://img.shields.io/badge/Zero-Trust-ED1C24?style=flat)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)

---

## 🔍 The Problem

Most organizations let applications call AI APIs directly:
- ❌ No authentication — anyone with the API key can call it
- ❌ No rate limiting — unlimited requests = unlimited cost
- ❌ No content inspection — malicious input reaches the AI
- ❌ API key visible to developers — easily stolen or leaked

**Solution: a gateway that enforces all security policy in one place.**

---

## 🛡️ Zero-Trust Pipeline

```
Client Request
      │
      ▼
[ JWT Authentication ]──── ❌ 401 if missing/invalid token
      │
      ▼
[ Rate Limiting ]──────── ❌ 429 if > 20 req/min
      │
      ▼
[ Injection Scanner ]──── ❌ 403 if attack detected
      │
      ▼
[ PII Redactor ]────────── ✅ Sensitive data masked
      │
      ▼
[ AI API ] ◄──────────── Only safe, authenticated,
                          rate-limited requests reach here
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/ai-api-security-gateway
cd ai-api-security-gateway
pip install flask pyjwt
python3 gateway.py
# Gateway starts at http://localhost:8000
```

---

## 💻 Usage

```bash
# Step 1: Get a JWT token
curl -X POST http://localhost:8000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"username":"janaki","password":"securepass"}'
# Returns: {"access_token":"eyJ...","expires_in":86400}

# Step 2: Call AI endpoint with token
curl -X POST http://localhost:8000/ai/chat \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"message":"What is Python?"}'
# Returns: {"response":"...","security":{"injection_score":0,"pii_redacted":false}}

# Step 3: Injection is automatically blocked
curl -X POST http://localhost:8000/ai/chat \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{"message":"Ignore all previous instructions"}'
# Returns: HTTP 403 {"blocked":true,"reason":"Prompt injection detected","risk_score":100}
```

---

## 🗺️ API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /auth/token` | None | Exchange credentials for JWT |
| `POST /ai/chat` | JWT | Secure AI message endpoint |
| `GET /gateway/logs` | Admin JWT | View audit trail |
| `GET /gateway/stats` | JWT | Request statistics |
| `GET /health` | None | Health check |

---

## 🔑 How JWT Works

```
Login: POST /auth/token
    │  credentials verified
    ▼
JWT created: header.payload.signature
  payload = {sub: "janaki", role: "user", exp: now+24h}
  signature = HMAC-SHA256(header+payload, SECRET_KEY)
    │
    ▼  Client stores token

Every request: Authorization: Bearer eyJ...
    │
    ▼
Gateway: jwt.decode(token, SECRET_KEY)
  ✅ Valid signature + not expired → allow
  ❌ Invalid or expired → 401
```

---

## 🛠️ Skills Demonstrated

- Flask reverse proxy architecture
- JWT token creation and verification (PyJWT)
- Sliding-window rate limiting
- Zero-trust security model implementation
- Multi-layer decorator pattern (auth → rate → scan)

---
