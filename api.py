# api.py — WhatsApp Cloud + FastAPI (temiz sürüm)
# - Tek bir GET /whatsapp/webhook doğrulaması (hub.challenge döndürür)
# - POST /whatsapp/webhook mesaj alır, faq.txt'den yanıtlar
# - .env, CORS, güvenli JSON parse, mutlak faq yolu

import os
import unicodedata
from pathlib import Path
from typing import Dict, Optional, List

import requests
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse

# .env (yüklüyse)
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

BASE_DIR = Path(__file__).resolve().parent
if load_dotenv:
    load_dotenv(BASE_DIR / ".env")

# ---- Env ----
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID", "")
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "mybotverify")
DEFAULT_CLIENT = os.getenv("DEFAULT_CLIENT", "dayi")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app = FastAPI(title="SSS API (clean)")

# ---- CORS ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Yardımcılar ----
def norm(s: str) -> str:
    if not isinstance(s, str):
        s = str(s or "")
    s = s.replace("İ", "I").replace("ı", "i")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.casefold().strip()

def load_faq(client: str) -> Dict[str, str]:
    path = BASE_DIR / "data" / client / "faq.txt"
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            out[norm(k)] = v.strip()
    except Exception as e:
        print("[faq read error]", e)
    return out

def find_any(faq: Dict[str, str], keys: List[str]) -> Optional[str]:
    keys_norm = [norm(k) for k in keys]
    for k_norm, val in faq.items():
        for needle in keys_norm:
            if needle and needle in k_norm:
                return val
    return None

def answer(client: str, question: str) -> str:
    faq = load_faq(client)
    s = norm(question)

    if not s or len(s) < 2:
        topics = ", ".join(sorted(faq.keys())) or "kargo, iade, çalışma saatleri, iletişim, ücret, bölgeler"
        return f"Merhaba! Yardımcı olabileceğim konular: {topics}\nÖr: 'kargo', 'iade', 'çalışma saatleri'."

    if "kargo" in s:
        return "Kargo: " + (find_any(faq, ["kargo"]) or "Bilgi yok.")
    if "iade" in s:
        return "İade: " + (find_any(faq, ["iade"]) or "Bilgi yok.")
    if any(w in s for w in ["saat", "acik", "açik", "calisma", "çalisma"]):
        return "Çalışma saatleri: " + (
            find_any(faq, ["calisma saatleri", "saatler", "saat"]) or "Bilgi yok."
        )
    if any(w in s for w in ["iletisim", "iletişim", "mail", "e posta", "e-posta"]):
        return "İletişim: " + (find_any(faq, ["iletisim"]) or "Bilgi yok.")
    if "garanti" in s:
        return "Garanti: " + (find_any(faq, ["garanti"]) or "Bilgi yok.")
    if any(w in s for w in ["ucret", "ücret", "fiyat"]):
        return "Ücret: " + (
            find_any(faq, ["servis ücreti", "ucret", "fiyat"]) or "Bilgi yok."
        )
    if any(w in s for w in ["bölge", "bolge", "nerelere", "servis alani", "servis alanı"]):
        return "Hizmet bölgeleri: " + (
            find_any(faq, ["hangi bolgelerde hizmet veriyorsunuz", "bolgeler", "bölgeler", "servis bolgesi", "servis bölgesi"])
            or "Bilgi yok."
        )
    return "Bu bilgi faq.txt içinde yok. 'yardım' veya 'menü' yazabilirsin."

# ---- İç test API ----
@app.get("/")
def root():
    return {"message": "SSS Bot API. Test: /docs  |  Soru: POST /ask"}

@app.get("/health")
def health():
    return {"ok": True}

from pydantic import BaseModel
class AskIn(BaseModel):
    client: str
    question: str

@app.post("/ask")
def ask(inp: AskIn, request: Request):
    return {"answer": answer(inp.client, inp.question)}

# ---- WhatsApp gönderici ----
def send_whatsapp_text(to_wa_id: str, text: str) -> None:
    if not (WHATSAPP_TOKEN and WHATSAPP_PHONE_ID):
        print("[warn] Missing WHATSAPP_TOKEN/WHATSAPP_PHONE_ID")
        return
    url = f"https://graph.facebook.com/v20.0/{WHATSAPP_PHONE_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_id,
        "type": "text",
        "text": {"body": text},
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        if r.status_code >= 400:
            print("[WA send error]", r.status_code, r.text)
    except requests.RequestException as e:
        print("[WA send exception]", e)

# ---- WhatsApp Webhook: DOĞRULAMA (TEK) ----
@app.get("/whatsapp/webhook")
def wa_verify(
    hub_mode: str = Query(..., alias="hub.mode"),
    hub_challenge: str = Query(..., alias="hub.challenge"),
    hub_verify_token: str = Query(..., alias="hub.verify_token"),
):
    # Sadece bu fonksiyon mevcut; duplication yok.
    if hub_mode == "subscribe" and hub_verify_token == VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge)  # text/plain
    raise HTTPException(status_code=403, detail="verification failed")

# ---- WhatsApp Webhook: MESAJ ALMA ----
@app.post("/whatsapp/webhook")
async def wa_receive(request: Request):
    # WhatsApp tekrar denemesin diye 200'ü önceliklendiriyoruz.
    try:
        data = await request.json()
    except Exception:
        return {"ok": True}

    try:
        entry = (data.get("entry") or [])
        if not entry:
            return {"ok": True}
        changes = (entry[0].get("changes") or [])
        if not changes:
            return {"ok": True}
        value = changes[0].get("value") or {}
        messages = value.get("messages")
        if not messages:
            return {"ok": True}

        msg = messages[0]
        wa_id = msg.get("from", "")
        text = (msg.get("text") or {}).get("body", "")
        text = (text or "").strip()

        client = DEFAULT_CLIENT  # şimdilik sabit; sonra multi-tenant
        reply = answer(client, text)
        if wa_id and reply:
            send_whatsapp_text(wa_id, reply)
    except Exception as e:
        print("[WA parse error]", e)

    return {"ok": True}
