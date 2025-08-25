# api.py — WhatsApp Cloud + FastAPI SSS bot
# Özellikler: karşılama+menü tek mesajda, whitelist auto-intents, sessiz mod, multi-tenant hazır
# Python 3.11+

import os
import json
import unicodedata
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple, Optional

import requests
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

# -----------------------------------------------------------------------------
# FastAPI
# -----------------------------------------------------------------------------
app = FastAPI(title="SSS Bot API")

# ----- CORS -----
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Ortam değişkenleri
# -----------------------------------------------------------------------------
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")  # System User ile alınmış kalıcı token
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "mybotverify")  # webhook doğrulama tokenı
DEFAULT_CLIENT = os.getenv("DEFAULT_CLIENT", "dayi")

# Çok müşterili eşleme (opsiyonel): {"phone_number_id":"tenant", ...}
PHONE_TO_CLIENT_JSON = os.getenv("PHONE_TO_CLIENT_JSON", "{}")

# Fallback phone id (opsiyonel): eventte gelmezse buradan alır
WHATSAPP_PHONE_ID_FALLBACK = os.getenv("WHATSAPP_PHONE_ID", "")

# -----------------------------------------------------------------------------
# Yardımcılar (normalize, faq yükleme, cevap)
# -----------------------------------------------------------------------------
def norm(s: str) -> str:
    """Türkçe normalize + küçük harf + trim."""
    if not isinstance(s, str):
        return ""
    s = s.replace("İ", "I").replace("ı", "i")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.casefold().strip()

def load_faq(client: str) -> dict[str, str]:
    """data/<client>/faq.txt -> {anahtar_norm: cevap}"""
    path = Path(f"data/{client}/faq.txt")
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[norm(k)] = v.strip()
    return out

def find_any(faq: dict[str, str], needles: list[str]) -> Optional[str]:
    for k_norm, val in faq.items():
        for needle in needles:
            if needle in k_norm:
                return val
    return None

def answer(client: str, question: str) -> str:
    """Basit SSS eşleştirici (intent anahtar kelimeleri + faq.txt lookup)."""
    faq = load_faq(client)
    s = norm(question)

    if "kargo" in s:
        return "Kargo: " + (find_any(faq, ["kargo"]) or "Bilgi yok.")
    if "iade" in s:
        return "İade: " + (find_any(faq, ["iade"]) or "Bilgi yok.")
    if any(w in s for w in ["saat", "acik", "açik", "acık", "calisma", "çalisma", "çalışma"]):
        return "Çalışma saatleri: " + (
            find_any(faq, ["calisma saatleri", "saatler", "saat"]) or "Bilgi yok."
        )
    if any(w in s for w in ["iletisim", "iletişim", "mail", "e posta", "e-posta"]):
        return "İletişim: " + (find_any(faq, ["iletisim", "telefon"]) or "Bilgi yok.")
    if "garanti" in s:
        return "Garanti: " + (find_any(faq, ["garanti"]) or "Bilgi yok.")
    if any(w in s for w in ["ucret", "ücret", "fiyat"]):
        return "Ücret: " + (
            find_any(faq, ["servis ücreti", "ucret", "ücret", "fiyat"]) or "Bilgi yok."
        )
    if any(w in s for w in ["bölge", "bolge", "nerelere", "servis alani", "servis alanı"]):
        return "Hizmet bölgeleri: " + (
            find_any(
                faq,
                [
                    "hangi bolgelerde hizmet veriyorsunuz",
                    "bolgeler",
                    "bölgeler",
                    "servis bolgesi",
                    "servis alanı",
                ],
            )
            or "Bilgi yok."
        )
    return "Bu bilgi faq.txt içinde yok."

# -----------------------------------------------------------------------------
# Tenant config (karşılama + whitelist)
# -----------------------------------------------------------------------------
def load_tenant_cfg(client: str) -> dict:
    cfg_path = Path(f"data/{client}/config.json")
    if cfg_path.exists():
        try:
            return json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    # Varsayılan ayarlar
    return {
        "greeting": "Hoş geldiniz! Yardım için 'menü' yazın.",
        "auto_intents": [],
        "cooldown_minutes": 120,
        "append_menu_to_greeting": True,  # karşılama altına menü ekle
        "help_enabled": True,             # menü/yardım komutunu aç/kapa
    }

def list_menu_text(client: str) -> str:
    cfg = load_tenant_cfg(client)
    items = cfg.get("auto_intents", [])
    if not items:
        return "Şu an hızlı cevap verebildiğim özel konu yok."
    bullets = "\n".join(f"- {x}" for x in items)
    return f"Aşağıdaki konularda anında yardımcı olabilirim:\n{bullets}"

def is_help_like(s: str) -> bool:
    return s in {"yardim", "yardım", "menu", "menü", "liste"}

# -----------------------------------------------------------------------------
# Basit durum saklama (RAM)
# -----------------------------------------------------------------------------
SESSIONS: Dict[Tuple[str, str], dict] = {}   # (client, wa_id) -> {greeted_at: dt}
PROCESSED_MSG_IDS: set[str] = set()          # idempotency

# -----------------------------------------------------------------------------
# Tenant çözümleme
# -----------------------------------------------------------------------------
def resolve_client(phone_number_id: Optional[str]) -> str:
    """phone_number_id -> tenant, yoksa DEFAULT_CLIENT."""
    try:
        mapping = json.loads(PHONE_TO_CLIENT_JSON or "{}")
        if phone_number_id and phone_number_id in mapping:
            return mapping[phone_number_id]
    except Exception:
        pass
    return DEFAULT_CLIENT

# -----------------------------------------------------------------------------
# WhatsApp gönderim
# -----------------------------------------------------------------------------
def send_whatsapp_text(phone_number_id: Optional[str], to_wa_id: str, text: str):
    """Meta Graph send API (v20). Gelen event'teki phone_number_id varsa onu kullan."""
    if not WHATSAPP_TOKEN:
        print("[WA] missing WHATSAPP_TOKEN")
        return
    phone_id = phone_number_id or WHATSAPP_PHONE_ID_FALLBACK
    if not phone_id:
        print("[WA] phone_number_id missing")
        return

    url = f"https://graph.facebook.com/v20.0/{phone_id}/messages"
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
    except Exception as e:
        print("[WA send error]", e)

# -----------------------------------------------------------------------------
# HTTP API (test amaçlı)
# -----------------------------------------------------------------------------
class AskIn(BaseModel):
    client: str
    question: str

@app.get("/")
def root():
    return {"message": "SSS Bot API. Test: /docs  |  Soru: POST /ask"}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ask")
def ask(inp: AskIn, request: Request):
    return {"answer": answer(inp.client, inp.question)}

# -----------------------------------------------------------------------------
# WhatsApp Webhook
# -----------------------------------------------------------------------------
# 1) GET verify
@app.get("/whatsapp/webhook")
def wa_verify(
    hub_mode: str = Query(..., alias="hub.mode"),
    hub_challenge: str = Query(..., alias="hub.challenge"),
    hub_verify_token: str = Query(..., alias="hub.verify_token"),
):
    if hub_mode == "subscribe" and hub_verify_token == VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge)
    raise HTTPException(status_code=403, detail="verification failed")

# 2) POST receive
@app.post("/whatsapp/webhook")
async def wa_receive(request: Request):
    data = await request.json()
    try:
        entry = data["entry"][0]["changes"][0]["value"]
        messages = entry.get("messages")
        if not messages:
            return {"ok": True}

        msg = messages[0]

        # idempotency
        msg_id = msg.get("id")
        if msg_id and msg_id in PROCESSED_MSG_IDS:
            return {"ok": True}
        if msg_id:
            PROCESSED_MSG_IDS.add(msg_id)

        wa_id = msg["from"]                           # kullanıcının WA numarası
        text = msg.get("text", {}).get("body", "").strip()
        phone_number_id = entry.get("metadata", {}).get("phone_number_id")

        # tenant belirle
        client = resolve_client(phone_number_id)
        cfg = load_tenant_cfg(client)
        auto_intents_norm = [norm(x) for x in cfg.get("auto_intents", [])]
        s = norm(text)
        now = datetime.utcnow()

        # menü/yardım komutu (ayar açıksa)
        if cfg.get("help_enabled", True) and is_help_like(s):
            send_whatsapp_text(phone_number_id, wa_id, list_menu_text(client))
            return {"ok": True}

        # karşılama (ilk mesaj veya cooldown dolmuşsa)
        sess_key = (client, wa_id)
        sess = SESSIONS.get(sess_key)
        cooldown = int(cfg.get("cooldown_minutes", 120))
        need_greet = False
        if not sess:
            need_greet = True
        else:
            last = sess.get("greeted_at")
            if not last or (now - last) > timedelta(minutes=cooldown):
                need_greet = True

        if need_greet:
            SESSIONS[sess_key] = {"greeted_at": now}
            greet = cfg.get("greeting", "Hoş geldiniz!")
            if cfg.get("append_menu_to_greeting", True):
                greet = f"{greet}\n\n{list_menu_text(client)}"
            send_whatsapp_text(phone_number_id, wa_id, greet)
            return {"ok": True}  # sadece karşılama gönder

        # sadece whitelist'teki konulara cevap ver
        if any(k in s for k in auto_intents_norm):
            reply = answer(client, text)
            send_whatsapp_text(phone_number_id, wa_id, reply)
            return {"ok": True}

        # izinli değilse sessiz kal
        return {"ok": True}

    except Exception as e:
        print("[WA parse error]", e)
        return {"ok": True}
