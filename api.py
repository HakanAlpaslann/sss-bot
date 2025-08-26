# api.py — WhatsApp Cloud + FastAPI SSS bot (pro sürüm)
# Python 3.11+
# Özellikler:
# - İlk mesajda karşılama + menü (config ile)
# - Sonrasında sadece auto_intents -> cevap, diğer tüm mesajlara sessiz
# - Fuzzy fallback (rapidfuzz) ile yazım hatalarında doğru cevabı bulma
# - Webhook imza doğrulama (X-Hub-Signature-256, APP_SECRET)
# - Arka planda gönderim + 429/5xx backoff
# - Multi-tenant hazır (PHONE_TO_CLIENT_JSON)
# - Admin reset endpoint'leri
# - Yapılandırılmış log

import os
import json
import time
import hmac
import hashlib
import unicodedata
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple, Optional

import requests
from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Query,
    Header,
    BackgroundTasks,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

# --- (opsiyonel) bulanık eşleştirme ---
try:
    from rapidfuzz import fuzz  # pip install rapidfuzz
except Exception:
    fuzz = None

# -----------------------------------------------------------------------------
# FastAPI & CORS
# -----------------------------------------------------------------------------
app = FastAPI(title="SSS Bot API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("sss-bot")

# -----------------------------------------------------------------------------
# Env
# -----------------------------------------------------------------------------
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "mybotverify")
DEFAULT_CLIENT = os.getenv("DEFAULT_CLIENT", "dayi")
PHONE_TO_CLIENT_JSON = os.getenv("PHONE_TO_CLIENT_JSON", "{}")
WHATSAPP_PHONE_ID_FALLBACK = os.getenv("WHATSAPP_PHONE_ID", "")
APP_SECRET = os.getenv("APP_SECRET", "")  # Meta App Secret (imza doğrulama)

# -----------------------------------------------------------------------------
# Yardımcılar: normalize, faq okuma
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

def fuzzy_find(faq: dict[str, str], user_text_norm: str, threshold: int = 85) -> Optional[str]:
    """faq anahtarları içinde user_text_norm'a en yakın olanı bulur (partial_ratio)."""
    if not fuzz or not faq:
        return None
    best_score = -1
    best_val = None
    for k_norm, val in faq.items():
        score = fuzz.partial_ratio(user_text_norm, k_norm)
        if score > best_score:
            best_score = score
            best_val = val
    if best_score >= threshold:
        return best_val
    return None

# -----------------------------------------------------------------------------
# Cevap üretimi
# -----------------------------------------------------------------------------
def answer(client: str, question: str) -> str:
    """SSS eşleştirici (kural bazlı + faq lookup + fuzzy fallback)."""
    faq = load_faq(client)
    s = norm(question)

    # ---- kural bazlı hızlı eşleşmeler ----
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

    # ---- Fuzzy fallback (rapidfuzz) ----
    try:
        cfg = load_tenant_cfg(client)
        threshold = int(cfg.get("fuzzy_threshold", 85))
    except Exception:
        threshold = 85
    fuzzy_val = fuzzy_find(faq, s, threshold)
    if fuzzy_val:
        return fuzzy_val  # başlıksız, doğrudan faq cevabı

    # ---- Son fallback ----
    return "Bu bilgi faq.txt içinde yok."

# -----------------------------------------------------------------------------
# Tenant config (greeting + whitelist)
# -----------------------------------------------------------------------------
def load_tenant_cfg(client: str) -> dict:
    cfg_path = Path(f"data/{client}/config.json")
    if cfg_path.exists():
        try:
            return json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    # varsayılan
    return {
        "greeting": "Hoş geldiniz! Yardım için 'menü' yazın.",
        "auto_intents": [],
        "cooldown_minutes": 120,
        "append_menu_to_greeting": True,
        "help_enabled": True,
        # "fuzzy_threshold": 85    # eklemezsen 85 kabul edilir
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
# In-memory durum (prod'da Redis önerilir)
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
# İmza doğrulama (X-Hub-Signature-256)
# -----------------------------------------------------------------------------
def verify_signature(app_secret: str, raw_body: bytes, signature_header: Optional[str]) -> bool:
    if not app_secret:
        return True  # APP_SECRET yoksa (dev) doğrulamayı atla
    if not signature_header:
        return False
    try:
        provided = signature_header.split("=", 1)[-1].strip()  # "sha256=<hex>" -> hex
    except Exception:
        return False
    digest = hmac.new(app_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, provided)

# -----------------------------------------------------------------------------
# WhatsApp gönderim (retry/backoff'lu)
# -----------------------------------------------------------------------------
def send_whatsapp_text(phone_number_id: Optional[str], to_wa_id: str, text: str):
    if not WHATSAPP_TOKEN:
        print("[WA] missing WHATSAPP_TOKEN"); return
    phone_id = phone_number_id or WHATSAPP_PHONE_ID_FALLBACK
    if not phone_id:
        print("[WA] phone_number_id missing"); return

    url = f"https://graph.facebook.com/v20.0/{phone_id}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_id,
        "type": "text",
        "text": {"body": text},
    }

    for attempt in range(3):
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=30)
            if r.status_code < 400:
                return
            if r.status_code in (429, 500, 502, 503, 504):
                wait = 2 ** attempt
                print(f"[WA backoff] {r.status_code} attempt={attempt+1} wait={wait}s {r.text}")
                time.sleep(wait)
                continue
            print("[WA send error]", r.status_code, r.text)
            return
        except Exception as e:
            wait = 2 ** attempt
            print("[WA send error]", e, f"attempt={attempt+1} wait={wait}s")
            time.sleep(wait)

# -----------------------------------------------------------------------------
# HTTP API (test & admin)
# -----------------------------------------------------------------------------
class AskIn(BaseModel):
    client: str
    question: str

class ResetIn(BaseModel):
    client: str
    wa_id: str  # +90 ile başlayan kullanıcı numarası

@app.get("/")
def root():
    return {"message": "SSS Bot API. Test: /docs  |  Soru: POST /ask"}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ask")
def ask(inp: AskIn, request: Request):
    return {"answer": answer(inp.client, inp.question)}

@app.post("/admin/reset-session")
def reset_session(inp: ResetIn):
    key = (inp.client, inp.wa_id)
    existed = key in SESSIONS
    if existed:
        del SESSIONS[key]
    return {"ok": True, "removed": existed}

@app.post("/admin/reset-all-sessions")
def reset_all_sessions():
    SESSIONS.clear()
    return {"ok": True, "cleared": True}

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
async def wa_receive(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(default=None, alias="X-Hub-Signature-256"),
):
    # --- imza doğrulama ---
    raw = await request.body()
    if not verify_signature(APP_SECRET, raw, x_hub_signature_256):
        raise HTTPException(status_code=403, detail="bad signature")

    data = json.loads(raw.decode("utf-8") or "{}")
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

        wa_id = msg["from"]  # kullanıcının WhatsApp numarası
        text = msg.get("text", {}).get("body", "").strip()
        phone_number_id = entry.get("metadata", {}).get("phone_number_id")

        # tenant
        client = resolve_client(phone_number_id)
        cfg = load_tenant_cfg(client)
        auto_intents_norm = [norm(x) for x in cfg.get("auto_intents", [])]
        s = norm(text)
        now = datetime.utcnow()

        # menü/yardım komutu (ayar açıksa)
        if cfg.get("help_enabled", True) and is_help_like(s):
            background_tasks.add_task(send_whatsapp_text, phone_number_id, wa_id, list_menu_text(client))
            logger.info(json.dumps({"evt":"reply","type":"menu","tenant":client,"wa":wa_id[-4:]}))
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
            background_tasks.add_task(send_whatsapp_text, phone_number_id, wa_id, greet)
            logger.info(json.dumps({"evt":"reply","type":"greeting","tenant":client,"wa":wa_id[-4:]}))
            return {"ok": True}  # hızlı 200

        # sadece whitelist'teki konulara cevap ver
        if any(k in s for k in auto_intents_norm):
            reply = answer(client, text)
            background_tasks.add_task(send_whatsapp_text, phone_number_id, wa_id, reply)
            logger.info(json.dumps({"evt":"reply","type":"faq","tenant":client,"wa":wa_id[-4:], "q": s[:80]}))
            return {"ok": True}

        # izinli değilse sessiz kal
        return {"ok": True}

    except Exception as e:
        print("[WA parse error]", e)
        return {"ok": True}
