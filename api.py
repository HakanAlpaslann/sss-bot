# api.py — WhatsApp Cloud + FastAPI SSS bot (hot-reload + Redis sürümü)
# Python 3.11+
# Özellikler:
# - İlk mesajda karşılama + menü (config ile)
# - Sonrasında sadece auto_intents -> cevap; diğer mesajlara sessiz
# - Fuzzy fallback (rapidfuzz)
# - Webhook imza doğrulama (X-Hub-Signature-256, APP_SECRET)
# - Arka planda gönderim + 429/5xx backoff
# - Multi-tenant hazır (PHONE_TO_CLIENT_JSON + IG_TO_CLIENT_JSON)
# - Admin: reset, hot-reload, stats (Bearer token ile korumalı)
# - Hot-reload: faq/config mtime cache + /admin/reload-faq
# - Redis (opsiyonel): session + idempotency + basit istatistik kalıcı

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
    Depends,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# --- (opsiyonel) bulanık eşleştirme ---
try:
    from rapidfuzz import fuzz  # pip install rapidfuzz
except Exception:
    fuzz = None

# --- (opsiyonel) Redis ---
try:
    from redis import Redis  # pip install redis
except Exception:
    Redis = None

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
REDIS_URL = os.getenv("REDIS_URL", "")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# --- Instagram ENV ---
IG_VERIFY_TOKEN = os.getenv("IG_VERIFY_TOKEN", "")
IG_PAGE_TOKEN = os.getenv("IG_PAGE_TOKEN", "")
IG_TO_CLIENT_JSON = os.getenv("IG_TO_CLIENT_JSON", "{}")
try:
    IG_TO_CLIENT = json.loads(IG_TO_CLIENT_JSON) if IG_TO_CLIENT_JSON else {}
except Exception:
    IG_TO_CLIENT = {}

# -----------------------------------------------------------------------------
# Admin auth (Bearer)
# -----------------------------------------------------------------------------
auth_scheme = HTTPBearer(auto_error=False)

def require_admin(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if not ADMIN_TOKEN:
        return True
    if not creds or not creds.credentials or (creds.scheme or "").lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing admin token")
    if creds.credentials != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")
    return True

# -----------------------------------------------------------------------------
# Redis yardımcıları (opsiyonel)
# -----------------------------------------------------------------------------
_redis_client = None

def get_redis() -> Optional["Redis"]:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not REDIS_URL or Redis is None:
        return None
    try:
        _redis_client = Redis.from_url(
            REDIS_URL, password=REDIS_PASSWORD or None, decode_responses=True
        )
        _redis_client.ping()
    except Exception as e:
        print("[Redis] connect error:", e)
        _redis_client = None
    return _redis_client

def r_set_json(key: str, value: dict, ttl_sec: int):
    r = get_redis()
    if not r:
        return
    try:
        r.setex(key, ttl_sec, json.dumps(value, ensure_ascii=False))
    except Exception as e:
        print("[Redis] set_json error:", e)

def r_get_json(key: str) -> Optional[dict]:
    r = get_redis()
    if not r:
        return None
    try:
        v = r.get(key)
        return json.loads(v) if v else None
    except Exception as e:
        print("[Redis] get_json error:", e)
        return None

def r_set_flag(key: str, ttl_sec: int):
    r = get_redis()
    if not r:
        return
    try:
        r.setex(key, ttl_sec, "1")
    except Exception as e:
        print("[Redis] set_flag error:", e)

def r_exists(key: str) -> bool:
    r = get_redis()
    if not r:
        return False
    try:
        return bool(r.exists(key))
    except Exception as e:
        print("[Redis] exists error:", e)
        return False

def r_del(key: str):
    r = get_redis()
    if not r:
        return
    try:
        r.delete(key)
    except Exception as e:
        print("[Redis] del error:", e)

def r_hincr(name: str, field: str, amount: int = 1):
    r = get_redis()
    if not r:
        return
    try:
        r.hincrby(name, field, amount)
    except Exception as e:
        print("[Redis] hincr error:", e)

def r_hgetall(name: str) -> dict:
    r = get_redis()
    if not r:
        return {}
    try:
        return r.hgetall(name) or {}
    except Exception as e:
        print("[Redis] hgetall error:", e)
        return {}

def r_sadd(name: str, member: str):
    r = get_redis()
    if not r:
        return
    try:
        r.sadd(name, member)
    except Exception as e:
        print("[Redis] sadd error:", e)

def r_smembers(name: str) -> set:
    r = get_redis()
    if not r:
        return set()
    try:
        return set(r.smembers(name))
    except Exception as e:
        print("[Redis] smembers error:", e)
        return set()

# -----------------------------------------------------------------------------
# Hot-reload cache'leri (Seviye 1)
# -----------------------------------------------------------------------------
FAQ_CACHE: dict[str, dict] = {}  # {client: {"mtime": float, "data": dict}}
CFG_CACHE: dict[str, dict] = {}  # {client: {"mtime": float, "data": dict}}

def _file_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except FileNotFoundError:
        return 0.0

# -----------------------------------------------------------------------------
# Yardımcılar: normalize, faq/config okuma (hot-reload)
# -----------------------------------------------------------------------------
def norm(s: str) -> str:
    if not isinstance(s, str):
        return ""
    s = s.replace("İ", "I").replace("ı", "i")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.casefold().strip()

def load_faq(client: str) -> dict[str, str]:
    path = Path(f"data/{client}/faq.txt")
    mtime = _file_mtime(path)
    cached = FAQ_CACHE.get(client)
    if cached and cached.get("mtime") == mtime:
        return cached["data"]

    out: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            out[norm(k)] = v.strip()

    FAQ_CACHE[client] = {"mtime": mtime, "data": out}
    return out

def load_tenant_cfg(client: str) -> dict:
    cfg_path = Path(f"data/{client}/config.json")
    mtime = _file_mtime(cfg_path)
    cached = CFG_CACHE.get(client)
    if cached and cached.get("mtime") == mtime:
        return cached["data"]

    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            CFG_CACHE[client] = {"mtime": mtime, "data": data}
            return data
        except Exception:
            pass

    data = {
        "greeting": "Hoş geldiniz! Yardım için 'menü' yazın.",
        "auto_intents": [],
        "cooldown_minutes": 120,
        "append_menu_to_greeting": True,
        "help_enabled": True,
        # "fuzzy_threshold": 85
    }
    CFG_CACHE[client] = {"mtime": mtime, "data": data}
    return data

def find_any(faq: dict[str, str], needles: list[str]) -> Optional[str]:
    for k_norm, val in faq.items():
        for needle in needles:
            if needle in k_norm:
                return val
    return None

def fuzzy_find(faq: dict[str, str], user_text_norm: str, threshold: int = 85) -> Optional[str]:
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
# Kalıcılık sarmalayıcıları (Redis + RAM fallback)
# -----------------------------------------------------------------------------
SESSIONS: Dict[Tuple[str, str], dict] = {}
PROCESSED_MSG_IDS: set[str] = set()
STATS_MEM: Dict[str, Dict[str, int]] = {}

def get_session(client: str, user_id: str) -> Optional[dict]:
    key = f"session:{client}:{user_id}"
    r_sess = r_get_json(key)
    if r_sess is not None:
        return r_sess
    return SESSIONS.get((client, user_id))

def set_session(client: str, user_id: str, data: dict):
    key = f"session:{client}:{user_id}"
    r_set_json(key, data, ttl_sec=60*60*24*30)
    SESSIONS[(client, user_id)] = data

def del_session(client: str, user_id: str):
    key = f"session:{client}:{user_id}"
    r_del(key)
    if (client, user_id) in SESSIONS:
        del SESSIONS[(client, user_id)]

def was_processed(msg_id: Optional[str]) -> bool:
    if not msg_id:
        return False
    key = f"msgid:{msg_id}"
    if r_exists(key):
        return True
    r_set_flag(key, ttl_sec=60*60*24*3)
    if msg_id in PROCESSED_MSG_IDS:
        return True
    PROCESSED_MSG_IDS.add(msg_id)
    return False

def inc_stat(tenant: str, kind: str):
    r_sadd("stats:tenants", tenant)
    r_hincr(f"stats:{tenant}", kind, 1)
    t = STATS_MEM.setdefault(tenant, {})
    t[kind] = t.get(kind, 0) + 1

def read_stats() -> dict:
    tenants = r_smembers("stats:tenants")
    out = {}
    if tenants:
        for t in tenants:
            out[t] = r_hgetall(f"stats:{t}")
    if not out:
        out = STATS_MEM
    for t, kv in list(out.items()):
        out[t] = {k: int(v) for k, v in kv.items()}
    return out

# -----------------------------------------------------------------------------
# Cevap üretimi
# -----------------------------------------------------------------------------
def answer(client: str, question: str) -> str:
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

    try:
        cfg = load_tenant_cfg(client)
        threshold = int(cfg.get("fuzzy_threshold", 85))
    except Exception:
        threshold = 85
    fuzzy_val = fuzzy_find(faq, s, threshold)
    if fuzzy_val:
        return fuzzy_val

    return "Bu bilgi faq.txt içinde yok."

# -----------------------------------------------------------------------------
# Tenant config (greeting + whitelist)
# -----------------------------------------------------------------------------
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
# Tenant çözümleme
# -----------------------------------------------------------------------------
def resolve_client(phone_number_id: Optional[str]) -> str:
    try:
        mapping = json.loads(PHONE_TO_CLIENT_JSON or "{}")
        if phone_number_id and phone_number_id in mapping:
            return mapping[phone_number_id]
    except Exception:
        pass
    return DEFAULT_CLIENT

def resolve_ig_client(page_or_ig_user_id: Optional[str]) -> str:
    if not page_or_ig_user_id:
        return DEFAULT_CLIENT
    return IG_TO_CLIENT.get(str(page_or_ig_user_id)) or DEFAULT_CLIENT

# -----------------------------------------------------------------------------
# İmza doğrulama (X-Hub-Signature-256)
# -----------------------------------------------------------------------------
def verify_signature(app_secret: str, raw_body: bytes, signature_header: Optional[str]) -> bool:
    if not app_secret:
        return True
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
# Instagram gönderim (retry/backoff'lu)
# -----------------------------------------------------------------------------
def send_ig_text(ig_user_id: str, recipient_psid: str, text: str):
    if not IG_PAGE_TOKEN:
        print("[IG] missing IG_PAGE_TOKEN"); return
    if not ig_user_id:
        print("[IG] missing ig_user_id"); return

    url = f"https://graph.facebook.com/v20.0/{ig_user_id}/messages"
    params = {"access_token": IG_PAGE_TOKEN}
    payload = {"recipient": {"id": recipient_psid}, "message": {"text": text}}

    for attempt in range(3):
        try:
            r = requests.post(url, params=params, json=payload, timeout=30)
            if r.status_code < 400:
                return
            if r.status_code in (429, 500, 502, 503, 504):
                wait = 2 ** attempt
                print(f"[IG backoff] {r.status_code} attempt={attempt+1} wait={wait}s {r.text}")
                time.sleep(wait)
                continue
            print("[IG send error]", r.status_code, r.text)
            return
        except Exception as e:
            wait = 2 ** attempt
            print("[IG send error]", e, f"attempt={attempt+1} wait={wait}s")
            time.sleep(wait)

# -----------------------------------------------------------------------------
# HTTP API (test & admin)
# -----------------------------------------------------------------------------
class AskIn(BaseModel):
    client: str
    question: str

class ResetIn(BaseModel):
    client: str
    wa_id: str  # kullanıcı id (WA: tel, IG: psid)

class ReloadIn(BaseModel):
    client: Optional[str] = None
    what: str = "all"  # "faq" | "config" | "all"

@app.get("/")
def root():
    return {"message": "SSS Bot API. Test: /docs  |  Soru: POST /ask"}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ask")
def ask(inp: AskIn, request: Request):
    return {"answer": answer(inp.client, inp.question)}

@app.post("/admin/reset-session", dependencies=[Depends(require_admin)])
def reset_session(inp: ResetIn):
    del_session(inp.client, inp.wa_id)
    return {"ok": True}

@app.post("/admin/reset-all-sessions", dependencies=[Depends(require_admin)])
def reset_all_sessions():
    SESSIONS.clear()
    return {"ok": True, "cleared_ram": True, "note": "Redis oturumları TTL ile kendiliğinden düşer."}

@app.post("/admin/reload-faq", dependencies=[Depends(require_admin)])
def reload_faq(inp: ReloadIn):
    if inp.client:
        if inp.what in ("faq", "all"):
            FAQ_CACHE.pop(inp.client, None)
        if inp.what in ("config", "all"):
            CFG_CACHE.pop(inp.client, None)
        scope = f"client:{inp.client}"
    else:
        if inp.what in ("faq", "all"):
            FAQ_CACHE.clear()
        if inp.what in ("config", "all"):
            CFG_CACHE.clear()
        scope = "all"
    return {"ok": True, "reloaded": inp.what, "scope": scope}

@app.get("/admin/stats", dependencies=[Depends(require_admin)])
def stats():
    return {"ok": True, "stats": read_stats()}

# -----------------------------------------------------------------------------
# WhatsApp Webhook
# -----------------------------------------------------------------------------
@app.get("/whatsapp/webhook")
def wa_verify(
    hub_mode: str = Query(..., alias="hub.mode"),
    hub_challenge: str = Query(..., alias="hub.challenge"),
    hub_verify_token: str = Query(..., alias="hub.verify_token"),
):
    if hub_mode == "subscribe" and hub_verify_token == VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge)
    raise HTTPException(status_code=403, detail="verification failed")

@app.post("/whatsapp/webhook")
async def wa_receive(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(default=None, alias="X-Hub-Signature-256"),
):
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

        msg_id = msg.get("id")
        if was_processed(msg_id):
            return {"ok": True}

        wa_id = msg["from"]
        text = msg.get("text", {}).get("body", "").strip()
        phone_number_id = entry.get("metadata", {}).get("phone_number_id")

        client = resolve_client(phone_number_id)
        cfg = load_tenant_cfg(client)
        auto_intents_norm = [norm(x) for x in cfg.get("auto_intents", [])]
        s = norm(text)
        now = datetime.utcnow()

        if cfg.get("help_enabled", True) and is_help_like(s):
            background_tasks.add_task(send_whatsapp_text, phone_number_id, wa_id, list_menu_text(client))
            inc_stat(client, "menu")
            logger.info(json.dumps({"evt":"reply","chan":"wa","type":"menu","tenant":client,"id":wa_id[-4:]}))
            return {"ok": True}

        sess = get_session(client, wa_id)
        cooldown = int(cfg.get("cooldown_minutes", 120))
        need_greet = False
        if not sess:
            need_greet = True
        else:
            last_iso = sess.get("greeted_at")
            last = datetime.fromisoformat(last_iso) if last_iso else None
            if (not last) or (now - last) > timedelta(minutes=cooldown):
                need_greet = True

        if need_greet:
            set_session(client, wa_id, {"greeted_at": now.isoformat()})
            greet = cfg.get("greeting", "Hoş geldiniz!")
            if cfg.get("append_menu_to_greeting", True):
                greet = f"{greet}\n\n{list_menu_text(client)}"
            background_tasks.add_task(send_whatsapp_text, phone_number_id, wa_id, greet)
            inc_stat(client, "greeting")
            logger.info(json.dumps({"evt":"reply","chan":"wa","type":"greeting","tenant":client,"id":wa_id[-4:]}))
            return {"ok": True}

        allowed = any(k in s for k in auto_intents_norm)
        if not allowed and fuzz:
            for k in auto_intents_norm:
                try:
                    if fuzz.partial_ratio(s, k) >= 80:
                        allowed = True
                        break
                except Exception:
                    pass

        if allowed:
            reply = answer(client, text)
            background_tasks.add_task(send_whatsapp_text, phone_number_id, wa_id, reply)
            inc_stat(client, "faq")
            logger.info(json.dumps({"evt":"reply","chan":"wa","type":"faq","tenant":client,"id":wa_id[-4:], "q": s[:80]}))
            return {"ok": True}

        return {"ok": True}

    except Exception as e:
        print("[WA parse error]", e)
        return {"ok": True}

# -----------------------------------------------------------------------------
# Instagram Webhook
# -----------------------------------------------------------------------------
@app.get("/instagram/webhook")
def ig_verify(
    hub_mode: str = Query(..., alias="hub.mode"),
    hub_challenge: str = Query(..., alias="hub.challenge"),
    hub_verify_token: str = Query(..., alias="hub.verify_token"),
):
    if hub_mode == "subscribe" and hub_verify_token == IG_VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge)
    raise HTTPException(status_code=403, detail="verification failed")

def _iter_ig_text_messages(entry: dict):
    """
    IG webhook farklı formatlarla gelebilir. Aşağıdaki senaryolar desteklenir:
    - entry["messaging"] listesi (sender.id, recipient.id, message.text)
    - entry["standby"] listesi (benzer yapı — bazı modlarda)
    Dönen her kayıt: (ig_user_id, sender_psid, text, mid)
    """
    ig_user_id = entry.get("id")  # sayfa/ig_user id (messages endpoint path)
    # 1) messaging
    for ev in entry.get("messaging", []) or []:
        sender_psid = (ev.get("sender") or {}).get("id")
        message = ev.get("message") or {}
        mid = message.get("mid") or ev.get("mid")
        text = None
        if isinstance(message.get("text"), str):
            text = message.get("text")
        elif isinstance(message.get("text"), dict):
            text = (message.get("text") or {}).get("body")
        if sender_psid and text:
            yield (ig_user_id, sender_psid, text.strip(), mid)

    # 2) standby (yedek mod)
    for ev in entry.get("standby", []) or []:
        sender_psid = (ev.get("sender") or {}).get("id")
        message = ev.get("message") or {}
        mid = message.get("mid") or ev.get("mid")
        text = None
        if isinstance(message.get("text"), str):
            text = message.get("text")
        elif isinstance(message.get("text"), dict):
            text = (message.get("text") or {}).get("body")
        if sender_psid and text:
            yield (ig_user_id, sender_psid, text.strip(), mid)

@app.post("/instagram/webhook")
async def ig_receive(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(default=None, alias="X-Hub-Signature-256"),
):
    raw = await request.body()
    if not verify_signature(APP_SECRET, raw, x_hub_signature_256):
        raise HTTPException(status_code=403, detail="bad signature")

    payload = json.loads(raw.decode("utf-8") or "{}")
    try:
        entries = payload.get("entry") or []
        if not entries:
            return {"ok": True}

        # Meta IG webhookları birden fazla entry/ değişiklik içerebilir
        for ent in entries:
            # Bazı setuplarda IG değişiklikleri "changes[].value" yerine doğrudan entry içinde olabilir
            if "changes" in ent:
                for ch in ent.get("changes") or []:
                    val = ch.get("value") or {}
                    for ig_user_id, sender_psid, text, mid in _iter_ig_text_messages(val):
                        if mid and was_processed(mid):
                            continue
                        await _handle_ig_text(background_tasks, ig_user_id, sender_psid, text)
                continue

            # Değişiklik yoksa doğrudan entry'den dene
            for ig_user_id, sender_psid, text, mid in _iter_ig_text_messages(ent):
                if mid and was_processed(mid):
                    continue
                await _handle_ig_text(background_tasks, ig_user_id, sender_psid, text)

        return {"ok": True}

    except Exception as e:
        print("[IG parse error]", e)
        return {"ok": True}

async def _handle_ig_text(background_tasks: BackgroundTasks, ig_user_id: str, sender_psid: str, text: str):
    client = resolve_ig_client(ig_user_id)
    cfg = load_tenant_cfg(client)
    auto_intents_norm = [norm(x) for x in cfg.get("auto_intents", [])]
    s = norm(text)
    now = datetime.utcnow()

    # yardım/menü
    if cfg.get("help_enabled", True) and is_help_like(s):
        background_tasks.add_task(send_ig_text, ig_user_id, sender_psid, list_menu_text(client))
        inc_stat(client, "menu")
        logger.info(json.dumps({"evt":"reply","chan":"ig","type":"menu","tenant":client,"id":sender_psid[-4:]}))
        return

    # karşılama (cooldown)
    sess = get_session(client, sender_psid)
    cooldown = int(cfg.get("cooldown_minutes", 120))
    need_greet = False
    if not sess:
        need_greet = True
    else:
        last_iso = sess.get("greeted_at")
        last = datetime.fromisoformat(last_iso) if last_iso else None
        if (not last) or (now - last) > timedelta(minutes=cooldown):
            need_greet = True

    if need_greet:
        set_session(client, sender_psid, {"greeted_at": now.isoformat()})
        greet = cfg.get("greeting", "Hoş geldiniz!")
        if cfg.get("append_menu_to_greeting", True):
            greet = f"{greet}\n\n{list_menu_text(client)}"
        background_tasks.add_task(send_ig_text, ig_user_id, sender_psid, greet)
        inc_stat(client, "greeting")
        logger.info(json.dumps({"evt":"reply","chan":"ig","type":"greeting","tenant":client,"id":sender_psid[-4:]}))
        return

    # whitelist kontrol + hafif fuzzy
    allowed = any(k in s for k in auto_intents_norm)
    if not allowed and fuzz:
        for k in auto_intents_norm:
            try:
                if fuzz.partial_ratio(s, k) >= 80:
                    allowed = True
                    break
            except Exception:
                pass

    if allowed:
        reply = answer(client, text)
        background_tasks.add_task(send_ig_text, ig_user_id, sender_psid, reply)
        inc_stat(client, "faq")
        logger.info(json.dumps({"evt":"reply","chan":"ig","type":"faq","tenant":client,"id":sender_psid[-4:], "q": s[:80]}))
        return
    # izinli değilse sessiz
